# FILE: routers/orders.py
# -*- coding: utf-8 -*-

import logging

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import func, select

from config import (
    ACTIVE_ORDER_STATUSES,
    FINAL_ORDER_STATUSES,
    STATUS_CANCELED,
    STATUS_FINISH,
    STATUS_NEW,
)
from database import (
    AppointmentTable,
    PromotionTable,
    RequestTable,
    ReviewTable,
    ScheduleSlotTable,
    ServicePriceTable,
    UserTable,
    database,
)
from media import media_url
from push import notify_managers, notify_user, push_event_data
from schemas import CancelRequest, OrderRequest, ReviewSubmitBody
from utils import (
    canon_status,
    iso_utc,
    normalize_phone,
    parse_iso_utc,
    pick_i18n,
    require_user_phone,
    unified_response,
    utc_now,
)

router = APIRouter(tags=["orders"])
logger = logging.getLogger("putz.orders")


# -------------------- Create order --------------------

@router.post("/order")
async def create_order(order: OrderRequest, request: Request):
    norm = require_user_phone(request, order.user_phone)

    user = await database.fetch_one(
        UserTable.__table__.select().where(UserTable.phone == norm)
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    svc = str(order.service_type or "").strip().lower()
    if not svc:
        raise HTTPException(status_code=400, detail="service_type required")

    # جلوگیری از سفارش تکراری فعال برای همان سرویس
    existing = await database.fetch_val(
        select(func.count()).select_from(RequestTable).where(
            (RequestTable.user_phone == norm) &
            (RequestTable.service_type == svc) &
            (RequestTable.status.in_(ACTIVE_ORDER_STATUSES))
        )
    )
    if int(existing or 0) > 0:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "ACTIVE_ORDER_EXISTS",
                "message": "شما قبلاً یک سفارش فعال برای این سرویس دارید",
            },
        )

    svc_types = [
        str(x or "").strip().lower()
        for x in (order.service_types or [])
        if str(x or "").strip()
    ] or [svc]

    # ✅ حداکثر 2 زمان پیشنهادی (طبق نیاز)
    pref = list({
        s for s in (
            str(x or "").strip()
            for x in (order.preferred_slots or [])
            if str(x or "").strip()
        )
    })[:2]

    req_dt = utc_now()
    if str(order.request_datetime or "").strip():
        req_dt = parse_iso_utc(str(order.request_datetime).strip())

    row = await database.fetch_one(
        RequestTable.__table__.insert().values(
            user_phone=norm,
            latitude=float(order.location.latitude),
            longitude=float(order.location.longitude),
            car_list=[car.model_dump() for car in (order.car_list or [])],
            address=str(order.address or "").strip(),
            home_number=str(order.home_number or "").strip(),
            service_type=svc,
            service_types=svc_types,
            preferred_slots=pref,
            price=int(order.price or 0),
            request_datetime=req_dt,
            status=STATUS_NEW,
            driver_name="",
            driver_phone="",
            finish_datetime=None,
            payment_type=str(order.payment_type or "").strip().lower(),
            service_place=str(order.service_place or "client").strip().lower(),
            scheduled_start=None,
            execution_start=None,
        ).returning(RequestTable.id)
    )
    new_id = int(row["id"]) if row else 0

    # ✅ نوتیف با title/body واقعی
    try:
        await notify_managers(
            title="", body="",
            event="new_order",
            data=push_event_data(
                event="new_order", order_id=new_id,
                status=STATUS_NEW, service_type=svc, user_phone=norm,
            ),
        )
    except Exception as e:
        logger.error(f"notify_managers(create_order) failed: {e}")

    return unified_response(
        "ok", "REQUEST_CREATED", "سفارش با موفقیت ثبت شد", {"id": new_id}
    )


# -------------------- List user orders --------------------

@router.get("/user_orders/{phone}")
async def get_user_orders(phone: str, request: Request):
    norm = require_user_phone(request, phone)

    rows = await database.fetch_all(
        RequestTable.__table__.select()
        .where(RequestTable.user_phone == norm)
        .order_by(RequestTable.request_datetime.desc(), RequestTable.id.desc())
    )

    items = [
        {
            "id": int(r["id"]),
            "user_phone": str(r["user_phone"] or ""),
            "address": str(r["address"] or ""),
            "home_number": str(r["home_number"] or ""),
            "service_type": str(r["service_type"] or ""),
            "service_types": r["service_types"] or [],
            "preferred_slots": r["preferred_slots"] or [],
            "price": int(r["price"] or 0),
            "status": canon_status(str(r["status"] or "")),
            "latitude": float(r["latitude"]) if r["latitude"] is not None else None,
            "longitude": float(r["longitude"]) if r["longitude"] is not None else None,
            "scheduled_start": iso_utc(r["scheduled_start"]),
            "execution_start": iso_utc(r["execution_start"]),
            "finish_datetime": iso_utc(r["finish_datetime"]),
            "driver_name": str(r["driver_name"] or ""),
            "driver_phone": str(r["driver_phone"] or ""),
            "request_datetime": iso_utc(r["request_datetime"]),
            "service_place": str(r["service_place"] or "client"),
            "payment_type": str(r["payment_type"] or ""),
            "car_list": r["car_list"] or [],
        }
        for r in rows
    ]

    return unified_response("ok", "USER_ORDERS", "لیست سفارش‌ها", {"items": items})


# -------------------- Cancel order --------------------

@router.post("/cancel_order")
async def cancel_order(cancel: CancelRequest, request: Request):
    norm = require_user_phone(request, cancel.user_phone)
    service = str(cancel.service_type or "").strip().lower()
    if not service:
        raise HTTPException(status_code=400, detail="service_type required")

    # بررسی وجود سفارش قابل لغو
    active_row = await database.fetch_one(
        RequestTable.__table__.select().where(
            (RequestTable.user_phone == norm) &
            (RequestTable.service_type == service) &
            (RequestTable.status.in_([STATUS_NEW, "WAITING", "ASSIGNED"])) &
            (RequestTable.execution_start.is_(None))
        )
    )

    if not active_row:
        # بررسی وجود سفارش PRICE_CONFIRMED یا IN_PROGRESS
        any_active = await database.fetch_one(
            RequestTable.__table__.select().where(
                (RequestTable.user_phone == norm) &
                (RequestTable.service_type == service) &
                (RequestTable.status.in_(ACTIVE_ORDER_STATUSES))
            )
        )
        if any_active:
            st = canon_status(str(any_active["status"] or ""))
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "CANNOT_CANCEL",
                    "message": f"سفارش در مرحله '{st}' قابل لغو توسط کاربر نیست. لطفاً با مدیر تماس بگیرید.",
                },
            )
        raise HTTPException(
            status_code=404,
            detail={"code": "ORDER_NOT_FOUND", "message": "سفارش فعال یافت نشد"},
        )

    rows = await database.fetch_all(
        RequestTable.__table__.update().where(
            (RequestTable.user_phone == norm) &
            (RequestTable.service_type == service) &
            (RequestTable.status.in_([STATUS_NEW, "WAITING", "ASSIGNED"])) &
            (RequestTable.execution_start.is_(None))
        ).values(
            status=STATUS_CANCELED,
            scheduled_start=None,
            execution_start=None,
            finish_datetime=None,
        ).returning(RequestTable.id, RequestTable.driver_phone)
    )

    ids = [int(r["id"]) for r in rows]
    drivers = list({
        str(r["driver_phone"] or "").strip()
        for r in rows
        if str(r["driver_phone"] or "").strip()
    })

    await database.execute(
        ScheduleSlotTable.__table__.update().where(
            (ScheduleSlotTable.request_id.in_(ids)) &
            (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))
        ).values(status="REJECTED")
    )
    await database.execute(
        AppointmentTable.__table__.update().where(
            (AppointmentTable.request_id.in_(ids)) &
            (AppointmentTable.status == "BOOKED")
        ).values(status="CANCELED")
    )

    # ✅ نوتیف با متن واقعی
    try:
        payload = push_event_data(
            event="canceled_by_user", order_id=ids[0], order_ids=ids,
            status=STATUS_CANCELED, service_type=service, user_phone=norm,
        )
        await notify_managers(
            title="", body="",
            event="canceled_by_user",
            data=payload,
        )
        for dp in drivers:
            await notify_managers(
                title="", body="",
                event="canceled_by_user",
                data=payload,
                target_phone=normalize_phone(dp),
            )
    except Exception as e:
        logger.error(f"notify_managers(cancel_order) failed: {e}")

    return unified_response(
        "ok", "ORDER_CANCELED", "سفارش با موفقیت لغو شد", {"count": len(ids)}
    )


# -------------------- Reviews --------------------

@router.get("/reviews")
async def public_reviews(limit: int = 50, offset: int = 0):
    reviews = ReviewTable.__table__
    users   = UserTable.__table__

    q = (
        select(
            reviews.c.id,
            reviews.c.request_id,
            reviews.c.user_phone,
            reviews.c.rating,
            reviews.c.comment,
            reviews.c.created_at,
            users.c.name.label("user_name"),
        )
        .select_from(reviews.outerjoin(users, users.c.phone == reviews.c.user_phone))
        .where(reviews.c.status == "APPROVED")
        .order_by(func.random())
        .limit(min(int(limit or 50), 100))
        .offset(max(int(offset or 0), 0))
    )

    rows = await database.fetch_all(q)
    items = [
        {
            "id": int(r["id"]),
            "request_id": int(r["request_id"]),
            "user_phone": str(r["user_phone"] or ""),
            "user_name": str(r["user_name"] or ""),
            "rating": int(r["rating"] or 0),
            "comment": str(r["comment"] or ""),
            "created_at": iso_utc(r["created_at"]),
        }
        for r in rows
    ]

    avg_val = await database.fetch_val(
        select(func.avg(reviews.c.rating)).where(reviews.c.status == "APPROVED")
    )
    count_val = await database.fetch_val(
        select(func.count()).select_from(reviews).where(reviews.c.status == "APPROVED")
    )

    return unified_response("ok", "PUBLIC_REVIEWS", "نظرات کاربران", {
        "items": items,
        "avg_rating": round(float(avg_val), 2) if avg_val is not None else None,
        "count": int(count_val or 0),
    })


@router.post("/order/{order_id}/review/submit")
async def submit_review(order_id: int, body: ReviewSubmitBody, request: Request):
    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="سفارش یافت نشد")

    norm = require_user_phone(request, str(req["user_phone"]))

    if canon_status(str(req["status"] or "")) != STATUS_FINISH:
        raise HTTPException(
            status_code=409,
            detail={"code": "ORDER_NOT_FINISHED", "message": "فقط سفارش‌های تکمیل شده قابل امتیازدهی هستند"},
        )

    rating  = int(body.rating or 0)
    comment = str(body.comment or "").strip()

    existing = await database.fetch_one(
        ReviewTable.__table__.select().where(ReviewTable.request_id == int(order_id))
    )

    if existing:
        await database.execute(
            ReviewTable.__table__.update().where(
                ReviewTable.request_id == int(order_id)
            ).values(
                rating=rating, comment=comment, status="PENDING",
                created_at=utc_now(), decided_at=None, decided_by=None,
            )
        )
    else:
        await database.execute(
            ReviewTable.__table__.insert().values(
                request_id=int(order_id), user_phone=norm,
                rating=rating, comment=comment, status="PENDING",
                created_at=utc_now(),
            )
        )

    # ✅ نوتیف به مدیر
    try:
        await notify_managers(
            title="", body="",
            event="review_submitted",
            data={
                "event": "review_submitted",
                "order_id": str(order_id),
                "rating": str(rating),
            },
        )
    except Exception as e:
        logger.error(f"notify_managers(review) failed: {e}")

    return unified_response(
        "ok", "REVIEW_SUBMITTED", "نظر شما ثبت شد و در انتظار تأیید است",
        {"order_id": int(order_id)}
    )


# -------------------- Public home --------------------

@router.get("/public/home")
async def public_home(lang: str = "fa"):
    lang = str(lang or "fa").strip().lower()
    if lang not in ("fa", "en", "de"):
        lang = "fa"

    promo_rows = await database.fetch_all(
        PromotionTable.__table__.select()
        .where(PromotionTable.active == True)
        .order_by(PromotionTable.sort_order.asc(), PromotionTable.id.asc())
    )

    reviews = ReviewTable.__table__
    reqs    = RequestTable.__table__
    q_rating = (
        select(
            reqs.c.service_type.label("service_type"),
            func.avg(reviews.c.rating).label("avg_rating"),
            func.count().label("count"),
        )
        .select_from(reviews.join(reqs, reqs.c.id == reviews.c.request_id))
        .where(reviews.c.status == "APPROVED")
        .group_by(reqs.c.service_type)
    )
    rating_map = {
        str(x["service_type"] or "").strip().lower(): {
            "avg": round(float(x["avg_rating"]), 2) if x["avg_rating"] is not None else None,
            "count": int(x["count"] or 0),
        }
        for x in await database.fetch_all(q_rating)
    }

    svc_rows = await database.fetch_all(
        ServicePriceTable.__table__.select()
        .where(ServicePriceTable.active == True)
        .order_by(ServicePriceTable.sort_order.asc(), ServicePriceTable.service_type.asc())
    )

    service_map = {}
    services = []
    for r in svc_rows:
        k  = str(r["service_type"] or "").strip().lower()
        rm = rating_map.get(k, {"avg": None, "count": 0})
        item = {
            "service_type": k,
            "name": pick_i18n(r["name_i18n"] or {}, lang),
            "name_i18n": r["name_i18n"] or {},
            "icon_url": media_url(str(r["icon_path"] or "")),
            "base_price": int(r["base_price"] or 0),
            "avg_rating": rm["avg"],
            "review_count": rm["count"],
            "sort_order": int(r["sort_order"] or 0),
        }
        services.append(item)
        service_map[k] = item

    promotion_details = []
    for p in promo_rows:
        svc_types = [str(x).strip().lower() for x in (p["service_types"] or []) if str(x).strip()]
        discount  = int(p["discount_amount"] or 0)
        details   = []
        for svc in svc_types:
            if svc not in service_map:
                continue
            base = int(service_map[svc]["base_price"] or 0)
            details.append({
                "service_type": svc,
                "name": service_map[svc]["name"],
                "icon_url": service_map[svc]["icon_url"],
                "base_price": base,
                "discount_amount": discount,
                "discounted_price": max(0, base - discount),
                "avg_rating": service_map[svc]["avg_rating"],
            })

        promotion_details.append({
            "id": int(p["id"]),
            "title": pick_i18n(p["title_i18n"] or {}, lang),
            "title_i18n": p["title_i18n"] or {},
            "subtitle": pick_i18n(p["subtitle_i18n"] or {}, lang),
            "subtitle_i18n": p["subtitle_i18n"] or {},
            "discount_amount": discount,
            "image_url": media_url(str(p["image_path"] or "")),
            "services": details,
            "sort_order": int(p["sort_order"] or 0),
            "active": bool(p["active"]),
        })

    return unified_response("ok", "PUBLIC_HOME", "home", {
        "promotion_details": promotion_details,
        "services": services,
        "lang": lang,
    })
