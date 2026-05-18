# FILE: routers/admin.py
# -*- coding: utf-8 -*-

import json
import logging
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from sqlalchemy import func, select

from config import ACTIVE_ORDER_STATUSES, STATUS_FINISH
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
from media import delete_media_file, media_url, save_image_upload
from schemas import ReviewDecisionBody
from utils import (
    canon_status,
    get_admin_provider_phone,
    iso_utc,
    require_admin,
    unified_response,
    utc_now,
)

router = APIRouter(tags=["admin"])
logger = logging.getLogger("putz.admin")


# -------------------- Active requests --------------------

@router.get("/admin/requests/active")
async def admin_active_requests(request: Request):
    require_admin(request)

    rows = await database.fetch_all(
        RequestTable.__table__.select()
        .where(RequestTable.status.in_(ACTIVE_ORDER_STATUSES))
        .order_by(RequestTable.request_datetime.desc(), RequestTable.id.desc())
    )

    items = [
        {
            "id": int(r["id"]),
            "user_phone": str(r["user_phone"] or ""),
            "latitude": float(r["latitude"]) if r["latitude"] is not None else None,
            "longitude": float(r["longitude"]) if r["longitude"] is not None else None,
            "car_list": r["car_list"] or [],
            "address": str(r["address"] or ""),
            "home_number": str(r["home_number"] or ""),
            "service_type": str(r["service_type"] or ""),
            "service_types": r["service_types"] or [],
            "preferred_slots": r["preferred_slots"] or [],
            "price": int(r["price"] or 0),
            "request_datetime": iso_utc(r["request_datetime"]),
            "status": canon_status(str(r["status"] or "")),
            "driver_name": str(r["driver_name"] or ""),
            "driver_phone": str(r["driver_phone"] or ""),
            "finish_datetime": iso_utc(r["finish_datetime"]),
            "payment_type": str(r["payment_type"] or ""),
            "scheduled_start": iso_utc(r["scheduled_start"]),
            "execution_start": iso_utc(r["execution_start"]),
            "service_place": str(r["service_place"] or "client"),
        }
        for r in rows
    ]

    return unified_response("ok", "ACTIVE_REQUESTS", "active requests", {"items": items})


# -------------------- Reviews --------------------

@router.get("/admin/reviews")
async def admin_list_reviews(
    request: Request,
    status: str = "APPROVED",
    limit: int = 50,
    offset: int = 0,
):
    require_admin(request)

    st = str(status or "APPROVED").strip().upper()
    if st not in ["PENDING", "APPROVED", "REJECTED"]:
        st = "APPROVED"

    reviews = ReviewTable.__table__
    users = UserTable.__table__

    q = (
        select(
            reviews.c.id,
            reviews.c.request_id,
            reviews.c.user_phone,
            reviews.c.rating,
            reviews.c.comment,
            reviews.c.status,
            reviews.c.created_at,
            users.c.name.label("user_name"),
        )
        .select_from(reviews.outerjoin(users, users.c.phone == reviews.c.user_phone))
        .where(reviews.c.status == st)
        .order_by(reviews.c.created_at.desc())
        .limit(limit)
        .offset(offset)
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
            "status": str(r["status"] or ""),
            "created_at": iso_utc(r["created_at"]),
        }
        for r in rows
    ]

    avg, count = None, 0
    if st == "APPROVED":
        avg_val = await database.fetch_val(
            select(func.avg(reviews.c.rating)).where(reviews.c.status == "APPROVED")
        )
        count_val = await database.fetch_val(
            select(func.count()).select_from(reviews).where(reviews.c.status == "APPROVED")
        )
        avg = float(avg_val) if avg_val is not None else None
        count = int(count_val or 0)

    return unified_response("ok", "REVIEWS", "reviews", {
        "items": items,
        "avg_rating": avg,
        "count": count,
        "status": st,
    })


@router.post("/admin/reviews/{review_id}/decide")
async def admin_decide_review(review_id: int, body: ReviewDecisionBody, request: Request):
    require_admin(request)

    row = await database.fetch_one(
        ReviewTable.__table__.select().where(ReviewTable.id == int(review_id))
    )
    if not row:
        raise HTTPException(status_code=404, detail="review not found")

    new_status = "APPROVED" if body.approve else "REJECTED"
    decided_by = get_admin_provider_phone(request)

    await database.execute(
        ReviewTable.__table__.update().where(ReviewTable.id == int(review_id)).values(
            status=new_status, decided_at=utc_now(), decided_by=decided_by,
        )
    )

    return unified_response("ok", "REVIEW_DECIDED", "decided", {
        "id": int(review_id),
        "status": new_status,
    })


# -------------------- Services --------------------

@router.get("/admin/services")
async def admin_list_services(request: Request):
    require_admin(request)

    reviews = ReviewTable.__table__
    reqs = RequestTable.__table__
    q_rating = (
        select(
            reqs.c.service_type.label("service_type"),
            func.avg(reviews.c.rating).label("avg_rating"),
            func.count().label("review_count"),
        )
        .select_from(reviews.join(reqs, reqs.c.id == reviews.c.request_id))
        .where(reviews.c.status == "APPROVED")
        .group_by(reqs.c.service_type)
    )
    rating_map = {
        str(x["service_type"] or "").strip().lower(): {
            "avg": float(x["avg_rating"]) if x["avg_rating"] is not None else None,
            "count": int(x["review_count"] or 0),
        }
        for x in await database.fetch_all(q_rating)
    }

    rows = await database.fetch_all(
        ServicePriceTable.__table__.select().order_by(
            ServicePriceTable.sort_order.asc(),
            ServicePriceTable.service_type.asc(),
        )
    )

    items = []
    for r in rows:
        svc = str(r["service_type"] or "").strip().lower()
        rm = rating_map.get(svc, {"avg": None, "count": 0})
        items.append({
            "service_type": svc,
            "base_price": int(r["base_price"] or 0),
            "active": bool(r["active"]),
            "sort_order": int(r["sort_order"] or 0),
            "name_i18n": r["name_i18n"] or {},
            "icon_url": media_url(str(r["icon_path"] or "")),
            "avg_rating": rm["avg"],
            "review_count": rm["count"],
            "updated_at": iso_utc(r["updated_at"]),
        })

    return unified_response("ok", "ADMIN_SERVICES", "services", {"items": items})


@router.post("/admin/services")
async def admin_upsert_service(
    request: Request,
    service_type: str = Form(...),
    base_price: int = Form(0),
    active: bool = Form(True),
    sort_order: int = Form(0),
    name_i18n: str = Form("{}"),
    icon: Optional[UploadFile] = File(None),
):
    require_admin(request)

    svc = str(service_type or "").strip().lower()
    if not svc:
        raise HTTPException(status_code=400, detail="service_type required")
    if int(base_price or 0) < 0:
        raise HTTPException(status_code=400, detail="base_price must be >= 0")

    try:
        nm = json.loads(name_i18n or "{}")
        if not isinstance(nm, dict):
            raise ValueError()
    except Exception:
        raise HTTPException(status_code=400, detail="name_i18n must be a JSON object string")

    existing = await database.fetch_one(
        ServicePriceTable.__table__.select().where(ServicePriceTable.service_type == svc)
    )

    patch = {
        "base_price": int(base_price or 0),
        "active": bool(active),
        "sort_order": int(sort_order),
        "name_i18n": nm,
        "updated_at": utc_now(),
    }

    if icon is not None:
        rel_path, mime, _ = await save_image_upload(icon, subdir="services")
        if existing and str(existing["icon_path"] or "").strip():
            delete_media_file(str(existing["icon_path"]))
        patch["icon_path"] = rel_path
        patch["icon_mime"] = mime

    if existing:
        await database.execute(
            ServicePriceTable.__table__.update().where(
                ServicePriceTable.service_type == svc
            ).values(**patch)
        )
    else:
        await database.execute(
            ServicePriceTable.__table__.insert().values(
                service_type=svc,
                icon_path=patch.pop("icon_path", ""),
                icon_mime=patch.pop("icon_mime", ""),
                **patch,
            )
        )

    return unified_response("ok", "SERVICE_UPSERTED", "saved", {"service_type": svc})


# -------------------- Promotions --------------------

@router.get("/admin/promotions")
async def admin_list_promotions(request: Request):
    require_admin(request)

    rows = await database.fetch_all(
        PromotionTable.__table__.select().order_by(
            PromotionTable.sort_order.asc(), PromotionTable.id.asc()
        )
    )

    items = [
        {
            "id": int(r["id"]),
            "active": bool(r["active"]),
            "sort_order": int(r["sort_order"] or 0),
            "title_i18n": r["title_i18n"] or {},
            "subtitle_i18n": r["subtitle_i18n"] or {},
            "service_types": r["service_types"] or [],
            "discount_amount": int(r["discount_amount"] or 0),
            "image_url": media_url(str(r["image_path"] or "")),
            "created_at": iso_utc(r["created_at"]),
            "updated_at": iso_utc(r["updated_at"]),
        }
        for r in rows
    ]

    return unified_response("ok", "PROMOTIONS", "promotions", {"items": items})


@router.post("/admin/promotions")
async def admin_create_promotion(
    request: Request,
    active: bool = Form(True),
    sort_order: int = Form(0),
    title_i18n: str = Form("{}"),
    subtitle_i18n: str = Form("{}"),
    service_types: str = Form(""),
    discount_amount: int = Form(0),
    image: Optional[UploadFile] = File(None),
):
    require_admin(request)

    try:
        title_map = json.loads(title_i18n or "{}")
        subtitle_map = json.loads(subtitle_i18n or "{}")
        if not isinstance(title_map, dict) or not isinstance(subtitle_map, dict):
            raise ValueError()
    except Exception:
        raise HTTPException(status_code=400, detail="title_i18n/subtitle_i18n must be JSON objects")

    svc_list = [s.strip().lower() for s in service_types.split(",") if s.strip()]
    if int(discount_amount or 0) < 0:
        raise HTTPException(status_code=400, detail="discount_amount must be >= 0")

    rel_path, mime = "", ""
    if image is not None:
        rel_path, mime, _ = await save_image_upload(image, subdir="promotions")

    now = utc_now()
    row = await database.fetch_one(
        PromotionTable.__table__.insert().values(
            active=bool(active),
            sort_order=int(sort_order),
            title_i18n=title_map,
            subtitle_i18n=subtitle_map,
            service_types=svc_list,
            discount_amount=int(discount_amount or 0),
            image_path=rel_path,
            image_mime=mime,
            created_at=now,
            updated_at=now,
        ).returning(PromotionTable.id)
    )

    return unified_response("ok", "PROMOTION_CREATED", "created", {
        "id": int(row["id"]) if row else 0
    })


@router.put("/admin/promotions/{promo_id}")
async def admin_update_promotion(
    promo_id: int,
    request: Request,
    active: Optional[bool] = Form(None),
    sort_order: Optional[int] = Form(None),
    title_i18n: Optional[str] = Form(None),
    subtitle_i18n: Optional[str] = Form(None),
    service_types: Optional[str] = Form(None),
    discount_amount: Optional[int] = Form(None),
    image: Optional[UploadFile] = File(None),
):
    require_admin(request)

    old = await database.fetch_one(
        PromotionTable.__table__.select().where(PromotionTable.id == int(promo_id))
    )
    if not old:
        raise HTTPException(status_code=404, detail="promotion not found")

    patch: dict = {"updated_at": utc_now()}

    if active is not None:
        patch["active"] = bool(active)
    if sort_order is not None:
        patch["sort_order"] = int(sort_order)
    if discount_amount is not None:
        da = int(discount_amount or 0)
        if da < 0:
            raise HTTPException(status_code=400, detail="discount_amount must be >= 0")
        patch["discount_amount"] = da
    if title_i18n is not None:
        try:
            v = json.loads(title_i18n or "{}")
            if not isinstance(v, dict):
                raise ValueError()
            patch["title_i18n"] = v
        except Exception:
            raise HTTPException(status_code=400, detail="title_i18n must be a JSON object")
    if subtitle_i18n is not None:
        try:
            v = json.loads(subtitle_i18n or "{}")
            if not isinstance(v, dict):
                raise ValueError()
            patch["subtitle_i18n"] = v
        except Exception:
            raise HTTPException(status_code=400, detail="subtitle_i18n must be a JSON object")
    if service_types is not None:
        patch["service_types"] = [s.strip().lower() for s in service_types.split(",") if s.strip()]
    if image is not None:
        rel_path, mime, _ = await save_image_upload(image, subdir="promotions")
        if str(old["image_path"] or "").strip():
            delete_media_file(str(old["image_path"]))
        patch["image_path"] = rel_path
        patch["image_mime"] = mime

    await database.execute(
        PromotionTable.__table__.update().where(
            PromotionTable.id == int(promo_id)
        ).values(**patch)
    )

    return unified_response("ok", "PROMOTION_UPDATED", "updated", {"id": int(promo_id)})


@router.delete("/admin/promotions/{promo_id}")
async def admin_delete_promotion(promo_id: int, request: Request):
    require_admin(request)

    old = await database.fetch_one(
        PromotionTable.__table__.select().where(PromotionTable.id == int(promo_id))
    )
    if not old:
        raise HTTPException(status_code=404, detail="promotion not found")

    if str(old["image_path"] or "").strip():
        delete_media_file(str(old["image_path"]))

    await database.execute(
        PromotionTable.__table__.delete().where(PromotionTable.id == int(promo_id))
    )

    return unified_response("ok", "PROMOTION_DELETED", "deleted", {"id": int(promo_id)})
