# FILE: routers/scheduling.py
# -*- coding: utf-8 -*-

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import func, select

from config import (
    ACTIVE_ORDER_STATUSES,
    FINAL_ORDER_STATUSES,
    SLOT_DURATION_HOURS,
    STATUS_ASSIGNED,
    STATUS_CANCELED,
    STATUS_FINISH,
    STATUS_IN_PROGRESS,
    STATUS_NEW,
    STATUS_PRICE_CONFIRMED,   # ✅ جدید
    STATUS_WAITING,
    WORK_END_HOUR,
    WORK_START_HOUR,
)
from database import (
    AppointmentTable,
    RequestTable,
    ScheduleSlotTable,
    database,
)
from push import notify_managers, notify_user, push_event_data
from schemas import ConfirmSlotRequest, PriceBody, ProposedSlotsRequest
from utils import (
    ADMIN_PHONES_SET,
    canon_status,
    get_admin_provider_phone,
    iso_utc,
    normalize_phone,
    parse_iso_utc,
    require_admin,
    require_user_phone,
    unified_response,
    utc_now,
)

router = APIRouter(tags=["scheduling"])
logger = logging.getLogger("putz.scheduling")


# -------------------- Conflict check --------------------

async def provider_is_free(
    provider_phone: str,
    start: datetime,
    end: datetime,
    exclude_order_id: Optional[int] = None,
) -> bool:
    provider = normalize_phone(provider_phone)
    if not provider:
        return False

    buffer = timedelta(hours=1)
    excl   = int(exclude_order_id) if exclude_order_id else None

    def _not_excl_req(col):
        return col != excl if excl else True

    def _not_excl_slot(col):
        return col != excl if excl else True

    checks = [
        select(func.count()).select_from(AppointmentTable).where(
            (AppointmentTable.provider_phone == provider) &
            (AppointmentTable.status == "BOOKED") &
            (AppointmentTable.start_time < end) &
            (AppointmentTable.end_time > start) &
            (_not_excl_req(AppointmentTable.request_id))
        ),
        select(func.count()).select_from(ScheduleSlotTable).where(
            (ScheduleSlotTable.provider_phone == provider) &
            (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) &
            (ScheduleSlotTable.slot_start < end) &
            (ScheduleSlotTable.slot_start > (start - buffer)) &
            (_not_excl_slot(ScheduleSlotTable.request_id))
        ),
        select(func.count()).select_from(RequestTable).where(
            (RequestTable.driver_phone == provider) &
            (RequestTable.scheduled_start.is_not(None)) &
            (RequestTable.status.in_([STATUS_WAITING, STATUS_ASSIGNED, STATUS_IN_PROGRESS])) &
            (RequestTable.scheduled_start < end) &
            (RequestTable.scheduled_start > (start - buffer)) &
            (_not_excl_req(RequestTable.id))
        ),
        select(func.count()).select_from(RequestTable).where(
            (RequestTable.driver_phone == provider) &
            (RequestTable.execution_start.is_not(None)) &
            (RequestTable.status.in_([STATUS_PRICE_CONFIRMED, STATUS_IN_PROGRESS])) &
            (RequestTable.execution_start < end) &
            (RequestTable.execution_start > (start - buffer)) &
            (_not_excl_req(RequestTable.id))
        ),
    ]

    for q in checks:
        if int(await database.fetch_val(q) or 0) != 0:
            return False
    return True


# -------------------- Busy slots --------------------

async def _busy_slots_for_provider(
    provider: str,
    start: datetime,
    end: datetime,
    exclude_order_id: Optional[int] = None,
) -> list[str]:
    busy: set[str] = set()

    q_sched = ScheduleSlotTable.__table__.select().where(
        (ScheduleSlotTable.slot_start >= start) &
        (ScheduleSlotTable.slot_start < end) &
        (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) &
        (ScheduleSlotTable.provider_phone == provider)
    )
    if exclude_order_id:
        q_sched = q_sched.where(ScheduleSlotTable.request_id != int(exclude_order_id))

    q_app = AppointmentTable.__table__.select().where(
        (AppointmentTable.start_time >= start) &
        (AppointmentTable.start_time < end) &
        (AppointmentTable.status == "BOOKED") &
        (AppointmentTable.provider_phone == provider)
    )
    if exclude_order_id:
        q_app = q_app.where(AppointmentTable.request_id != int(exclude_order_id))

    q_visit = RequestTable.__table__.select().where(
        (RequestTable.scheduled_start >= start) &
        (RequestTable.scheduled_start < end) &
        (RequestTable.scheduled_start.is_not(None)) &
        (RequestTable.status.in_([STATUS_WAITING, STATUS_ASSIGNED, STATUS_IN_PROGRESS])) &
        (RequestTable.driver_phone == provider)
    )
    if exclude_order_id:
        q_visit = q_visit.where(RequestTable.id != int(exclude_order_id))

    q_exec = RequestTable.__table__.select().where(
        (RequestTable.execution_start >= start) &
        (RequestTable.execution_start < end) &
        (RequestTable.execution_start.is_not(None)) &
        (RequestTable.status.in_([STATUS_PRICE_CONFIRMED, STATUS_IN_PROGRESS])) &
        (RequestTable.driver_phone == provider)
    )
    if exclude_order_id:
        q_exec = q_exec.where(RequestTable.id != int(exclude_order_id))

    for r in await database.fetch_all(q_sched):
        busy.add(r["slot_start"].astimezone(timezone.utc).isoformat())
    for r in await database.fetch_all(q_app):
        busy.add(r["start_time"].astimezone(timezone.utc).isoformat())
    for r in await database.fetch_all(q_visit):
        busy.add(r["scheduled_start"].astimezone(timezone.utc).isoformat())
    for r in await database.fetch_all(q_exec):
        busy.add(r["execution_start"].astimezone(timezone.utc).isoformat())

    return sorted(busy)


@router.get("/busy_slots")
async def get_busy_slots(
    request: Request,
    date: str,
    exclude_order_id: Optional[int] = None,
):
    require_admin(request)
    try:
        d = datetime.fromisoformat(str(date).strip()).date()
    except Exception:
        raise HTTPException(status_code=400, detail="فرمت تاریخ نامعتبر است (ISO format)")

    provider = get_admin_provider_phone(request)
    start    = datetime(d.year, d.month, d.day, 0, 0, tzinfo=timezone.utc)
    end      = start + timedelta(days=1)

    items = await _busy_slots_for_provider(provider, start, end, exclude_order_id)
    return unified_response("ok", "BUSY_SLOTS", "ساعات مشغول", {"items": items})


@router.get("/public/busy_slots")
async def public_busy_slots(date: str, exclude_order_id: Optional[int] = None):
    try:
        d = datetime.fromisoformat(str(date).strip()).date()
    except Exception:
        raise HTTPException(status_code=400, detail="فرمت تاریخ نامعتبر است")

    provider = sorted(ADMIN_PHONES_SET)[0] if ADMIN_PHONES_SET else ""
    if not provider:
        return unified_response("ok", "BUSY_SLOTS", "ساعات مشغول", {"items": []})

    start = datetime(d.year, d.month, d.day, 0, 0, tzinfo=timezone.utc)
    end   = start + timedelta(days=1)

    items = await _busy_slots_for_provider(provider, start, end, exclude_order_id)
    return unified_response("ok", "BUSY_SLOTS", "ساعات مشغول", {"items": items})


# ✅ جدید: ساعات آزاد برای کاربر
@router.get("/public/available_slots")
async def public_available_slots(date: str, exclude_order_id: Optional[int] = None):
    """
    برگردوندن ساعات آزاد در یک روز مشخص
    بر اساس ساعات کاری تعریف شده در config
    منهای ساعات مشغول
    """
    try:
        d = datetime.fromisoformat(str(date).strip()).date()
    except Exception:
        raise HTTPException(status_code=400, detail="فرمت تاریخ نامعتبر است")

    # بررسی گذشته نبودن تاریخ
    today = datetime.now(timezone.utc).date()
    if d < today:
        raise HTTPException(status_code=400, detail="تاریخ انتخاب شده گذشته است")

    provider = sorted(ADMIN_PHONES_SET)[0] if ADMIN_PHONES_SET else ""
    if not provider:
        return unified_response("ok", "AVAILABLE_SLOTS", "ساعات آزاد", {"items": []})

    # تولید همه slot های کاری روز
    all_slots: list[str] = []
    now_utc = datetime.now(timezone.utc)

    for hour in range(WORK_START_HOUR, WORK_END_HOUR, SLOT_DURATION_HOURS):
        slot_dt = datetime(d.year, d.month, d.day, hour, 0, tzinfo=timezone.utc)
        # slot های گذشته رو نشون نده (برای امروز)
        if slot_dt <= now_utc:
            continue
        all_slots.append(slot_dt.isoformat())

    if not all_slots:
        return unified_response("ok", "AVAILABLE_SLOTS", "ساعات آزاد", {
            "items": [],
            "date": d.isoformat(),
            "work_start": WORK_START_HOUR,
            "work_end": WORK_END_HOUR,
        })

    start = datetime(d.year, d.month, d.day, 0, 0, tzinfo=timezone.utc)
    end   = start + timedelta(days=1)

    busy_slots = set(
        await _busy_slots_for_provider(provider, start, end, exclude_order_id)
    )

    available = [s for s in all_slots if s not in busy_slots]

    return unified_response("ok", "AVAILABLE_SLOTS", "ساعات آزاد", {
        "items": available,
        "busy": sorted(busy_slots),
        "date": d.isoformat(),
        "work_start": WORK_START_HOUR,
        "work_end": WORK_END_HOUR,
        "slot_duration_hours": SLOT_DURATION_HOURS,
    })


# -------------------- Propose slots (admin) --------------------

@router.post("/order/{order_id}/propose_slots")
async def propose_slots(order_id: int, body: ProposedSlotsRequest, request: Request):
    require_admin(request)
    provider = get_admin_provider_phone(request)

    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="سفارش یافت نشد")

    st = canon_status(str(req["status"] or ""))
    if st in FINAL_ORDER_STATUSES or req["execution_start"]:
        raise HTTPException(status_code=409, detail="این سفارش امکان پیشنهاد زمان ندارد")

    slots    = sorted(set(body.slots))[:3]
    slot_dts = [parse_iso_utc(x) for x in slots]

    async with database.transaction():
        # پاک کردن slot های قبلی
        await database.execute(
            ScheduleSlotTable.__table__.update().where(
                (ScheduleSlotTable.request_id == int(order_id)) &
                (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))
            ).values(status="REJECTED")
        )
        await database.execute(
            AppointmentTable.__table__.update().where(
                (AppointmentTable.request_id == int(order_id)) &
                (AppointmentTable.status == "BOOKED")
            ).values(status="CANCELED")
        )
        await database.execute(
            RequestTable.__table__.update().where(RequestTable.id == int(order_id)).values(
                driver_phone=provider, status=STATUS_WAITING, scheduled_start=None,
            )
        )

        for dt in slot_dts:
            end_dt = dt + timedelta(hours=SLOT_DURATION_HOURS)
            if not await provider_is_free(provider, dt, end_dt, int(order_id)):
                raise HTTPException(
                    status_code=409,
                    detail=f"تداخل زمانی در ساعت {dt.isoformat()}"
                )
            await database.execute(
                ScheduleSlotTable.__table__.insert().values(
                    request_id=int(order_id), provider_phone=provider,
                    slot_start=dt, status="PROPOSED", created_at=utc_now(),
                )
            )

    # ✅ نوتیف با متن واقعی
    try:
        await notify_user(
            phone=str(req["user_phone"]),
            title="", body="",
            event="visit_slots_proposed",
            data=push_event_data(
                event="visit_slots_proposed", order_id=int(order_id),
                status=STATUS_WAITING, service_type=str(req["service_type"] or ""),
                user_phone=str(req["user_phone"] or ""),
            ),
        )
    except Exception as e:
        logger.error(f"notify_user(propose_slots) failed: {e}")

    return unified_response("ok", "SLOTS_PROPOSED", "زمان‌های بازدید پیشنهاد شد", {
        "accepted": [dt.isoformat() for dt in slot_dts]
    })


# -------------------- Get proposed slots (user) --------------------

@router.get("/order/{order_id}/proposed_slots")
async def get_proposed_slots(order_id: int, request: Request):
    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="سفارش یافت نشد")

    require_user_phone(request, str(req["user_phone"]))

    rows = await database.fetch_all(
        ScheduleSlotTable.__table__.select().where(
            (ScheduleSlotTable.request_id == int(order_id)) &
            (ScheduleSlotTable.status == "PROPOSED")
        ).order_by(ScheduleSlotTable.slot_start.asc())
    )

    return unified_response("ok", "PROPOSED_SLOTS", "زمان‌های پیشنهادی", {
        "items": [r["slot_start"].astimezone(timezone.utc).isoformat() for r in rows],
        "order_status": canon_status(str(req["status"] or "")),
        "scheduled_start": iso_utc(req["scheduled_start"]),
    })


# -------------------- Confirm slot (user) --------------------

@router.post("/order/{order_id}/confirm_slot")
async def confirm_slot(order_id: int, body: ConfirmSlotRequest, request: Request):
    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="سفارش یافت نشد")

    require_user_phone(request, str(req["user_phone"]))

    st = canon_status(str(req["status"] or ""))
    if req["execution_start"] or st not in [STATUS_WAITING, STATUS_ASSIGNED, STATUS_NEW]:
        raise HTTPException(status_code=409, detail="این سفارش قابل تأیید زمان نیست")

    slot_dt = parse_iso_utc(body.slot)
    end_dt  = slot_dt + timedelta(hours=SLOT_DURATION_HOURS)

    async with database.transaction():
        slot_row = await database.fetch_one(
            ScheduleSlotTable.__table__.select().where(
                (ScheduleSlotTable.request_id == int(order_id)) &
                (ScheduleSlotTable.slot_start == slot_dt) &
                (ScheduleSlotTable.status == "PROPOSED")
            )
        )
        if not slot_row:
            raise HTTPException(status_code=404, detail="زمان انتخاب شده یافت نشد")

        provider = normalize_phone(str(slot_row["provider_phone"]))
        if not await provider_is_free(provider, slot_dt, end_dt, int(order_id)):
            raise HTTPException(status_code=409, detail="این زمان دیگر در دسترس نیست")

        # رد کردن بقیه slot ها
        await database.execute(
            ScheduleSlotTable.__table__.update().where(
                (ScheduleSlotTable.request_id == int(order_id)) &
                (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) &
                (ScheduleSlotTable.slot_start != slot_dt)
            ).values(status="REJECTED")
        )
        await database.execute(
            ScheduleSlotTable.__table__.update().where(
                (ScheduleSlotTable.request_id == int(order_id)) &
                (ScheduleSlotTable.slot_start == slot_dt)
            ).values(status="ACCEPTED")
        )

        # لغو appointment های قبلی متفاوت
        await database.execute(
            AppointmentTable.__table__.update().where(
                (AppointmentTable.request_id == int(order_id)) &
                (AppointmentTable.status == "BOOKED") &
                (
                    (AppointmentTable.start_time != slot_dt) |
                    (AppointmentTable.end_time != end_dt)
                )
            ).values(status="CANCELED")
        )

        # Upsert appointment
        exist = await database.fetch_one(
            AppointmentTable.__table__.select().where(
                (AppointmentTable.provider_phone == provider) &
                (AppointmentTable.start_time == slot_dt)
            ).limit(1)
        )
        if exist:
            if str(exist["status"]) == "BOOKED" and int(exist["request_id"]) != int(order_id):
                raise HTTPException(status_code=409, detail="تداخل زمانی در appointment")
            await database.execute(
                AppointmentTable.__table__.update().where(
                    AppointmentTable.id == int(exist["id"])
                ).values(request_id=int(order_id), status="BOOKED")
            )
        else:
            await database.execute(
                AppointmentTable.__table__.insert().values(
                    provider_phone=provider, request_id=int(order_id),
                    start_time=slot_dt, end_time=end_dt,
                    status="BOOKED", created_at=utc_now(),
                )
            )

        await database.execute(
            RequestTable.__table__.update().where(RequestTable.id == int(order_id)).values(
                scheduled_start=slot_dt, status=STATUS_ASSIGNED, driver_phone=provider,
            )
        )

    # ✅ نوتیف با متن واقعی
    try:
        await notify_managers(
            title="", body="",
            event="visit_time_confirmed",
            data=push_event_data(
                event="visit_time_confirmed", order_id=int(order_id),
                status=STATUS_ASSIGNED, service_type=str(req["service_type"] or ""),
                user_phone=str(req["user_phone"] or ""), scheduled_start=slot_dt,
            ),
            target_phone=provider,
        )
    except Exception as e:
        logger.error(f"notify(confirm_slot) failed: {e}")

    return unified_response("ok", "SLOT_CONFIRMED", "زمان بازدید تأیید شد", {
        "start": slot_dt.isoformat(),
        "end": end_dt.isoformat(),
        "status": STATUS_ASSIGNED,
    })


# -------------------- Reject all & cancel (user) --------------------

@router.post("/order/{order_id}/reject_all_and_cancel")
async def reject_all_and_cancel(order_id: int, request: Request):
    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="سفارش یافت نشد")

    require_user_phone(request, str(req["user_phone"]))

    st = canon_status(str(req["status"] or ""))
    if req["execution_start"] or st not in [STATUS_NEW, STATUS_WAITING, STATUS_ASSIGNED]:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "CANNOT_CANCEL",
                "message": "در این مرحله امکان لغو توسط کاربر وجود ندارد",
            },
        )

    await database.execute(
        ScheduleSlotTable.__table__.update().where(
            (ScheduleSlotTable.request_id == int(order_id)) &
            (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))
        ).values(status="REJECTED")
    )
    await database.execute(
        AppointmentTable.__table__.update().where(
            (AppointmentTable.request_id == int(order_id)) &
            (AppointmentTable.status == "BOOKED")
        ).values(status="CANCELED")
    )
    await database.execute(
        RequestTable.__table__.update().where(RequestTable.id == int(order_id)).values(
            status=STATUS_CANCELED, scheduled_start=None,
            execution_start=None, finish_datetime=None,
        )
    )

    try:
        await notify_managers(
            title="", body="",
            event="canceled_by_user",
            data=push_event_data(
                event="canceled_by_user", order_id=int(order_id),
                status=STATUS_CANCELED, service_type=str(req["service_type"] or ""),
                user_phone=str(req["user_phone"] or ""),
            ),
        )
    except Exception as e:
        logger.error(f"notify_managers(reject_all) failed: {e}")

    return unified_response("ok", "ORDER_CANCELED", "سفارش لغو شد", {
        "order_id": int(order_id)
    })


# -------------------- Set price (admin) --------------------

@router.post("/admin/order/{order_id}/price")
async def admin_set_price(order_id: int, body: PriceBody, request: Request):
    require_admin(request)

    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="سفارش یافت نشد")

    st = canon_status(str(req["status"] or ""))
    if st in FINAL_ORDER_STATUSES:
        raise HTTPException(status_code=409, detail="این سفارش قبلاً نهایی شده است")

    provider   = normalize_phone(str(req["driver_phone"] or "")) or get_admin_provider_phone(request)
    exec_dt    = None
    # ✅ وضعیت جدید: PRICE_CONFIRMED به جای IN_PROGRESS
    new_status = STATUS_CANCELED if not body.agree else STATUS_PRICE_CONFIRMED

    async with database.transaction():
        if body.agree:
            if st != STATUS_ASSIGNED:
                raise HTTPException(
                    status_code=409,
                    detail="تعیین قیمت فقط بعد از تأیید زمان بازدید امکان‌پذیر است",
                )
            if not body.exec_time:
                raise HTTPException(status_code=400, detail="زمان اجرا الزامی است")

            exec_dt = parse_iso_utc(str(body.exec_time))
            end_dt  = exec_dt + timedelta(hours=SLOT_DURATION_HOURS)

            if not await provider_is_free(provider, exec_dt, end_dt, int(order_id)):
                raise HTTPException(status_code=409, detail="تداخل زمانی با سفارش دیگری")

            exist = await database.fetch_one(
                AppointmentTable.__table__.select().where(
                    (AppointmentTable.provider_phone == provider) &
                    (AppointmentTable.start_time == exec_dt)
                ).limit(1)
            )
            if exist:
                if str(exist["status"]) == "BOOKED" and int(exist["request_id"]) != int(order_id):
                    raise HTTPException(status_code=409, detail="تداخل در appointment")
                await database.execute(
                    AppointmentTable.__table__.update().where(
                        AppointmentTable.id == int(exist["id"])
                    ).values(request_id=int(order_id), status="BOOKED")
                )
            else:
                await database.execute(
                    AppointmentTable.__table__.insert().values(
                        provider_phone=provider, request_id=int(order_id),
                        start_time=exec_dt, end_time=end_dt,
                        status="BOOKED", created_at=utc_now(),
                    )
                )
        else:
            # عدم توافق قیمت → کنسل
            await database.execute(
                ScheduleSlotTable.__table__.update().where(
                    (ScheduleSlotTable.request_id == int(order_id)) &
                    (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))
                ).values(status="REJECTED")
            )
            await database.execute(
                AppointmentTable.__table__.update().where(
                    (AppointmentTable.request_id == int(order_id)) &
                    (AppointmentTable.status == "BOOKED")
                ).values(status="CANCELED")
            )

        saved = await database.fetch_one(
            RequestTable.__table__.update().where(
                RequestTable.id == int(order_id)
            ).values(
                price=int(body.price),
                status=new_status,
                execution_start=exec_dt,
                driver_phone=provider,
            ).returning(
                RequestTable.id,
                RequestTable.price,
                RequestTable.status,
                RequestTable.execution_start,
            )
        )

    # ✅ نوتیف با متن واقعی
    try:
        event = "execution_set" if body.agree else "canceled_by_manager"
        await notify_user(
            phone=str(req["user_phone"]),
            title="", body="",
            event=event,
            data=push_event_data(
                event=event, order_id=int(order_id),
                status=new_status,
                service_type=str(req["service_type"] or ""),
                user_phone=str(req["user_phone"] or ""),
                scheduled_start=req["scheduled_start"],
                execution_start=exec_dt,
                price=int(body.price),
            ),
        )
    except Exception as e:
        logger.error(f"notify_user(set_price) failed: {e}")

    return unified_response("ok", "PRICE_SET", "قیمت و زمان اجرا تعیین شد", {
        "order_id": int(saved["id"]),
        "price": int(saved["price"]),
        "status": canon_status(str(saved["status"] or "")),
        "execution_start": iso_utc(saved["execution_start"]),
    })


# -------------------- Start order (admin) ✅ جدید --------------------

@router.post("/order/{order_id}/start")
async def start_order(order_id: int, request: Request):
    """
    شروع اجرای کار توسط مدیر
    PRICE_CONFIRMED → IN_PROGRESS
    """
    require_admin(request)

    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="سفارش یافت نشد")

    st = canon_status(str(req["status"] or ""))
    if st != STATUS_PRICE_CONFIRMED:
        raise HTTPException(
            status_code=409,
            detail=f"فقط سفارش‌های تأیید شده قابل شروع هستند (وضعیت فعلی: {st})",
        )

    await database.execute(
        RequestTable.__table__.update().where(RequestTable.id == int(order_id)).values(
            status=STATUS_IN_PROGRESS,
        )
    )

    try:
        await notify_user(
            phone=str(req["user_phone"]),
            title="", body="",
            event="in_progress",
            data=push_event_data(
                event="in_progress", order_id=int(order_id),
                status=STATUS_IN_PROGRESS,
                service_type=str(req["service_type"] or ""),
                user_phone=str(req["user_phone"] or ""),
            ),
        )
    except Exception as e:
        logger.error(f"notify(start_order) failed: {e}")

    return unified_response("ok", "ORDER_STARTED", "اجرای کار شروع شد", {
        "order_id": int(order_id),
        "status": STATUS_IN_PROGRESS,
    })


# -------------------- Finish order (admin) --------------------

@router.post("/order/{order_id}/finish")
async def finish_order(order_id: int, request: Request):
    require_admin(request)

    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="سفارش یافت نشد")

    st = canon_status(str(req["status"] or ""))
    # ✅ هم IN_PROGRESS هم PRICE_CONFIRMED قابل پایان هستن
    if st not in [STATUS_IN_PROGRESS, STATUS_PRICE_CONFIRMED]:
        raise HTTPException(
            status_code=409,
            detail=f"فقط سفارش‌های در حال اجرا یا تأیید شده قابل پایان هستند (وضعیت: {st})",
        )

    async with database.transaction():
        await database.execute(
            RequestTable.__table__.update().where(RequestTable.id == int(order_id)).values(
                status=STATUS_FINISH,
                finish_datetime=utc_now(),
            )
        )
        await database.execute(
            AppointmentTable.__table__.update().where(
                (AppointmentTable.request_id == int(order_id)) &
                (AppointmentTable.status == "BOOKED")
            ).values(status="DONE")
        )

    try:
        await notify_user(
            phone=str(req["user_phone"]),
            title="", body="",
            event="finished",
            data=push_event_data(
                event="finished", order_id=int(order_id),
                status=STATUS_FINISH,
                service_type=str(req["service_type"] or ""),
                user_phone=str(req["user_phone"] or ""),
            ),
        )
    except Exception as e:
        logger.error(f"notify(finish) failed: {e}")

    return unified_response("ok", "ORDER_FINISHED", "سفارش با موفقیت پایان یافت", {
        "order_id": int(order_id),
        "status": STATUS_FINISH,
    })


# -------------------- Admin cancel --------------------

@router.post("/admin/order/{order_id}/cancel")
async def admin_cancel_order(order_id: int, request: Request):
    require_admin(request)

    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="سفارش یافت نشد")

    if canon_status(str(req["status"] or "")) in FINAL_ORDER_STATUSES:
        raise HTTPException(status_code=409, detail="این سفارش قبلاً نهایی شده است")

    await database.execute(
        RequestTable.__table__.update().where(RequestTable.id == int(order_id)).values(
            status=STATUS_CANCELED,
            scheduled_start=None,
            execution_start=None,
            finish_datetime=None,
        )
    )
    await database.execute(
        ScheduleSlotTable.__table__.update().where(
            (ScheduleSlotTable.request_id == int(order_id)) &
            (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))
        ).values(status="REJECTED")
    )
    await database.execute(
        AppointmentTable.__table__.update().where(
            (AppointmentTable.request_id == int(order_id)) &
            (AppointmentTable.status == "BOOKED")
        ).values(status="CANCELED")
    )

    try:
        await notify_user(
            phone=str(req["user_phone"]),
            title="", body="",
            event="canceled_by_manager",
            data=push_event_data(
                event="canceled_by_manager", order_id=int(order_id),
                status=STATUS_CANCELED,
                service_type=str(req["service_type"] or ""),
                user_phone=str(req["user_phone"] or ""),
            ),
        )
    except Exception as e:
        logger.error(f"notify(admin_cancel) failed: {e}")

    return unified_response("ok", "ORDER_CANCELED", "سفارش توسط مدیر لغو شد", {
        "order_id": int(order_id),
        "status": STATUS_CANCELED,
    })
