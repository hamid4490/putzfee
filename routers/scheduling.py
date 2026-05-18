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
    STATUS_ASSIGNED,
    STATUS_CANCELED,
    STATUS_FINISH,
    STATUS_IN_PROGRESS,
    STATUS_NEW,
    STATUS_WAITING,
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

    checks = [
        select(func.count()).select_from(AppointmentTable).where(
            (AppointmentTable.provider_phone == provider) &
            (AppointmentTable.status == "BOOKED") &
            (AppointmentTable.start_time < end) &
            (AppointmentTable.end_time > start) &
            (AppointmentTable.request_id != int(exclude_order_id) if exclude_order_id else True)
        ),
        select(func.count()).select_from(ScheduleSlotTable).where(
            (ScheduleSlotTable.provider_phone == provider) &
            (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"])) &
            (ScheduleSlotTable.slot_start < end) &
            (ScheduleSlotTable.slot_start > (start - buffer)) &
            (ScheduleSlotTable.request_id != int(exclude_order_id) if exclude_order_id else True)
        ),
        select(func.count()).select_from(RequestTable).where(
            (RequestTable.driver_phone == provider) &
            (RequestTable.scheduled_start.is_not(None)) &
            (RequestTable.status.in_([STATUS_WAITING, STATUS_ASSIGNED, STATUS_IN_PROGRESS])) &
            (RequestTable.scheduled_start < end) &
            (RequestTable.scheduled_start > (start - buffer)) &
            (RequestTable.id != int(exclude_order_id) if exclude_order_id else True)
        ),
        select(func.count()).select_from(RequestTable).where(
            (RequestTable.driver_phone == provider) &
            (RequestTable.execution_start.is_not(None)) &
            (RequestTable.status == STATUS_IN_PROGRESS) &
            (RequestTable.execution_start < end) &
            (RequestTable.execution_start > (start - buffer)) &
            (RequestTable.id != int(exclude_order_id) if exclude_order_id else True)
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
        (RequestTable.status == STATUS_IN_PROGRESS) &
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
        raise HTTPException(status_code=400, detail="invalid date")

    provider = get_admin_provider_phone(request)
    start = datetime(d.year, d.month, d.day, 0, 0, tzinfo=timezone.utc)
    end = start + timedelta(days=1)

    items = await _busy_slots_for_provider(provider, start, end, exclude_order_id)
    return unified_response("ok", "BUSY_SLOTS", "busy slots", {"items": items})


@router.get("/public/busy_slots")
async def public_busy_slots(date: str, exclude_order_id: Optional[int] = None):
    try:
        d = datetime.fromisoformat(str(date).strip()).date()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid date")

    provider = sorted(ADMIN_PHONES_SET)[0] if ADMIN_PHONES_SET else ""
    if not provider:
        return unified_response("ok", "BUSY_SLOTS", "busy slots", {"items": []})

    start = datetime(d.year, d.month, d.day, 0, 0, tzinfo=timezone.utc)
    end = start + timedelta(days=1)

    items = await _busy_slots_for_provider(provider, start, end, exclude_order_id)
    return unified_response("ok", "BUSY_SLOTS", "busy slots", {"items": items})


# -------------------- Propose slots --------------------

@router.post("/order/{order_id}/propose_slots")
async def propose_slots(order_id: int, body: ProposedSlotsRequest, request: Request):
    require_admin(request)
    provider = get_admin_provider_phone(request)

    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="order not found")

    st = canon_status(str(req["status"] or ""))
    if st in FINAL_ORDER_STATUSES or req["execution_start"]:
        raise HTTPException(status_code=409, detail="cannot propose slots")

    slots = sorted(set(body.slots))[:3]
    if not slots:
        raise HTTPException(status_code=400, detail="slots required")

    slot_dts = [parse_iso_utc(x) for x in slots]

    async with database.transaction():
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
            if not await provider_is_free(provider, dt, dt + timedelta(hours=1), int(order_id)):
                raise HTTPException(status_code=409, detail=f"slot overlap: {dt.isoformat()}")
            await database.execute(
                ScheduleSlotTable.__table__.insert().values(
                    request_id=int(order_id), provider_phone=provider,
                    slot_start=dt, status="PROPOSED", created_at=utc_now(),
                )
            )

    try:
        await notify_user(
            phone=str(req["user_phone"]), title="", body="",
            data=push_event_data(
                event="visit_slots_proposed", order_id=int(order_id),
                status=STATUS_WAITING, service_type=str(req["service_type"] or ""),
                user_phone=str(req["user_phone"] or ""),
            ),
        )
    except Exception as e:
        logger.error(f"notify_user(propose_slots) failed: {e}")

    return unified_response("ok", "SLOTS_PROPOSED", "slots proposed", {
        "accepted": [dt.isoformat() for dt in slot_dts]
    })


# -------------------- Get proposed slots (user) --------------------

@router.get("/order/{order_id}/proposed_slots")
async def get_proposed_slots(order_id: int, request: Request):
    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="order not found")

    require_user_phone(request, str(req["user_phone"]))

    rows = await database.fetch_all(
        ScheduleSlotTable.__table__.select().where(
            (ScheduleSlotTable.request_id == int(order_id)) &
            (ScheduleSlotTable.status == "PROPOSED")
        ).order_by(ScheduleSlotTable.slot_start.asc())
    )

    return unified_response("ok", "PROPOSED_SLOTS", "proposed slots", {
        "items": [r["slot_start"].astimezone(timezone.utc).isoformat() for r in rows]
    })


# -------------------- Confirm slot (user) --------------------

@router.post("/order/{order_id}/confirm_slot")
async def confirm_slot(order_id: int, body: ConfirmSlotRequest, request: Request):
    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="order not found")

    require_user_phone(request, str(req["user_phone"]))

    st = canon_status(str(req["status"] or ""))
    if req["execution_start"] or st not in [STATUS_WAITING, STATUS_ASSIGNED, STATUS_NEW]:
        raise HTTPException(status_code=409, detail="cannot confirm")

    slot_dt = parse_iso_utc(body.slot)
    end_dt = slot_dt + timedelta(hours=1)

    async with database.transaction():
        slot_row = await database.fetch_one(
            ScheduleSlotTable.__table__.select().where(
                (ScheduleSlotTable.request_id == int(order_id)) &
                (ScheduleSlotTable.slot_start == slot_dt) &
                (ScheduleSlotTable.status == "PROPOSED")
            )
        )
        if not slot_row:
            raise HTTPException(status_code=404, detail="slot not found")

        provider = normalize_phone(str(slot_row["provider_phone"]))
        if not await provider_is_free(provider, slot_dt, end_dt, int(order_id)):
            raise HTTPException(status_code=409, detail="time slot overlap")

        # Reject other slots for this order
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

        # Cancel existing appointments for this order (different time)
        await database.execute(
            AppointmentTable.__table__.update().where(
                (AppointmentTable.request_id == int(order_id)) &
                (AppointmentTable.status == "BOOKED") &
                ((AppointmentTable.start_time != slot_dt) | (AppointmentTable.end_time != end_dt))
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
                raise HTTPException(status_code=409, detail="appointment conflict")
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

    try:
        await notify_managers(
            title="", body="",
            data=push_event_data(
                event="visit_time_confirmed", order_id=int(order_id),
                status=STATUS_ASSIGNED, service_type=str(req["service_type"] or ""),
                user_phone=str(req["user_phone"] or ""), scheduled_start=slot_dt,
            ),
            target_phone=provider,
        )
    except Exception as e:
        logger.error(f"notify(confirm_slot) failed: {e}")

    return unified_response("ok", "SLOT_CONFIRMED", "confirmed", {
        "start": slot_dt.isoformat(),
        "end": end_dt.isoformat(),
    })


# -------------------- Reject all & cancel (user) --------------------

@router.post("/order/{order_id}/reject_all_and_cancel")
async def reject_all_and_cancel(order_id: int, request: Request):
    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="order not found")

    require_user_phone(request, str(req["user_phone"]))

    st = canon_status(str(req["status"] or ""))
    if req["execution_start"] or st not in [STATUS_NEW, STATUS_WAITING, STATUS_ASSIGNED]:
        raise HTTPException(status_code=409, detail="cannot cancel")

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
            data=push_event_data(
                event="canceled_by_user", order_id=int(order_id),
                status=STATUS_CANCELED, service_type=str(req["service_type"] or ""),
                user_phone=str(req["user_phone"] or ""),
            ),
        )
    except Exception as e:
        logger.error(f"notify_managers(reject_all) failed: {e}")

    return unified_response("ok", "ORDER_CANCELED", "canceled", {"order_id": int(order_id)})


# -------------------- Set price (admin) --------------------

@router.post("/admin/order/{order_id}/price")
async def admin_set_price(order_id: int, body: PriceBody, request: Request):
    require_admin(request)

    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="order not found")

    st = canon_status(str(req["status"] or ""))
    if st in FINAL_ORDER_STATUSES:
        raise HTTPException(status_code=409, detail="order already final")

    provider = normalize_phone(str(req["driver_phone"] or "")) or get_admin_provider_phone(request)
    exec_dt = None
    new_status = STATUS_CANCELED if not body.agree else STATUS_IN_PROGRESS

    async with database.transaction():
        if body.agree:
            if st != STATUS_ASSIGNED:
                raise HTTPException(
                    status_code=409,
                    detail="price can be set only after visit time is confirmed",
                )
            if not body.exec_time:
                raise HTTPException(status_code=400, detail="exec_time required")

            exec_dt = parse_iso_utc(str(body.exec_time))
            end_dt = exec_dt + timedelta(hours=1)

            if not await provider_is_free(provider, exec_dt, end_dt, int(order_id)):
                raise HTTPException(status_code=409, detail="time overlap")

            exist = await database.fetch_one(
                AppointmentTable.__table__.select().where(
                    (AppointmentTable.provider_phone == provider) &
                    (AppointmentTable.start_time == exec_dt)
                ).limit(1)
            )
            if exist:
                if str(exist["status"]) == "BOOKED" and int(exist["request_id"]) != int(order_id):
                    raise HTTPException(status_code=409, detail="appointment conflict")
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
                price=int(body.price), status=new_status,
                execution_start=exec_dt, driver_phone=provider,
            ).returning(
                RequestTable.id, RequestTable.price,
                RequestTable.status, RequestTable.execution_start,
            )
        )

    try:
        event = "execution_set" if body.agree else "canceled_by_manager"
        await notify_user(
            phone=str(req["user_phone"]), title="", body="",
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

    return unified_response("ok", "PRICE_SET", "updated", {
        "order_id": int(saved["id"]),
        "price": int(saved["price"]),
        "status": canon_status(str(saved["status"] or "")),
        "execution_start": iso_utc(saved["execution_start"]),
    })


# -------------------- Finish order (admin) --------------------

@router.post("/order/{order_id}/finish")
async def finish_order(order_id: int, request: Request):
    require_admin(request)

    req = await database.fetch_one(
        RequestTable.__table__.select().where(RequestTable.id == int(order_id))
    )
    if not req:
        raise HTTPException(status_code=404, detail="order not found")

    if canon_status(str(req["status"] or "")) != STATUS_IN_PROGRESS:
        raise HTTPException(status_code=409, detail="only in-progress orders can be finished")

    async with database.transaction():
        await database.execute(
            RequestTable.__table__.update().where(RequestTable.id == int(order_id)).values(
                status=STATUS_FINISH, finish_datetime=utc_now(),
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
            phone=str(req["user_phone"]), title="", body="",
            data=push_event_data(
                event="finished", order_id=int(order_id),
                status=STATUS_FINISH, service_type=str(req["service_type"] or ""),
                user_phone=str(req["user_phone"] or ""),
            ),
        )
    except Exception as e:
        logger.error(f"notify(finish) failed: {e}")

    return unified_response("ok", "ORDER_FINISHED", "finished", {
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
        raise HTTPException(status_code=404, detail="order not found")

    if canon_status(str(req["status"] or "")) in FINAL_ORDER_STATUSES:
        raise HTTPException(status_code=409, detail="order already final")

    await database.execute(
        RequestTable.__table__.update().where(RequestTable.id == int(order_id)).values(
            status=STATUS_CANCELED, scheduled_start=None,
            execution_start=None, finish_datetime=None,
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
            phone=str(req["user_phone"]), title="", body="",
            data=push_event_data(
                event="canceled_by_manager", order_id=int(order_id),
                status=STATUS_CANCELED, service_type=str(req["service_type"] or ""),
                user_phone=str(req["user_phone"] or ""),
            ),
        )
    except Exception as e:
        logger.error(f"notify(admin_cancel) failed: {e}")

    return unified_response("ok", "ORDER_CANCELED", "canceled by admin", {
        "order_id": int(order_id),
        "status": STATUS_CANCELED,
    })
