# FILE: routers/user.py
# -*- coding: utf-8 -*-

from typing import Any, Dict, List

from fastapi import APIRouter, File, HTTPException, Query, Request, UploadFile

from database import NotificationTable, UserTable, database
from media import delete_media_file, media_url, save_image_upload
from schemas import CarListUpdateRequest, NotificationReadBody, UserProfileUpdate
from utils import iso_utc, normalize_phone, require_user_phone, unified_response, utc_now

router = APIRouter(tags=["user"])


# -------------------- Profile --------------------

@router.post("/user/{phone}/photo")
async def upload_user_photo(phone: str, request: Request, file: UploadFile = File(...)):
    norm = require_user_phone(request, phone)

    user = await database.fetch_one(
        UserTable.__table__.select().where(UserTable.phone == norm)
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    rel_path, mime, size = await save_image_upload(file, subdir=f"users/{norm}")

    if str(user["photo_path"] or "").strip():
        delete_media_file(str(user["photo_path"]))

    await database.execute(
        UserTable.__table__.update().where(UserTable.phone == norm).values(
            photo_path=rel_path,
            photo_mime=mime,
            photo_updated_at=utc_now(),
        )
    )

    return unified_response("ok", "PHOTO_SAVED", "saved", {
        "phone": norm,
        "photo_url": media_url(rel_path),
        "bytes": int(size),
    })


@router.post("/user/profile")
async def update_profile(body: UserProfileUpdate, request: Request):
    norm = require_user_phone(request, body.phone)

    user = await database.fetch_one(
        UserTable.__table__.select().where(UserTable.phone == norm)
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    await database.execute(
        UserTable.__table__.update().where(UserTable.phone == norm).values(
            name=str(body.name or "").strip(),
            address=str(body.address or "").strip(),
        )
    )
    return unified_response("ok", "PROFILE_UPDATED", "profile saved", {"phone": norm})


@router.get("/user/profile/{phone}")
async def get_user_profile(phone: str, request: Request):
    norm = require_user_phone(request, phone)

    user = await database.fetch_one(
        UserTable.__table__.select().where(UserTable.phone == norm)
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return unified_response("ok", "PROFILE_FETCHED", "profile data", {
        "phone": norm,
        "name": str(user["name"] or ""),
        "address": str(user["address"] or ""),
        "photo_url": media_url(str(user["photo_path"] or "")),
    })


# -------------------- Cars --------------------

@router.get("/user_cars/{user_phone}")
async def get_user_cars(user_phone: str, request: Request):
    norm = require_user_phone(request, user_phone)

    user = await database.fetch_one(
        UserTable.__table__.select().where(UserTable.phone == norm)
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return unified_response("ok", "USER_CARS", "cars list", {
        "items": user["car_list"] or []
    })


@router.post("/user_cars")
async def update_user_cars(body: CarListUpdateRequest, request: Request):
    norm = require_user_phone(request, body.user_phone)

    user = await database.fetch_one(
        UserTable.__table__.select().where(UserTable.phone == norm)
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    cars_payload = [c.model_dump() for c in (body.car_list or [])]
    await database.execute(
        UserTable.__table__.update().where(UserTable.phone == norm).values(
            car_list=cars_payload
        )
    )
    return unified_response("ok", "USER_CARS_UPDATED", "cars updated", {
        "count": len(cars_payload)
    })


# -------------------- Notifications --------------------

@router.get("/notifications/{phone}")
async def list_notifications(
    phone: str,
    request: Request,
    limit: int = Query(50, ge=1, le=200),
):
    norm = require_user_phone(request, phone)

    rows = await database.fetch_all(
        NotificationTable.__table__.select().where(
            NotificationTable.user_phone == norm
        ).order_by(NotificationTable.created_at.desc()).limit(limit)
    )

    items: List[Dict[str, Any]] = [
        {
            "id": int(r["id"]),
            "title": str(r["title"] or ""),
            "body": str(r["body"] or ""),
            "data": r["data"] or {},
            "read": bool(r["read"]),
            "read_at": iso_utc(r["read_at"]),
            "created_at": iso_utc(r["created_at"]),
        }
        for r in rows
    ]

    unread_count = sum(1 for i in items if not i["read"])

    return unified_response("ok", "NOTIFICATIONS", "notifications", {
        "items": items,
        "unread_count": unread_count,
    })


@router.post("/notifications/{phone}/read")
async def mark_notifications_read(phone: str, body: NotificationReadBody, request: Request):
    norm = require_user_phone(request, phone)
    now = utc_now()

    if body.notification_id:
        await database.execute(
            NotificationTable.__table__.update().where(
                (NotificationTable.user_phone == norm) &
                (NotificationTable.id == int(body.notification_id))
            ).values(read=True, read_at=now)
        )
        return unified_response("ok", "NOTIFICATIONS_READ", "marked read", {"count": 1})

    if body.order_id:
        # بهینه‌سازی مستقیم دیتابیس بدون خواندن به حافظه رم پایتون
        query = (
            NotificationTable.__table__.update()
            .where(
                (NotificationTable.user_phone == norm) &
                (NotificationTable.read == False) &
                # پارس ایمن فیلد جیسون دیتابیس برای پیدا کردن شناسه سفارش سریع
                (NotificationTable.data['order_id'].astext == str(int(body.order_id)))
            )
            .values(read=True, read_at=now)
        )
        result = await database.execute(query)
        return unified_response("ok", "NOTIFICATIONS_READ", "marked read", {"count": result})

    # مارک کردن تمام نوتیفیکیشن‌ها به عنوان خوانده شده
    result = await database.execute(
        NotificationTable.__table__.update().where(
            (NotificationTable.user_phone == norm) &
            (NotificationTable.read == False)
        ).values(read=True, read_at=now)
    )
    return unified_response("ok", "NOTIFICATIONS_READ", "all marked read", {"count": result})
