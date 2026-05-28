"""User-facing profile, cars and device-token endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status

from ..database import cars, database, device_tokens, notifications, users
from ..deps import current_locale, current_user, rate_limit
from ..i18n import Locale, t
from ..media import absolute_url, save_image
from ..schemas import (
    CarIn,
    CarOut,
    DeviceTokenIn,
    Message,
    NotificationOut,
    UserPublic,
    UserUpdate,
)

router = APIRouter(prefix="/user", tags=["user"])


# ---------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------
@router.get("/me", response_model=UserPublic)
async def me(user=Depends(current_user)) -> UserPublic:
    return UserPublic(**user)


@router.patch("/me", response_model=UserPublic)
async def update_me(
    body: UserUpdate, user=Depends(current_user)
) -> UserPublic:
    values = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
    if values:
        values["updated_at"] = datetime.now(timezone.utc)
        await database.execute(
            users.update().where(users.c.id == user["id"]).values(**values)
        )
    row = await database.fetch_one(users.select().where(users.c.id == user["id"]))
    return UserPublic(**dict(row))


@router.post("/me/photo", response_model=UserPublic)
async def upload_photo(
    file: UploadFile = File(...),
    user=Depends(current_user),
) -> UserPublic:
    url = await save_image(file, sub_dir="avatars")
    absolute = absolute_url(url)
    await database.execute(
        users.update()
        .where(users.c.id == user["id"])
        .values(photo_url=absolute, updated_at=datetime.now(timezone.utc))
    )
    row = await database.fetch_one(users.select().where(users.c.id == user["id"]))
    return UserPublic(**dict(row))


# ---------------------------------------------------------------------
# Cars
# ---------------------------------------------------------------------
@router.get("/cars", response_model=List[CarOut])
async def list_cars(user=Depends(current_user)) -> List[CarOut]:
    rows = await database.fetch_all(
        cars.select().where(cars.c.user_id == user["id"]).order_by(cars.c.id)
    )
    return [CarOut(**dict(r)) for r in rows]


@router.post("/cars", response_model=CarOut, status_code=status.HTTP_201_CREATED)
async def add_car(body: CarIn, user=Depends(current_user)) -> CarOut:
    new_id = await database.execute(
        cars.insert().values(
            user_id=user["id"],
            brand=body.brand.strip(),
            model=body.model.strip(),
            plate=body.plate,
            color=body.color,
        )
    )
    row = await database.fetch_one(cars.select().where(cars.c.id == new_id))
    return CarOut(**dict(row))


@router.patch("/cars/{car_id}", response_model=CarOut)
async def update_car(
    car_id: int, body: CarIn, user=Depends(current_user)
) -> CarOut:
    row = await database.fetch_one(cars.select().where(cars.c.id == car_id))
    if row is None or row["user_id"] != user["id"]:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="car not found")
    await database.execute(
        cars.update().where(cars.c.id == car_id).values(
            brand=body.brand.strip(),
            model=body.model.strip(),
            plate=body.plate,
            color=body.color,
        )
    )
    row = await database.fetch_one(cars.select().where(cars.c.id == car_id))
    return CarOut(**dict(row))


@router.delete("/cars/{car_id}", response_model=Message)
async def delete_car(car_id: int, user=Depends(current_user)) -> Message:
    row = await database.fetch_one(cars.select().where(cars.c.id == car_id))
    if row is None or row["user_id"] != user["id"]:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="car not found")
    await database.execute(cars.delete().where(cars.c.id == car_id))
    return Message(message="ok")


# ---------------------------------------------------------------------
# Device tokens (push)
# ---------------------------------------------------------------------
@router.post("/devices", response_model=Message)
async def register_device(body: DeviceTokenIn, user=Depends(current_user)) -> Message:
    # Upsert: if token already exists for another user, take it over.
    await database.execute(
        device_tokens.delete().where(device_tokens.c.token == body.token)
    )
    await database.execute(
        device_tokens.insert().values(
            user_id=user["id"], token=body.token, platform=body.platform
        )
    )
    return Message(message="ok")


@router.delete("/devices/{token}", response_model=Message)
async def unregister_device(token: str, user=Depends(current_user)) -> Message:
    await database.execute(
        device_tokens.delete()
        .where(device_tokens.c.token == token)
        .where(device_tokens.c.user_id == user["id"])
    )
    return Message(message="ok")


# ---------------------------------------------------------------------
# Existence probe (rate-limited)
# ---------------------------------------------------------------------
@router.get(
    "/exists",
    dependencies=[Depends(rate_limit(limit=10, window_seconds=60, scope="exists"))],
)
async def user_exists(phone: str) -> dict:
    """Return a generic OK; never reveal whether the phone exists.

    Kept for backwards compatibility — clients should not depend on the
    boolean. Always returns ``{"exists": true}``.
    """
    return {"exists": True}


# ---------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------
@router.get("/notifications", response_model=List[NotificationOut])
async def list_notifications(
    user=Depends(current_user),
    limit: int = 50,
    offset: int = 0,
) -> List[NotificationOut]:
    rows = await database.fetch_all(
        notifications.select()
        .where(notifications.c.user_id == user["id"])
        .order_by(notifications.c.created_at.desc())
        .limit(max(1, min(limit, 200)))
        .offset(max(0, offset))
    )
    return [NotificationOut(**dict(r)) for r in rows]


@router.post("/notifications/{nid}/read", response_model=Message)
async def mark_read(nid: int, user=Depends(current_user)) -> Message:
    await database.execute(
        notifications.update()
        .where(notifications.c.id == nid)
        .where(notifications.c.user_id == user["id"])
        .values(read_at=datetime.now(timezone.utc))
    )
    return Message(message="ok")


@router.post("/notifications/read-all", response_model=Message)
async def mark_all_read(user=Depends(current_user)) -> Message:
    await database.execute(
        notifications.update()
        .where(notifications.c.user_id == user["id"])
        .where(notifications.c.read_at.is_(None))
        .values(read_at=datetime.now(timezone.utc))
    )
    return Message(message="ok")
