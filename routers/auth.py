# FILE: routers/auth.py
# -*- coding: utf-8 -*-

from datetime import timedelta

from fastapi import APIRouter, HTTPException, Request

from config import (
    ADMIN_PHONES_ENV,
    LOGIN_LOCK_SECONDS,
    LOGIN_MAX_ATTEMPTS,
    LOGIN_WINDOW_SECONDS,
    REFRESH_TOKEN_EXPIRE_DAYS,
    ROLE_ADMIN,
    ROLE_USER,
)
from database import (
    DeviceTokenTable,
    LoginAttemptTable,
    RefreshTokenTable,
    UserTable,
    database,
)
from schemas import (
    AdminLoginRequest,
    LogoutRequest,
    PushRegister,
    PushUnregister,
    RefreshAccessRequest,
    UserLoginRequest,
    UserRegisterRequest,
)
from sqlalchemy import func, select
from utils import (
    ADMIN_PHONES_SET,
    bcrypt_hash_password,
    create_access_token,
    create_refresh_token,
    get_client_ip,
    hash_refresh_token,
    normalize_phone,
    unified_response,
    utc_now,
    verify_password_secure,
)

router = APIRouter(tags=["auth"])


# -------------------- Rate-limit helper --------------------

async def _check_and_update_rate_limit(phone: str, ip: str) -> dict:
    now = utc_now()
    sel = LoginAttemptTable.__table__.select().where(
        (LoginAttemptTable.phone == phone) &
        (LoginAttemptTable.ip == ip)
    )
    att = await database.fetch_one(sel)

    if not att:
        await database.execute(
            LoginAttemptTable.__table__.insert().values(
                phone=phone, ip=ip,
                attempt_count=0, window_start=now,
                locked_until=None, last_attempt_at=now, created_at=now,
            )
        )
        att = await database.fetch_one(sel)

    locked_until = att["locked_until"]
    if locked_until and locked_until > now:
        remain = int((locked_until - now).total_seconds())
        raise HTTPException(
            status_code=429,
            detail={"code": "RATE_LIMITED", "lock_remaining": remain},
            headers={"Retry-After": str(remain)},
        )

    if (now - att["window_start"]).total_seconds() > LOGIN_WINDOW_SECONDS:
        await database.execute(
            LoginAttemptTable.__table__.update().where(
                LoginAttemptTable.id == int(att["id"])
            ).values(attempt_count=0, window_start=now, locked_until=None, last_attempt_at=now)
        )
        att = await database.fetch_one(sel)

    return att


async def _record_failed_attempt(att: dict) -> None:
    now = utc_now()
    cur = int(att["attempt_count"] or 0) + 1
    if cur >= LOGIN_MAX_ATTEMPTS:
        lock_time = now + timedelta(seconds=LOGIN_LOCK_SECONDS)
        await database.execute(
            LoginAttemptTable.__table__.update().where(
                LoginAttemptTable.id == int(att["id"])
            ).values(attempt_count=cur, locked_until=lock_time, last_attempt_at=now)
        )
        raise HTTPException(
            status_code=429,
            detail={"code": "RATE_LIMITED", "lock_remaining": LOGIN_LOCK_SECONDS},
            headers={"Retry-After": str(LOGIN_LOCK_SECONDS)},
        )
    rem = max(0, LOGIN_MAX_ATTEMPTS - cur)
    await database.execute(
        LoginAttemptTable.__table__.update().where(
            LoginAttemptTable.id == int(att["id"])
        ).values(attempt_count=cur, last_attempt_at=now)
    )
    raise HTTPException(
        status_code=401,
        detail={"code": "WRONG_PASSWORD", "remaining_attempts": rem},
        headers={"X-Remaining-Attempts": str(rem)},
    )


async def _clear_rate_limit(att: dict) -> None:
    now = utc_now()
    await database.execute(
        LoginAttemptTable.__table__.update().where(
            LoginAttemptTable.id == int(att["id"])
        ).values(attempt_count=0, window_start=now, locked_until=None, last_attempt_at=now)
    )


async def _issue_tokens(user_id: int, phone: str, role: str) -> tuple[str, str]:
    now = utc_now()
    access = create_access_token(phone, role)
    refresh = create_refresh_token()
    await database.execute(
        RefreshTokenTable.__table__.insert().values(
            user_id=user_id,
            token_hash=hash_refresh_token(refresh),
            expires_at=now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
            revoked=False,
            created_at=now,
        )
    )
    return access, refresh


# -------------------- Endpoints --------------------

@router.get("/verify_token")
def verify_token(request: Request):
    from utils import decode_access_token, extract_bearer_token
    token = extract_bearer_token(request)
    if not token:
        return {"status": "ok", "valid": False, "role": None, "phone": None}
    payload = decode_access_token(token)
    if not payload or not payload.get("sub"):
        return {"status": "ok", "valid": False, "role": None, "phone": None}
    return {
        "status": "ok",
        "valid": True,
        "role": str(payload.get("role") or ""),
        "phone": normalize_phone(str(payload.get("sub") or "")),
    }


@router.get("/users/exists")
async def user_exists(phone: str):
    norm = normalize_phone(phone)
    if not norm:
        return unified_response("ok", "USER_NOT_FOUND", "check", {"exists": False})
    count = await database.fetch_val(
        select(func.count()).select_from(UserTable).where(UserTable.phone == norm)
    )
    exists = bool(count and int(count) > 0)
    return unified_response(
        "ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "check", {"exists": exists}
    )


@router.post("/register_user")
async def register_user(user: UserRegisterRequest):
    norm = normalize_phone(user.phone)
    if not norm:
        raise HTTPException(status_code=400, detail="phone required")

    count = await database.fetch_val(
        select(func.count()).select_from(UserTable).where(UserTable.phone == norm)
    )
    if count and int(count) > 0:
        raise HTTPException(status_code=400, detail="User already exists")

    await database.execute(
        UserTable.__table__.insert().values(
            phone=norm,
            password_hash=bcrypt_hash_password(user.password),
            address=str(user.address or "").strip(),
            name="",
            car_list=[],
            photo_path="",
            photo_mime="",
            photo_updated_at=None,
        )
    )
    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": norm})


@router.post("/login")
async def login_user(user: UserLoginRequest, request: Request):
    phone = normalize_phone(user.phone)
    if not phone:
        raise HTTPException(status_code=400, detail="invalid phone")

    ip = get_client_ip(request)
    att = await _check_and_update_rate_limit(phone, ip)

    db_user = await database.fetch_one(
        UserTable.__table__.select().where(UserTable.phone == phone)
    )
    if not db_user:
        raise HTTPException(status_code=404, detail={"code": "USER_NOT_FOUND"})

    if not verify_password_secure(user.password, db_user["password_hash"]):
        await _record_failed_attempt(att)

    await _clear_rate_limit(att)
    access, refresh = await _issue_tokens(int(db_user["id"]), phone, ROLE_USER)

    return {
        "status": "ok",
        "access_token": access,
        "refresh_token": refresh,
        "user": {
            "phone": phone,
            "address": str(db_user["address"] or ""),
            "name": str(db_user["name"] or ""),
            "role": ROLE_USER,
        },
    }


@router.post("/admin/login")
async def admin_login(body: AdminLoginRequest, request: Request):
    phone = normalize_phone(body.phone)
    if not phone:
        raise HTTPException(status_code=400, detail="invalid phone")

    if phone not in ADMIN_PHONES_SET:
        raise HTTPException(
            status_code=401,
            detail={"code": "WRONG_PASSWORD", "remaining_attempts": 0},
        )

    password_raw = str(body.password or "").strip()
    if not password_raw:
        raise HTTPException(status_code=400, detail="password required")

    ip = get_client_ip(request)
    att = await _check_and_update_rate_limit(phone, ip)

    db_user = await database.fetch_one(
        UserTable.__table__.select().where(UserTable.phone == phone)
    )

    if not db_user:
        # First login: store password
        await database.execute(
            UserTable.__table__.insert().values(
                phone=phone,
                password_hash=bcrypt_hash_password(password_raw),
                address="",
                name="Manager",
                car_list=[],
                photo_path="",
                photo_mime="",
                photo_updated_at=None,
            )
        )
        db_user = await database.fetch_one(
            UserTable.__table__.select().where(UserTable.phone == phone)
        )
    else:
        if not verify_password_secure(password_raw, db_user["password_hash"]):
            await _record_failed_attempt(att)

    await _clear_rate_limit(att)
    access, refresh = await _issue_tokens(int(db_user["id"]), phone, ROLE_ADMIN)

    return {
        "status": "ok",
        "access_token": access,
        "refresh_token": refresh,
        "user": {
            "phone": phone,
            "address": str(db_user["address"] or ""),
            "name": str(db_user["name"] or "Manager"),
            "role": ROLE_ADMIN,
        },
    }


@router.post("/auth/refresh")
async def refresh_access(body: RefreshAccessRequest):
    raw = str(body.refresh_token or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="refresh_token required")

    token_hash = hash_refresh_token(raw)
    row = await database.fetch_one(
        RefreshTokenTable.__table__.select().where(RefreshTokenTable.token_hash == token_hash)
    )
    if not row or bool(row["revoked"]):
        raise HTTPException(status_code=401, detail="invalid/revoked refresh token")
    if row["expires_at"] <= utc_now():
        raise HTTPException(status_code=401, detail="refresh token expired")

    db_user = await database.fetch_one(
        UserTable.__table__.select().where(UserTable.id == int(row["user_id"]))
    )
    if not db_user:
        raise HTTPException(status_code=401, detail="user not found")

    phone = normalize_phone(db_user["phone"])
    role = ROLE_ADMIN if phone in ADMIN_PHONES_SET else ROLE_USER
    access = create_access_token(phone, role)

    return unified_response("ok", "ACCESS_REFRESHED", "access token refreshed", {
        "access_token": access,
        "role": role,
        "phone": phone,
    })


@router.post("/logout")
async def logout_user(body: LogoutRequest):
    raw = str(body.refresh_token or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="refresh_token required")

    token_hash = hash_refresh_token(raw)
    rt_row = await database.fetch_one(
        RefreshTokenTable.__table__.select().where(RefreshTokenTable.token_hash == token_hash)
    )

    await database.execute(
        RefreshTokenTable.__table__.update().where(
            RefreshTokenTable.token_hash == token_hash
        ).values(revoked=True)
    )

    device_token = str(body.device_token or "").strip()
    if device_token:
        await database.execute(
            DeviceTokenTable.__table__.delete().where(DeviceTokenTable.token == device_token)
        )
    elif rt_row:
        db_user = await database.fetch_one(
            UserTable.__table__.select().where(UserTable.id == int(rt_row["user_id"]))
        )
        if db_user:
            phone = normalize_phone(db_user["phone"])
            await database.execute(
                DeviceTokenTable.__table__.delete().where(
                    DeviceTokenTable.user_phone == phone
                )
            )

    return unified_response("ok", "LOGOUT", "logged out", {})


@router.post("/push/register")
async def register_push_token(body: PushRegister):
    now = utc_now()
    token = str(body.token or "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="token required")

    role = str(body.role or "").strip().lower()
    platform = str(body.platform or "android").strip().lower()
    norm_phone = normalize_phone(body.user_phone) if body.user_phone else None

    row = await database.fetch_one(
        DeviceTokenTable.__table__.select().where(DeviceTokenTable.token == token)
    )

    if row is None:
        await database.execute(
            DeviceTokenTable.__table__.insert().values(
                token=token, role=role, platform=platform,
                user_phone=norm_phone, created_at=now, updated_at=now,
            )
        )
    else:
        await database.execute(
            DeviceTokenTable.__table__.update().where(
                DeviceTokenTable.id == int(row["id"])
            ).values(
                role=role,
                platform=platform,
                user_phone=norm_phone if norm_phone else row["user_phone"],
                updated_at=now,
            )
        )

    return unified_response("ok", "TOKEN_REGISTERED", "registered", {"role": role})


@router.post("/push/unregister")
async def unregister_push_token(body: PushUnregister):
    token = str(body.token or "").strip()
    if token:
        await database.execute(
            DeviceTokenTable.__table__.delete().where(DeviceTokenTable.token == token)
        )
    return unified_response("ok", "TOKEN_UNREGISTERED", "unregistered", {})
