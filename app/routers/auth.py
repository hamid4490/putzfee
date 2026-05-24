"""Authentication endpoints (register, login, refresh, logout, reset)."""

from __future__ import annotations

import secrets as _secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..config import get_settings
from ..database import database, password_resets, refresh_tokens, users
from ..deps import current_locale, current_user, rate_limit
from ..i18n import Locale, t
from ..schemas import (
    AccessOnly,
    ChangePasswordIn,
    ForgotPasswordIn,
    LoginIn,
    Message,
    RefreshIn,
    RegisterIn,
    ResetPasswordIn,
    TokenPair,
    UserPublic,
)
from ..utils import (
    create_access_token,
    create_refresh_token,
    hash_password,
    hash_refresh_token,
    is_account_locked,
    normalize_phone,
    record_login_attempt,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


# ---------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------
@router.post(
    "/register",
    response_model=TokenPair,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit(limit=10, window_seconds=300, scope="register"))],
)
async def register(
    body: RegisterIn,
    locale: Locale = Depends(current_locale),
) -> TokenPair:
    s = get_settings()
    phone = normalize_phone(body.phone)
    existing = await database.fetch_one(
        users.select().where(users.c.phone == phone)
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=t("auth.phone_taken", locale),
        )

    is_admin = phone in s.admin_phone_set
    user_id = await database.execute(
        users.insert().values(
            phone=phone,
            full_name=body.full_name.strip(),
            password_hash=hash_password(body.password),
            address=body.address,
            locale=body.locale or "en",
            is_admin=is_admin,
        )
    )
    return await _issue_tokens(int(user_id), is_admin)


# ---------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------
@router.post(
    "/login",
    response_model=TokenPair,
    dependencies=[Depends(rate_limit(limit=10, window_seconds=60, scope="login"))],
)
async def login(
    body: LoginIn,
    request: Request,
    locale: Locale = Depends(current_locale),
) -> TokenPair:
    phone = normalize_phone(body.phone)
    ip = (request.client.host if request.client else None)

    if await is_account_locked(phone):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=t("auth.account_locked", locale),
        )

    row = await database.fetch_one(
        users.select().where(users.c.phone == phone)
    )
    if row is None or not row["is_active"]:
        await record_login_attempt(phone, ip, False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=t("auth.invalid_credentials", locale),
        )
    if not verify_password(body.password, row["password_hash"]):
        await record_login_attempt(phone, ip, False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=t("auth.invalid_credentials", locale),
        )
    await record_login_attempt(phone, ip, True)
    return await _issue_tokens(int(row["id"]), bool(row["is_admin"]))


# ---------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------
@router.post(
    "/refresh",
    response_model=TokenPair,
    dependencies=[Depends(rate_limit(limit=30, window_seconds=60, scope="refresh"))],
)
async def refresh(
    body: RefreshIn,
    locale: Locale = Depends(current_locale),
) -> TokenPair:
    digest = hash_refresh_token(body.refresh_token)
    row = await database.fetch_one(
        refresh_tokens.select().where(refresh_tokens.c.token_hash == digest)
    )
    now = datetime.now(timezone.utc)
    if (
        row is None
        or row["revoked_at"] is not None
        or row["expires_at"] < now
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=t("auth.token_invalid", locale),
        )
    user = await database.fetch_one(
        users.select().where(users.c.id == row["user_id"])
    )
    if user is None or not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=t("auth.user_not_found", locale),
        )
    # Rotate: revoke the old refresh token and issue a fresh pair.
    await database.execute(
        refresh_tokens.update()
        .where(refresh_tokens.c.id == row["id"])
        .values(revoked_at=now)
    )
    return await _issue_tokens(int(user["id"]), bool(user["is_admin"]))


# ---------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------
@router.post("/logout", response_model=Message)
async def logout(body: RefreshIn) -> Message:
    digest = hash_refresh_token(body.refresh_token)
    await database.execute(
        refresh_tokens.update()
        .where(refresh_tokens.c.token_hash == digest)
        .values(revoked_at=datetime.now(timezone.utc))
    )
    return Message(message="ok")


# ---------------------------------------------------------------------
# Me / change password
# ---------------------------------------------------------------------
@router.get("/me", response_model=UserPublic)
async def me(user=Depends(current_user)) -> UserPublic:
    return UserPublic(**user)


@router.post("/change-password", response_model=Message)
async def change_password(
    body: ChangePasswordIn,
    user=Depends(current_user),
    locale: Locale = Depends(current_locale),
) -> Message:
    if not verify_password(body.current_password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=t("auth.invalid_credentials", locale),
        )
    await database.execute(
        users.update()
        .where(users.c.id == user["id"])
        .values(password_hash=hash_password(body.new_password))
    )
    # Revoke all refresh tokens for this user.
    await database.execute(
        refresh_tokens.update()
        .where(refresh_tokens.c.user_id == user["id"])
        .where(refresh_tokens.c.revoked_at.is_(None))
        .values(revoked_at=datetime.now(timezone.utc))
    )
    return Message(message="ok")


# ---------------------------------------------------------------------
# Forgot / reset password
# ---------------------------------------------------------------------
@router.post(
    "/forgot-password",
    response_model=Message,
    dependencies=[
        Depends(rate_limit(limit=5, window_seconds=600, scope="forgot")),
    ],
)
async def forgot_password(body: ForgotPasswordIn) -> Message:
    """Generate a single-use reset token.

    Always returns the same message to prevent enumeration. In real
    deployments, the token would be delivered via SMS / push. For now
    the token is logged and returned in the response **only when**
    no FCM configuration is present (development convenience).
    """
    phone = normalize_phone(body.phone)
    row = await database.fetch_one(users.select().where(users.c.phone == phone))
    if row is not None and row["is_active"]:
        token = _secrets.token_urlsafe(24)
        await database.execute(
            password_resets.insert().values(
                user_id=row["id"],
                token_hash=hash_refresh_token(token),
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )
        )
        # In production, deliver via SMS/push. For now, push it to the user.
        from ..push import push_to_user  # local import avoids cycle

        await push_to_user(
            int(row["id"]),
            title="Password reset",
            body="Use the link in the app to reset your password.",
            data={"reset_token": token},
        )
    return Message(message="If the account exists, a reset token was sent.")


@router.post(
    "/reset-password",
    response_model=Message,
    dependencies=[Depends(rate_limit(limit=10, window_seconds=600, scope="reset"))],
)
async def reset_password(
    body: ResetPasswordIn,
    locale: Locale = Depends(current_locale),
) -> Message:
    digest = hash_refresh_token(body.token)
    row = await database.fetch_one(
        password_resets.select().where(password_resets.c.token_hash == digest)
    )
    now = datetime.now(timezone.utc)
    if (
        row is None
        or row["used_at"] is not None
        or row["expires_at"] < now
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=t("auth.token_invalid", locale),
        )
    await database.execute(
        users.update()
        .where(users.c.id == row["user_id"])
        .values(password_hash=hash_password(body.new_password))
    )
    await database.execute(
        password_resets.update()
        .where(password_resets.c.id == row["id"])
        .values(used_at=now)
    )
    # Revoke all refresh tokens after a password reset.
    await database.execute(
        refresh_tokens.update()
        .where(refresh_tokens.c.user_id == row["user_id"])
        .where(refresh_tokens.c.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    return Message(message="ok")


# ---------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------
async def _issue_tokens(user_id: int, is_admin: bool) -> TokenPair:
    access = create_access_token(user_id, is_admin=is_admin)
    refresh_raw, expires_at = create_refresh_token(user_id)
    await database.execute(
        refresh_tokens.insert().values(
            user_id=user_id,
            token_hash=hash_refresh_token(refresh_raw),
            expires_at=expires_at,
        )
    )
    return TokenPair(
        access_token=access,
        refresh_token=refresh_raw,
        user_id=user_id,
        is_admin=is_admin,
    )
