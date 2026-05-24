"""Shared FastAPI dependencies (authentication, locale, rate limit)."""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .database import database, users
from .i18n import Locale, normalise_locale, t
from .utils import decode_token

_bearer = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------
# Locale
# ---------------------------------------------------------------------
async def current_locale(
    accept_language: str | None = Header(default=None, alias="Accept-Language"),
    x_locale: str | None = Header(default=None, alias="X-Locale"),
) -> Locale:
    return normalise_locale(x_locale or accept_language)


# ---------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------
async def current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    locale: Locale = Depends(current_locale),
) -> Dict[str, Any]:
    if creds is None or not creds.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=t("auth.token_invalid", locale),
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_token(creds.credentials)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=t("auth.token_expired", locale),
            headers={"WWW-Authenticate": "Bearer"},
        )
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=t("auth.token_invalid", locale),
        )
    try:
        uid = int(payload.get("sub", "0"))
    except (TypeError, ValueError):
        uid = 0
    if not uid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=t("auth.token_invalid", locale),
        )
    row = await database.fetch_one(users.select().where(users.c.id == uid))
    if row is None or not row["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=t("auth.user_not_found", locale),
        )
    return dict(row)


async def current_admin(
    user: Dict[str, Any] = Depends(current_user),
    locale: Locale = Depends(current_locale),
) -> Dict[str, Any]:
    if not user.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=t("permission.denied", locale),
        )
    return user


async def optional_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> Dict[str, Any] | None:
    if creds is None or not creds.credentials:
        return None
    try:
        payload = decode_token(creds.credentials)
    except ValueError:
        return None
    if payload.get("type") != "access":
        return None
    try:
        uid = int(payload.get("sub", "0"))
    except (TypeError, ValueError):
        return None
    if not uid:
        return None
    row = await database.fetch_one(users.select().where(users.c.id == uid))
    if row is None or not row["is_active"]:
        return None
    return dict(row)


# ---------------------------------------------------------------------
# Rate limiting (in-process; sufficient for single-instance deployments)
# ---------------------------------------------------------------------
class _RateLimiter:
    def __init__(self) -> None:
        self._buckets: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        async with self._lock:
            bucket = self._buckets[key]
            cutoff = now - window_seconds
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            return True


_global_limiter = _RateLimiter()


def rate_limit(limit: int, window_seconds: int, scope: str):
    """Return a FastAPI dependency that limits *scope* per client IP."""

    async def _dep(
        request: Request,
        locale: Locale = Depends(current_locale),
    ) -> None:
        ip = (request.client.host if request.client else "unknown") or "unknown"
        key = f"{scope}:{ip}"
        if not await _global_limiter.allow(key, limit, window_seconds):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=t("rate.limited", locale),
            )

    return _dep


def per_user_rate_limit(limit: int, window_seconds: int, scope: str):
    """Return a FastAPI dependency that limits *scope* per authenticated user."""

    async def _dep(
        user: Dict[str, Any] = Depends(current_user),
        locale: Locale = Depends(current_locale),
    ) -> Dict[str, Any]:
        key = f"{scope}:u:{user['id']}"
        if not await _global_limiter.allow(key, limit, window_seconds):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=t("rate.limited", locale),
            )
        return user

    return _dep
