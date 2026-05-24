"""Public endpoints (services, promotions, reviews).

These are usable without authentication. Sensitive data such as user
phone numbers is masked.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query

from ..database import database, promotions, reviews, services, users
from ..deps import rate_limit
from ..schemas import ReviewPublic
from ..utils import mask_phone

router = APIRouter(prefix="/public", tags=["public"])

# Tiny in-process cache for /home (60s).
_home_cache: dict = {"data": None, "expires_at": 0.0}
_home_lock = asyncio.Lock()


@router.get("/home")
async def home_payload() -> Dict[str, Any]:
    """Return active services + active promotions in a single payload."""
    async with _home_lock:
        now = time.monotonic()
        if _home_cache["data"] is not None and now < _home_cache["expires_at"]:
            return _home_cache["data"]
        svc_rows = await database.fetch_all(
            services.select()
            .where(services.c.is_active == True)  # noqa: E712
            .order_by(services.c.sort_order, services.c.id)
        )
        promo_rows = await database.fetch_all(
            promotions.select()
            .where(promotions.c.is_active == True)  # noqa: E712
            .order_by(promotions.c.id.desc())
        )
        data = {
            "services": [dict(r) for r in svc_rows],
            "promotions": [dict(r) for r in promo_rows],
        }
        _home_cache["data"] = data
        _home_cache["expires_at"] = now + 60.0
        return data


@router.get(
    "/reviews",
    response_model=List[ReviewPublic],
    dependencies=[Depends(rate_limit(limit=30, window_seconds=60, scope="reviews"))],
)
async def list_reviews(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> List[ReviewPublic]:
    rows = await database.fetch_all(
        f"""
        SELECT r.id, r.rating, r.comment, r.created_at, u.phone
          FROM reviews r
          JOIN users u ON u.id = r.user_id
         WHERE r.is_public = true
         ORDER BY r.created_at DESC
         LIMIT :limit OFFSET :offset
        """,
        values={"limit": limit, "offset": offset},
    )
    return [
        ReviewPublic(
            id=int(r["id"]),
            rating=int(r["rating"]),
            comment=r["comment"],
            created_at=r["created_at"],
            masked_phone=mask_phone(r["phone"]),
        )
        for r in rows
    ]
