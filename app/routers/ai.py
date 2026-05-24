"""In-app AI assistant endpoint (authenticated + rate limited)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status

from ..ai_provider import chat
from ..config import get_settings
from ..database import ai_usage, database, promotions, services
from ..deps import current_locale, current_user, per_user_rate_limit
from ..i18n import Locale, t
from ..schemas import AIChatIn, AIChatOut

router = APIRouter(prefix="/ai", tags=["ai"])


@router.post(
    "/chat",
    response_model=AIChatOut,
)
async def ai_chat(
    body: AIChatIn,
    user=Depends(current_user),
    locale: Locale = Depends(current_locale),
) -> AIChatOut:
    s = get_settings()

    # Per-minute and per-day limits, enforced against ai_usage table.
    now = datetime.now(timezone.utc)
    one_min_ago = now - timedelta(minutes=1)
    one_day_ago = now - timedelta(days=1)

    minute_count_row = await database.fetch_one(
        """
        SELECT COUNT(*) AS c FROM ai_usage
         WHERE user_id = :uid AND created_at >= :ts
        """,
        values={"uid": user["id"], "ts": one_min_ago},
    )
    if minute_count_row and int(minute_count_row["c"]) >= s.AI_RATE_PER_MINUTE:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=t("rate.limited", locale),
        )
    day_count_row = await database.fetch_one(
        """
        SELECT COUNT(*) AS c FROM ai_usage
         WHERE user_id = :uid AND created_at >= :ts
        """,
        values={"uid": user["id"], "ts": one_day_ago},
    )
    if day_count_row and int(day_count_row["c"]) >= s.AI_RATE_PER_DAY:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=t("rate.limited", locale),
        )

    # Inject lightweight context (active services + promos) to ground responses.
    svc_rows = await database.fetch_all(
        services.select().where(services.c.is_active == True)  # noqa: E712
    )
    promo_rows = await database.fetch_all(
        promotions.select().where(promotions.c.is_active == True)  # noqa: E712
    )
    context = {
        "services": [
            {
                "key": r["key"],
                "name": r["name_i18n"],
                "price": float(r["base_price"] or 0),
            }
            for r in svc_rows
        ],
        "promotions": [
            {
                "key": r["key"],
                "title": r["title_i18n"],
                "discount_percent": float(r["discount_percent"])
                if r["discount_percent"] is not None
                else None,
                "flat_discount": float(r["flat_discount"])
                if r["flat_discount"] is not None
                else None,
                "applies_to_keys": r["applies_to_keys"] or [],
            }
            for r in promo_rows
        ],
        "locale": locale,
    }
    if body.context:
        context.update(body.context)

    reply, model = await chat(body.message, history=None, extra_context=context)

    await database.execute(
        ai_usage.insert().values(
            user_id=user["id"], prompt_tokens=0, completion_tokens=0
        )
    )
    return AIChatOut(reply=reply, model=model)
