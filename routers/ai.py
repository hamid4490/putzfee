# FILE: routers/ai.py
# -*- coding: utf-8 -*-

import logging
from typing import List

import httpx
from fastapi import APIRouter, HTTPException, Request

from config import (
    AI_API_KEY,
    AI_MAX_TOKENS,
    AI_MODEL,
    AI_PROVIDER,
    AI_SYSTEM_PROMPT_DE,
    AI_SYSTEM_PROMPT_EN,
    AI_SYSTEM_PROMPT_FA,
    AI_TEMPERATURE,
)
from database import ServicePriceTable, database
from media import media_url
from schemas import AIChatRequest
from utils import pick_i18n, unified_response

router = APIRouter(tags=["ai"])
logger = logging.getLogger("putz.ai")


# -------------------- System prompt builder --------------------

def _get_system_prompt(lang: str) -> str:
    if lang == "de":
        return AI_SYSTEM_PROMPT_DE
    if lang == "en":
        return AI_SYSTEM_PROMPT_EN
    return AI_SYSTEM_PROMPT_FA


async def _build_services_context(lang: str) -> str:
    """
    ساختن context سرویس‌ها برای AI
    تا بتونه سرویس مناسب پیشنهاد بده
    """
    try:
        rows = await database.fetch_all(
            ServicePriceTable.__table__.select()
            .where(ServicePriceTable.active == True)
            .order_by(ServicePriceTable.sort_order.asc())
        )
        if not rows:
            return ""

        lines = []
        for r in rows:
            name  = pick_i18n(r["name_i18n"] or {}, lang)
            price = int(r["base_price"] or 0)
            stype = str(r["service_type"] or "")
            lines.append(f"- {name} ({stype}): {price}")

        if lang == "fa":
            return "سرویس‌های موجود:\n" + "\n".join(lines)
        if lang == "de":
            return "Verfügbare Services:\n" + "\n".join(lines)
        return "Available services:\n" + "\n".join(lines)

    except Exception as e:
        logger.warning(f"_build_services_context failed: {e}")
        return ""


# -------------------- OpenAI --------------------

async def _call_openai(
    messages: List[dict],
    model: str,
    max_tokens: int,
    temperature: float,
) -> str:
    if not AI_API_KEY:
        raise HTTPException(status_code=503, detail="AI service not configured")

    payload = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {AI_API_KEY}",
                "Content-Type": "application/json",
            },
            json=payload,
        )

    if resp.status_code != 200:
        logger.error(f"OpenAI error {resp.status_code}: {resp.text[:300]}")
        raise HTTPException(
            status_code=502,
            detail="خطا در ارتباط با سرویس هوش مصنوعی. لطفاً دوباره تلاش کنید.",
        )

    data = resp.json()
    try:
        return str(data["choices"][0]["message"]["content"]).strip()
    except (KeyError, IndexError) as e:
        logger.error(f"OpenAI parse error: {e} | data: {data}")
        raise HTTPException(status_code=502, detail="خطا در پردازش پاسخ AI")


# -------------------- Gemini --------------------

async def _call_gemini(
    messages: List[dict],
    model: str,
    max_tokens: int,
    temperature: float,
) -> str:
    if not AI_API_KEY:
        raise HTTPException(status_code=503, detail="AI service not configured")

    # تبدیل فرمت OpenAI به Gemini
    contents = []
    for msg in messages:
        role = "user" if msg["role"] in ("user", "system") else "model"
        contents.append({
            "role": role,
            "parts": [{"text": msg["content"]}],
        })

    payload = {
        "contents": contents,
        "generationConfig": {
            "maxOutputTokens": max_tokens,
            "temperature": temperature,
        },
    }

    gemini_model = model if model.startswith("gemini") else "gemini-1.5-flash"
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{gemini_model}:generateContent?key={AI_API_KEY}"
    )

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            url,
            headers={"Content-Type": "application/json"},
            json=payload,
        )

    if resp.status_code != 200:
        logger.error(f"Gemini error {resp.status_code}: {resp.text[:300]}")
        raise HTTPException(
            status_code=502,
            detail="خطا در ارتباط با سرویس هوش مصنوعی. لطفاً دوباره تلاش کنید.",
        )

    data = resp.json()
    try:
        return str(
            data["candidates"][0]["content"]["parts"][0]["text"]
        ).strip()
    except (KeyError, IndexError) as e:
        logger.error(f"Gemini parse error: {e} | data: {data}")
        raise HTTPException(status_code=502, detail="خطا در پردازش پاسخ AI")


# -------------------- Main chat endpoint --------------------

@router.post("/ai/chat")
async def ai_chat(body: AIChatRequest, request: Request):
    """
    چت با دستیار هوشمند PUTZ
    - context سرویس‌ها رو از دیتابیس میگیره
    - تاریخچه مکالمه رو پشتیبانی میکنه
    - سه زبان فارسی، انگلیسی، آلمانی
    """
    lang = str(body.lang or "fa").strip().lower()

    # ساخت context سرویس‌ها
    services_ctx = await _build_services_context(lang)

    # system prompt با context سرویس‌ها
    system_content = _get_system_prompt(lang)
    if services_ctx:
        system_content = f"{system_content}\n\n{services_ctx}"

    # ساخت messages برای API
    messages: List[dict] = [
        {"role": "system", "content": system_content}
    ]

    # اضافه کردن context اضافی از کاربر
    if body.context:
        extra_ctx = []
        if body.context.get("current_service"):
            svc = body.context["current_service"]
            if lang == "fa":
                extra_ctx.append(f"سرویس فعلی کاربر: {svc}")
            else:
                extra_ctx.append(f"Current user service: {svc}")
        if body.context.get("order_status"):
            st = body.context["order_status"]
            if lang == "fa":
                extra_ctx.append(f"وضعیت سفارش: {st}")
            else:
                extra_ctx.append(f"Order status: {st}")
        if extra_ctx:
            messages.append({
                "role": "system",
                "content": "\n".join(extra_ctx),
            })

    # اضافه کردن تاریخچه مکالمه
    for hist_msg in (body.history or [])[-10:]:  # حداکثر 10 پیام قبلی
        role = str(hist_msg.role or "user").strip().lower()
        if role not in ("user", "assistant"):
            continue
        messages.append({
            "role": role,
            "content": str(hist_msg.content or "").strip(),
        })

    # پیام فعلی کاربر
    messages.append({
        "role": "user",
        "content": body.message,
    })

    # ارسال به AI provider
    try:
        if AI_PROVIDER == "gemini":
            reply = await _call_gemini(
                messages, AI_MODEL, AI_MAX_TOKENS, AI_TEMPERATURE
            )
        else:
            # پیش‌فرض: OpenAI
            reply = await _call_openai(
                messages, AI_MODEL, AI_MAX_TOKENS, AI_TEMPERATURE
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"AI chat unexpected error: {e}")
        if lang == "fa":
            raise HTTPException(
                status_code=503,
                detail="سرویس هوش مصنوعی موقتاً در دسترس نیست. لطفاً دوباره تلاش کنید.",
            )
        raise HTTPException(status_code=503, detail="AI service temporarily unavailable")

    return unified_response("ok", "AI_REPLY", "پاسخ دستیار", {
        "reply": reply,
        "lang": lang,
        "provider": AI_PROVIDER,
        "model": AI_MODEL,
    })


# -------------------- Health check AI --------------------

@router.get("/ai/status")
async def ai_status():
    """بررسی وضعیت سرویس AI"""
    configured = bool(AI_API_KEY)
    return unified_response("ok", "AI_STATUS", "وضعیت AI", {
        "configured": configured,
        "provider": AI_PROVIDER if configured else None,
        "model": AI_MODEL if configured else None,
    })
