"""Pluggable AI provider for the in-app assistant.

Supported providers:

* ``gemini``  – Google Gemini 1.5 Flash (recommended; free tier).
* ``openai``  – OpenAI Chat Completions (paid).

Returns a single reply string and a model identifier.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

from .config import get_settings

logger = logging.getLogger("putzfee.ai")


SYSTEM_PROMPT = (
    "You are PUTZFEE's friendly multilingual assistant. "
    "Answer the user's questions about the cleaning services, prices, "
    "promotions and which combination saves the most money. "
    "Reply in the same language the user wrote in (Persian, English or German). "
    "Be concise. If asked about something unrelated to the app or "
    "cleaning services, politely decline."
)


async def chat(
    user_message: str,
    *,
    history: Optional[List[Dict[str, str]]] = None,
    extra_context: Optional[Dict[str, Any]] = None,
) -> tuple[str, str]:
    s = get_settings()
    provider = (s.AI_PROVIDER or "gemini").lower()
    if not s.AI_API_KEY:
        return (
            "The AI assistant is not configured on the server yet.",
            s.AI_MODEL,
        )
    if provider == "gemini":
        return await _chat_gemini(user_message, history or [], extra_context)
    if provider == "openai":
        return await _chat_openai(user_message, history or [], extra_context)
    raise ValueError(f"unknown AI provider: {provider}")


async def _chat_gemini(
    user_message: str,
    history: List[Dict[str, str]],
    extra_context: Optional[Dict[str, Any]],
) -> tuple[str, str]:
    s = get_settings()
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{s.AI_MODEL}:generateContent?key={s.AI_API_KEY}"
    )

    contents: List[Dict[str, Any]] = []
    for msg in history[-10:]:
        role = "user" if msg.get("role") == "user" else "model"
        contents.append({"role": role, "parts": [{"text": msg.get("content", "")}]})
    contents.append({"role": "user", "parts": [{"text": user_message}]})

    payload: Dict[str, Any] = {
        "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": contents,
        "generationConfig": {
            "maxOutputTokens": s.AI_MAX_TOKENS,
            "temperature": s.AI_TEMPERATURE,
        },
    }
    if extra_context:
        payload["systemInstruction"]["parts"].append(
            {"text": f"Context: {extra_context}"}
        )

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(url, json=payload)
    if r.status_code != 200:
        logger.warning("Gemini call failed %s: %s", r.status_code, r.text)
        return ("Sorry, the assistant is unavailable right now.", s.AI_MODEL)
    data = r.json()
    try:
        parts = data["candidates"][0]["content"]["parts"]
        text = "".join(p.get("text", "") for p in parts).strip()
    except (KeyError, IndexError):
        text = ""
    if not text:
        text = "Sorry, I couldn't generate a reply."
    return text, s.AI_MODEL


async def _chat_openai(
    user_message: str,
    history: List[Dict[str, str]],
    extra_context: Optional[Dict[str, Any]],
) -> tuple[str, str]:
    s = get_settings()
    msgs: List[Dict[str, str]] = [{"role": "system", "content": SYSTEM_PROMPT}]
    if extra_context:
        msgs.append({"role": "system", "content": f"Context: {extra_context}"})
    for m in history[-10:]:
        if m.get("role") in ("user", "assistant") and m.get("content"):
            msgs.append({"role": m["role"], "content": m["content"]})
    msgs.append({"role": "user", "content": user_message})

    payload = {
        "model": s.AI_MODEL,
        "messages": msgs,
        "max_tokens": s.AI_MAX_TOKENS,
        "temperature": s.AI_TEMPERATURE,
    }
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            "https://api.openai.com/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {s.AI_API_KEY}"},
        )
    if r.status_code != 200:
        logger.warning("OpenAI call failed %s: %s", r.status_code, r.text)
        return ("Sorry, the assistant is unavailable right now.", s.AI_MODEL)
    data = r.json()
    try:
        text = data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError):
        text = "Sorry, I couldn't generate a reply."
    return text, s.AI_MODEL
