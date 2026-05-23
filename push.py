# FILE: push.py
# -*- coding: utf-8 -*-

import base64
import json
import logging
import time # FILE: push.py
# -*- coding: utf-8 -*-

import base64
import json
import logging
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import httpx
import jwt

from config import (
    FCM_PROJECT_ID,
    FCM_SERVER_KEY,
    GOOGLE_APPLICATION_CREDENTIALS_JSON,
    GOOGLE_APPLICATION_CREDENTIALS_JSON_B64,
    NTFY_AUTH,
    NTFY_BASE_URL,
    PUSH_BACKEND,
)
from database import DeviceTokenTable, NotificationTable, database
from utils import canon_status, iso_utc, normalize_phone, utc_now

logger = logging.getLogger("putz.push")
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[PUSH] %(levelname)s: %(message)s"))
    logger.addHandler(h)
logger.setLevel(logging.INFO)

_FCM_OAUTH_TOKEN = ""
_FCM_OAUTH_EXP   = 0.0


# -------------------- Notification Text --------------------

# ✅ متن نوتیف به سه زبان
_NOTIFICATION_TEXTS: Dict[str, Dict[str, Tuple[str, str]]] = {
    "new_order": {
        "fa": ("سفارش جدید 🛎️", "یک سفارش جدید ثبت شد"),
        "en": ("New Order 🛎️", "A new order has been placed"),
        "de": ("Neue Bestellung 🛎️", "Eine neue Bestellung wurde aufgegeben"),
    },
    "visit_slots_proposed": {
        "fa": ("زمان بازدید 📅", "مدیر زمان‌های بازدید را پیشنهاد داد"),
        "en": ("Visit Times 📅", "Manager proposed visit times"),
        "de": ("Besuchszeiten 📅", "Manager hat Besuchszeiten vorgeschlagen"),
    },
    "visit_time_confirmed": {
        "fa": ("زمان تأیید شد ✅", "زمان بازدید توسط شما تأیید شد"),
        "en": ("Time Confirmed ✅", "Visit time has been confirmed"),
        "de": ("Zeit bestätigt ✅", "Besuchszeit wurde bestätigt"),
    },
    "execution_set": {
        "fa": ("قیمت و زمان تعیین شد 💰", "مدیر قیمت و زمان اجرا را تعیین کرد"),
        "en": ("Price & Time Set 💰", "Manager set the price and execution time"),
        "de": ("Preis & Zeit festgelegt 💰", "Manager hat Preis und Ausführungszeit festgelegt"),
    },
    "in_progress": {
        "fa": ("شروع کار 🔧", "اجرای سفارش شما آغاز شد"),
        "en": ("Work Started 🔧", "Your order execution has started"),
        "de": ("Arbeit begonnen 🔧", "Die Ausführung Ihrer Bestellung hat begonnen"),
    },
    "finished": {
        "fa": ("پایان کار ✅", "سفارش شما با موفقیت انجام شد"),
        "en": ("Work Done ✅", "Your order has been completed successfully"),
        "de": ("Arbeit erledigt ✅", "Ihre Bestellung wurde erfolgreich abgeschlossen"),
    },
    "canceled_by_user": {
        "fa": ("لغو سفارش ❌", "سفارش توسط کاربر لغو شد"),
        "en": ("Order Cancelled ❌", "Order was cancelled by the user"),
        "de": ("Bestellung storniert ❌", "Bestellung wurde vom Benutzer storniert"),
    },
    "canceled_by_manager": {
        "fa": ("لغو سفارش ❌", "سفارش توسط مدیر لغو شد"),
        "en": ("Order Cancelled ❌", "Order was cancelled by the manager"),
        "de": ("Bestellung storniert ❌", "Bestellung wurde vom Manager storniert"),
    },
    "review_submitted": {
        "fa": ("نظر جدید ⭐", "کاربر نظر جدیدی ثبت کرد"),
        "en": ("New Review ⭐", "User submitted a new review"),
        "de": ("Neue Bewertung ⭐", "Benutzer hat eine neue Bewertung abgegeben"),
    },
}

# ✅ متن‌های پیش‌فرض برای رول مدیر
_MANAGER_EVENT_TEXTS: Dict[str, Dict[str, Tuple[str, str]]] = {
    "new_order": {
        "fa": ("سفارش جدید 🛎️", "یک سفارش جدید در انتظار بررسی است"),
        "en": ("New Order 🛎️", "A new order is waiting for review"),
        "de": ("Neue Bestellung 🛎️", "Eine neue Bestellung wartet auf Überprüfung"),
    },
    "visit_time_confirmed": {
        "fa": ("زمان تأیید شد ✅", "کاربر زمان بازدید را تأیید کرد"),
        "en": ("Time Confirmed ✅", "User confirmed the visit time"),
        "de": ("Zeit bestätigt ✅", "Benutzer hat die Besuchszeit bestätigt"),
    },
    "canceled_by_user": {
        "fa": ("لغو توسط کاربر ❌", "کاربر سفارش را لغو کرد"),
        "en": ("Cancelled by User ❌", "User cancelled the order"),
        "de": ("Vom Benutzer storniert ❌", "Benutzer hat die Bestellung storniert"),
    },
    "review_submitted": {
        "fa": ("نظر جدید در انتظار تأیید ⭐", "یک نظر جدید برای تأیید ارسال شد"),
        "en": ("New Review Pending ⭐", "A new review is waiting for approval"),
        "de": ("Neue Bewertung ausstehend ⭐", "Eine neue Bewertung wartet auf Genehmigung"),
    },
}


def get_notification_text(
    event: str,
    lang: str = "fa",
    for_manager: bool = False,
) -> Tuple[str, str]:
    """
    برگردوندن (title, body) برای یک رویداد
    اگه برای مدیر باشه از متن‌های مدیر استفاده میشه
    """
    lang = str(lang or "fa").strip().lower()
    if lang not in ("fa", "en", "de"):
        lang = "fa"

    source = _MANAGER_EVENT_TEXTS if for_manager else _NOTIFICATION_TEXTS
    event_texts = source.get(event) or _NOTIFICATION_TEXTS.get(event)

    if not event_texts:
        return ("اعلان", "پیام جدید دریافت شد") if lang == "fa" else ("Notification", "New message")

    return event_texts.get(lang) or event_texts.get("fa") or ("اعلان", "")


# -------------------- Service Account --------------------

def _load_service_account() -> Optional[dict]:
    for source, is_b64 in [
        (GOOGLE_APPLICATION_CREDENTIALS_JSON_B64, True),
        (GOOGLE_APPLICATION_CREDENTIALS_JSON, False),
    ]:
        if not source:
            continue
        try:
            raw = base64.b64decode(source).decode("utf-8") if is_b64 else source
            data = json.loads(raw)
            if "client_email" in data and "private_key" in data:
                pk = str(data.get("private_key", ""))
                if "\\n" in pk:
                    data["private_key"] = pk.replace("\\n", "\n")
                return data
        except Exception as e:
            logger.error(f"SA load failed ({'b64' if is_b64 else 'json'}): {e}")
    return None


def _get_oauth2_token_for_fcm() -> Optional[str]:
    global _FCM_OAUTH_TOKEN, _FCM_OAUTH_EXP
    now = time.time()
    if _FCM_OAUTH_TOKEN and (_FCM_OAUTH_EXP - 60) > now:
        return _FCM_OAUTH_TOKEN

    sa = _load_service_account()
    if not sa:
        return None

    issued = int(now)
    payload = {
        "iss": sa["client_email"],
        "scope": "https://www.googleapis.com/auth/firebase.messaging",
        "aud": "https://oauth2.googleapis.com/token",
        "iat": issued,
        "exp": issued + 3600,
    }

    try:
        assertion = jwt.encode(payload, sa["private_key"], algorithm="RS256")
        resp = httpx.post(
            "https://oauth2.googleapis.com/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": assertion,
            },
            timeout=10.0,
        )
        if resp.status_code != 200:
            logger.error(f"OAuth token fetch failed: {resp.text}")
            return None
        data = resp.json()
        token = str(data.get("access_token", "")).strip()
        if token:
            _FCM_OAUTH_TOKEN = token
            _FCM_OAUTH_EXP = now + int(data.get("expires_in", 3600))
            return token
    except Exception as e:
        logger.error(f"OAuth exception: {e}")
    return None


# -------------------- FCM send --------------------

def _to_fcm_data(data: dict) -> Dict[str, str]:
    return {str(k): str(v) for k, v in (data or {}).items() if v is not None}


async def _send_fcm_legacy(
    tokens: List[str], title: str, body: str, data: dict
) -> None:
    if not tokens or not FCM_SERVER_KEY:
        return
    merged = {**data, "title": str(title), "body": str(body)}
    payload = {
        "registration_ids": tokens,
        "priority": "high",
        "notification": {"title": title, "body": body},
        "data": _to_fcm_data(merged),
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            "https://fcm.googleapis.com/fcm/send",
            headers={
                "Authorization": f"key={FCM_SERVER_KEY}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
    if resp.status_code != 200:
        logger.error(f"FCM legacy failed HTTP_{resp.status_code}: {resp.text}")


async def _send_fcm_v1_single(
    token: str, title: str, body: str, data: dict
) -> None:
    access = _get_oauth2_token_for_fcm()
    if not access or not FCM_PROJECT_ID:
        logger.error("FCM v1 config missing (token or project_id)")
        return
    merged = {**data, "title": str(title), "body": str(body)}
    msg = {
        "message": {
            "token": str(token).strip(),
            "notification": {"title": title, "body": body},
            "android": {
                "priority": "HIGH",
                "notification": {"sound": "default"},
            },
            "apns": {
                "payload": {"aps": {"sound": "default"}},
            },
            "data": _to_fcm_data(merged),
        }
    }
    url = f"https://fcm.googleapis.com/v1/projects/{FCM_PROJECT_ID}/messages:send"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            url,
            headers={
                "Authorization": f"Bearer {access}",
                "Content-Type": "application/json",
            },
            json=msg,
        )
    if resp.status_code not in (200, 201):
        logger.error(f"FCM v1 failed HTTP_{resp.status_code}: {resp.text}")


async def push_notify_tokens(
    tokens: List[str], title: str, body: str, data: dict
) -> None:
    if not tokens:
        return

    if PUSH_BACKEND == "fcm":
        sa = _load_service_account()
        if FCM_PROJECT_ID and sa:
            for t in tokens:
                await _send_fcm_v1_single(t, title, body, data)
            return
        if FCM_SERVER_KEY:
            await _send_fcm_legacy(tokens, title, body, data)
            return
        logger.error("FCM push: no credentials configured")
        return

    if PUSH_BACKEND == "ntfy":
        base = (NTFY_BASE_URL or "https://ntfy.sh").strip()
        headers = {"Authorization": NTFY_AUTH} if NTFY_AUTH else {}
        async with httpx.AsyncClient(timeout=10.0) as client:
            for topic in tokens:
                await client.post(
                    f"{base}/{topic}",
                    headers={"Title": title, **headers},
                    data=body.encode("utf-8"),
                )
        return

    logger.error(f"Unknown PUSH_BACKEND={PUSH_BACKEND}")


# -------------------- Token lookup --------------------

async def get_manager_tokens(target_phone: Optional[str] = None) -> List[str]:
    q = DeviceTokenTable.__table__.select().where(
        DeviceTokenTable.role == "manager"
    )
    if target_phone:
        q = q.where(DeviceTokenTable.user_phone == normalize_phone(target_phone))

    rows = await database.fetch_all(q)
    seen: set[str] = set()
    out: List[str] = []
    for r in rows:
        t = str(r["token"] or "").strip()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


async def get_user_tokens(phone: str) -> List[str]:
    norm = normalize_phone(phone)
    q = DeviceTokenTable.__table__.select().where(
        (DeviceTokenTable.role.in_(["client", "user"])) &
        (DeviceTokenTable.user_phone == norm)
    )
    rows = await database.fetch_all(q)
    seen: set[str] = set()
    out: List[str] = []
    for r in rows:
        t = str(r["token"] or "").strip()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


# -------------------- High-level notify --------------------

async def notify_user(
    phone: str,
    title: str,
    body: str,
    data: Optional[dict] = None,
    event: Optional[str] = None,
    lang: str = "fa",
) -> None:
    """
    ارسال نوتیف به کاربر
    اگه title/body خالی باشن از event و lang متن خودکار ساخته میشه
    """
    norm = normalize_phone(phone)

    # ✅ اگه title یا body خالی بود و event داشتیم، متن خودکار بساز
    if event and (not title or not body):
        auto_title, auto_body = get_notification_text(event, lang=lang, for_manager=False)
        title = title or auto_title
        body  = body  or auto_body

    await database.execute(
        NotificationTable.__table__.insert().values(
            user_phone=norm,
            title=str(title or ""),
            body=str(body or ""),
            data=data or {},
            read=False,
            created_at=utc_now(),
        )
    )
    tokens = await get_user_tokens(norm)
    if tokens:
        await push_notify_tokens(tokens, title, body, data or {})
    else:
        logger.info(f"notify_user: no tokens for phone={norm}")


async def notify_managers(
    title: str,
    body: str,
    data: Optional[dict] = None,
    target_phone: Optional[str] = None,
    event: Optional[str] = None,
    lang: str = "fa",
) -> None:
    """
    ارسال نوتیف به مدیر(ها)
    اگه title/body خالی باشن از event متن خودکار ساخته میشه
    """
    # ✅ متن خودکار برای مدیر
    if event and (not title or not body):
        auto_title, auto_body = get_notification_text(event, lang=lang, for_manager=True)
        title = title or auto_title
        body  = body  or auto_body

    tokens = await get_manager_tokens(target_phone=target_phone)
    if not tokens and target_phone:
        tokens = await get_manager_tokens(target_phone=None)
    if tokens:
        await push_notify_tokens(tokens, title, body, data or {})
    else:
        logger.info("notify_managers: no manager tokens found")


# -------------------- Push event payload --------------------

def push_event_data(
    event: str,
    order_id: int,
    *,
    status: str = "",
    service_type: str = "",
    user_phone: str = "",
    order_ids: Optional[List[int]] = None,
    scheduled_start: Optional[datetime] = None,
    execution_start: Optional[datetime] = None,
    price: Optional[int] = None,
) -> dict:
    data: dict = {
        "event": str(event or "").strip(),
        "order_id": str(int(order_id)),
    }
    if order_ids:
        data["order_ids"] = ",".join(str(int(x)) for x in order_ids if x is not None)
    if status:
        data["status"] = canon_status(status)
    if service_type:
        data["service_type"] = str(service_type).strip().lower()
    if user_phone:
        data["user_phone"] = normalize_phone(user_phone)
    if scheduled_start is not None:
        data["scheduled_start"] = iso_utc(scheduled_start)
    if execution_start is not None:
        data["execution_start"] = iso_utc(execution_start)
    if price is not None:
        data["price"] = str(int(price))
    return data
from datetime import datetime
from typing import Dict, List, Optional

import httpx
import jwt

from config import (
    FCM_PROJECT_ID,
    FCM_SERVER_KEY,
    GOOGLE_APPLICATION_CREDENTIALS_JSON,
    GOOGLE_APPLICATION_CREDENTIALS_JSON_B64,
    NTFY_AUTH,
    NTFY_BASE_URL,
    PUSH_BACKEND,
)
from database import DeviceTokenTable, NotificationTable, database
from utils import canon_status, iso_utc, normalize_phone, utc_now

logger = logging.getLogger("putz.push")
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[PUSH] %(levelname)s: %(message)s"))
    logger.addHandler(h)
logger.setLevel(logging.INFO)

_FCM_OAUTH_TOKEN = ""
_FCM_OAUTH_EXP = 0.0


# -------------------- Service Account --------------------

def _load_service_account() -> Optional[dict]:
    for source, is_b64 in [
        (GOOGLE_APPLICATION_CREDENTIALS_JSON_B64, True),
        (GOOGLE_APPLICATION_CREDENTIALS_JSON, False),
    ]:
        if not source:
            continue
        try:
            raw = base64.b64decode(source).decode("utf-8") if is_b64 else source
            data = json.loads(raw)
            if "client_email" in data and "private_key" in data:
                pk = str(data.get("private_key", ""))
                if "\\n" in pk:
                    data["private_key"] = pk.replace("\\n", "\n")
                return data
        except Exception as e:
            logger.error(f"SA load failed ({'b64' if is_b64 else 'json'}): {e}")
    return None


def _get_oauth2_token_for_fcm() -> Optional[str]:
    global _FCM_OAUTH_TOKEN, _FCM_OAUTH_EXP
    now = time.time()
    if _FCM_OAUTH_TOKEN and (_FCM_OAUTH_EXP - 60) > now:
        return _FCM_OAUTH_TOKEN

    sa = _load_service_account()
    if not sa:
        return None

    issued = int(now)
    payload = {
        "iss": sa["client_email"],
        "scope": "https://www.googleapis.com/auth/firebase.messaging",
        "aud": "https://oauth2.googleapis.com/token",
        "iat": issued,
        "exp": issued + 3600,
    }

    try:
        assertion = jwt.encode(payload, sa["private_key"], algorithm="RS256")
        resp = httpx.post(
            "https://oauth2.googleapis.com/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": assertion,
            },
            timeout=10.0,
        )
        if resp.status_code != 200:
            logger.error(f"OAuth token fetch failed: {resp.text}")
            return None
        data = resp.json()
        token = str(data.get("access_token", "")).strip()
        if token:
            _FCM_OAUTH_TOKEN = token
            _FCM_OAUTH_EXP = now + int(data.get("expires_in", 3600))
            return token
    except Exception as e:
        logger.error(f"OAuth exception: {e}")
    return None


# -------------------- FCM send --------------------

def _to_fcm_data(data: dict) -> Dict[str, str]:
    return {str(k): str(v) for k, v in (data or {}).items() if v is not None}


async def _send_fcm_legacy(
    tokens: List[str], title: str, body: str, data: dict
) -> None:
    if not tokens or not FCM_SERVER_KEY:
        return
    merged = {**data, "title": str(title), "body": str(body)}
    payload = {
        "registration_ids": tokens,
        "priority": "high",
        "data": _to_fcm_data(merged),
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            "https://fcm.googleapis.com/fcm/send",
            headers={
                "Authorization": f"key={FCM_SERVER_KEY}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
    if resp.status_code != 200:
        logger.error(f"FCM legacy failed HTTP_{resp.status_code}: {resp.text}")


async def _send_fcm_v1_single(
    token: str, title: str, body: str, data: dict
) -> None:
    access = _get_oauth2_token_for_fcm()
    if not access or not FCM_PROJECT_ID:
        logger.error("FCM v1 config missing (token or project_id)")
        return
    merged = {**data, "title": str(title), "body": str(body)}
    msg = {
        "message": {
            "token": str(token).strip(),
            "android": {"priority": "HIGH"},
            "data": _to_fcm_data(merged),
        }
    }
    url = f"https://fcm.googleapis.com/v1/projects/{FCM_PROJECT_ID}/messages:send"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            url,
            headers={
                "Authorization": f"Bearer {access}",
                "Content-Type": "application/json",
            },
            json=msg,
        )
    if resp.status_code not in (200, 201):
        logger.error(f"FCM v1 failed HTTP_{resp.status_code}: {resp.text}")


async def push_notify_tokens(
    tokens: List[str], title: str, body: str, data: dict
) -> None:
    if not tokens:
        return

    if PUSH_BACKEND == "fcm":
        sa = _load_service_account()
        if FCM_PROJECT_ID and sa:
            for t in tokens:
                await _send_fcm_v1_single(t, title, body, data)
            return
        if FCM_SERVER_KEY:
            await _send_fcm_legacy(tokens, title, body, data)
            return
        logger.error("FCM push: no credentials configured")
        return

    if PUSH_BACKEND == "ntfy":
        base = (NTFY_BASE_URL or "https://ntfy.sh").strip()
        headers = {"Authorization": NTFY_AUTH} if NTFY_AUTH else {}
        async with httpx.AsyncClient(timeout=10.0) as client:
            for topic in tokens:
                await client.post(
                    f"{base}/{topic}",
                    headers=headers,
                    data=body.encode("utf-8"),
                )
        return

    logger.error(f"Unknown PUSH_BACKEND={PUSH_BACKEND}")


# -------------------- Token lookup --------------------

async def get_manager_tokens(target_phone: Optional[str] = None) -> List[str]:
    q = DeviceTokenTable.__table__.select().where(
        DeviceTokenTable.role == "manager"
    )
    if target_phone:
        q = q.where(DeviceTokenTable.user_phone == normalize_phone(target_phone))

    rows = await database.fetch_all(q)
    seen: set[str] = set()
    out: List[str] = []
    for r in rows:
        t = str(r["token"] or "").strip()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


async def get_user_tokens(phone: str) -> List[str]:
    norm = normalize_phone(phone)
    q = DeviceTokenTable.__table__.select().where(
        (DeviceTokenTable.role.in_(["client", "user"])) &
        (DeviceTokenTable.user_phone == norm)
    )
    rows = await database.fetch_all(q)
    seen: set[str] = set()
    out: List[str] = []
    for r in rows:
        t = str(r["token"] or "").strip()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


# -------------------- High-level notify --------------------

async def notify_user(
    phone: str, title: str, body: str, data: Optional[dict] = None
) -> None:
    norm = normalize_phone(phone)
    await database.execute(
        NotificationTable.__table__.insert().values(
            user_phone=norm,
            title=str(title or ""),
            body=str(body or ""),
            data=data or {},
            read=False,
            created_at=utc_now(),
        )
    )
    tokens = await get_user_tokens(norm)
    if tokens:
        await push_notify_tokens(tokens, title, body, data or {})
    else:
        logger.info(f"notify_user: no tokens for phone={norm}")


async def notify_managers(
    title: str,
    body: str,
    data: Optional[dict] = None,
    target_phone: Optional[str] = None,
) -> None:
    tokens = await get_manager_tokens(target_phone=target_phone)
    if not tokens and target_phone:
        tokens = await get_manager_tokens(target_phone=None)
    if tokens:
        await push_notify_tokens(tokens, title, body, data or {})
    else:
        logger.info("notify_managers: no manager tokens found")


# -------------------- Push event payload --------------------

def push_event_data(
    event: str,
    order_id: int,
    *,
    status: str = "",
    service_type: str = "",
    user_phone: str = "",
    order_ids: Optional[List[int]] = None,
    scheduled_start: Optional[datetime] = None,
    execution_start: Optional[datetime] = None,
    price: Optional[int] = None,
) -> dict:
    data: dict = {
        "event": str(event or "").strip(),
        "order_id": str(int(order_id)),
    }
    if order_ids:
        data["order_ids"] = ",".join(str(int(x)) for x in order_ids if x is not None)
    if status:
        data["status"] = canon_status(status)
    if service_type:
        data["service_type"] = str(service_type).strip().lower()
    if user_phone:
        data["user_phone"] = normalize_phone(user_phone)
    if scheduled_start is not None:
        data["scheduled_start"] = iso_utc(scheduled_start)
    if execution_start is not None:
        data["execution_start"] = iso_utc(execution_start)
    if price is not None:
        data["price"] = str(int(price))
    return data
