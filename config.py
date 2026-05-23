# FILE: config.py
# -*- coding: utf-8 -*-

import os
from dotenv import load_dotenv

load_dotenv()

# -------------------- Database --------------------
DATABASE_URL: str = os.getenv("DATABASE_URL", "").strip()
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is empty")

ENABLE_SCHEMA_CREATE: bool = os.getenv("ENABLE_SCHEMA_CREATE", "true").strip().lower() in (
    "1", "true", "yes", "on"
)

# -------------------- JWT & Auth --------------------
JWT_SECRET: str = os.getenv("JWT_SECRET", "change-me-secret").strip()
PASSWORD_PEPPER: str = os.getenv("PASSWORD_PEPPER", "change-me-pepper").strip()
ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
BCRYPT_ROUNDS: int = int(os.getenv("BCRYPT_ROUNDS", "12"))

# -------------------- Rate limiting --------------------
LOGIN_WINDOW_SECONDS: int = int(os.getenv("LOGIN_WINDOW_SECONDS", "600"))
LOGIN_MAX_ATTEMPTS: int = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_LOCK_SECONDS: int = int(os.getenv("LOGIN_LOCK_SECONDS", "1800"))

# -------------------- Admin --------------------
ADMIN_KEY: str = os.getenv("ADMIN_KEY", "CHANGE_ME_ADMIN").strip()
ADMIN_PHONES_ENV: str = os.getenv("ADMIN_PHONES", "").strip()

# -------------------- CORS --------------------
ALLOW_ORIGINS_ENV: str = os.getenv("ALLOW_ORIGINS", "*").strip()

# -------------------- Push notifications --------------------
FCM_SERVER_KEY: str = os.getenv("FCM_SERVER_KEY", "").strip()
FCM_PROJECT_ID: str = os.getenv("FCM_PROJECT_ID", "").strip()
GOOGLE_APPLICATION_CREDENTIALS_JSON: str = os.getenv(
    "GOOGLE_APPLICATION_CREDENTIALS_JSON", ""
).strip()
GOOGLE_APPLICATION_CREDENTIALS_JSON_B64: str = os.getenv(
    "GOOGLE_APPLICATION_CREDENTIALS_JSON_B64", ""
).strip()
PUSH_BACKEND: str = os.getenv("PUSH_BACKEND", "fcm").strip().lower()
NTFY_BASE_URL: str = os.getenv("NTFY_BASE_URL", "https://ntfy.sh").strip()
NTFY_AUTH: str = os.getenv("NTFY_AUTH", "").strip()

# -------------------- Media --------------------
MEDIA_DIR: str = os.getenv("MEDIA_DIR", "media").strip() or "media"
MEDIA_URL_PREFIX: str = os.getenv("MEDIA_URL_PREFIX", "/media").strip() or "/media"
PUBLIC_BASE_URL: str = os.getenv("PUBLIC_BASE_URL", "").strip()
MAX_IMAGE_BYTES: int = int(os.getenv("MAX_IMAGE_BYTES", "5000000"))
MEDIA_TARGET_WIDTH: int = int(os.getenv("MEDIA_TARGET_WIDTH", "1200"))
MEDIA_TARGET_HEIGHT: int = int(os.getenv("MEDIA_TARGET_HEIGHT", "1200"))
MEDIA_SAVE_FORMAT: str = os.getenv("MEDIA_SAVE_FORMAT", "JPEG").strip().upper()
MEDIA_JPEG_QUALITY: int = int(os.getenv("MEDIA_JPEG_QUALITY", "82"))
MEDIA_WEBP_QUALITY: int = int(os.getenv("MEDIA_WEBP_QUALITY", "82"))

# -------------------- Order status constants --------------------
STATUS_NEW              = "NEW"
STATUS_WAITING          = "WAITING"
STATUS_ASSIGNED         = "ASSIGNED"
STATUS_PRICE_CONFIRMED  = "PRICE_CONFIRMED"   # ✅ جدید: قیمت و زمان اجرا تعیین شد
STATUS_IN_PROGRESS      = "IN_PROGRESS"
STATUS_FINISH           = "FINISH"
STATUS_CANCELED         = "CANCELED"

ACTIVE_ORDER_STATUSES = [
    STATUS_NEW,
    STATUS_WAITING,
    STATUS_ASSIGNED,
    STATUS_PRICE_CONFIRMED,   # ✅ اضافه شد
    STATUS_IN_PROGRESS,
]
FINAL_ORDER_STATUSES = [STATUS_FINISH, STATUS_CANCELED]

ROLE_USER  = "user"
ROLE_ADMIN = "admin"

# -------------------- Working hours --------------------
# ساعات کاری برای نمایش slot های آزاد به کاربر
WORK_START_HOUR: int = int(os.getenv("WORK_START_HOUR", "8"))   # 8 صبح
WORK_END_HOUR: int   = int(os.getenv("WORK_END_HOUR",   "20"))  # 8 شب
SLOT_DURATION_HOURS: int = int(os.getenv("SLOT_DURATION_HOURS", "2"))  # هر slot 2 ساعته

# -------------------- AI Assistant --------------------
AI_PROVIDER: str  = os.getenv("AI_PROVIDER", "openai").strip().lower()  # openai | gemini
AI_API_KEY: str   = os.getenv("AI_API_KEY", "").strip()
AI_MODEL: str     = os.getenv("AI_MODEL", "gpt-4o-mini").strip()
AI_MAX_TOKENS: int = int(os.getenv("AI_MAX_TOKENS", "1000"))
AI_TEMPERATURE: float = float(os.getenv("AI_TEMPERATURE", "0.7"))

# System prompt پایه برای AI مشاور
AI_SYSTEM_PROMPT_FA = """تو یک دستیار هوشمند برای اپلیکیشن خدماتی PUTZ هستی.
وظیفه‌ات راهنمایی کاربران در انتخاب سرویس مناسب، توضیح مراحل سفارش و پاسخ به سوالات است.
همیشه مودب، مختصر و مفید باش. پاسخ‌ها را به زبان کاربر بده."""

AI_SYSTEM_PROMPT_EN = """You are an intelligent assistant for PUTZ service application.
Your job is to help users choose the right service, explain order steps and answer questions.
Always be polite, concise and helpful."""

AI_SYSTEM_PROMPT_DE = """Du bist ein intelligenter Assistent für die PUTZ-Service-Anwendung.
Deine Aufgabe ist es, Benutzern bei der Auswahl des richtigen Services zu helfen.
Sei immer höflich, prägnant und hilfreich."""
