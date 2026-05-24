"""Centralised application configuration.

All runtime configuration is loaded from environment variables via
pydantic-settings. Settings are exposed through :func:`get_settings`,
which is `lru_cache`d so the values are parsed once per process.
"""

from __future__ import annotations

from functools import lru_cache
from typing import List
from zoneinfo import ZoneInfo

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Strongly typed application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------
    DATABASE_URL: str

    # ------------------------------------------------------------------
    # Security / Auth
    # ------------------------------------------------------------------
    JWT_SECRET: str
    PASSWORD_PEPPER: str = ""
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    BCRYPT_ROUNDS: int = 12
    JWT_ALGORITHM: str = "HS256"

    # Bootstrap-only: phones that auto-receive admin rights on registration.
    ADMIN_PHONES: str = ""

    LOGIN_WINDOW_SECONDS: int = 300
    LOGIN_MAX_ATTEMPTS: int = 5
    LOGIN_LOCK_SECONDS: int = 900

    ALLOW_ORIGINS: str = "*"

    # ------------------------------------------------------------------
    # Timezone & scheduling
    # ------------------------------------------------------------------
    SERVER_TIMEZONE: str = "Europe/Berlin"
    WORK_START_HOUR: int = 8
    WORK_END_HOUR: int = 20
    SLOT_DURATION_HOURS: int = 1
    MAX_SLOTS_PER_REQUEST: int = 2

    # ------------------------------------------------------------------
    # Push notifications (FCM v1)
    # ------------------------------------------------------------------
    FCM_PROJECT_ID: str = ""
    GOOGLE_APPLICATION_CREDENTIALS_JSON_B64: str = ""

    # ------------------------------------------------------------------
    # Media
    # ------------------------------------------------------------------
    MEDIA_DIR: str = "./media"
    MEDIA_URL_PREFIX: str = "/media"
    PUBLIC_BASE_URL: str = "http://localhost:8000"
    MAX_IMAGE_BYTES: int = 5 * 1024 * 1024
    MEDIA_TARGET_WIDTH: int = 1280
    MEDIA_TARGET_HEIGHT: int = 1280
    MEDIA_SAVE_FORMAT: str = "webp"
    MEDIA_JPEG_QUALITY: int = 85
    MEDIA_WEBP_QUALITY: int = 80

    # ------------------------------------------------------------------
    # AI
    # ------------------------------------------------------------------
    AI_PROVIDER: str = "gemini"
    AI_API_KEY: str = ""
    AI_MODEL: str = "gemini-1.5-flash"
    AI_MAX_TOKENS: int = 512
    AI_TEMPERATURE: float = 0.4
    AI_RATE_PER_MINUTE: int = 8
    AI_RATE_PER_DAY: int = 50

    # ------------------------------------------------------------------
    # Operational
    # ------------------------------------------------------------------
    ENABLE_SCHEMA_CREATE: bool = False
    APP_ENV: str = "development"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @field_validator("BCRYPT_ROUNDS")
    @classmethod
    def _validate_bcrypt_rounds(cls, v: int) -> int:
        if not 4 <= v <= 15:
            raise ValueError("BCRYPT_ROUNDS must be between 4 and 15")
        return v

    @field_validator("WORK_START_HOUR", "WORK_END_HOUR")
    @classmethod
    def _validate_hour(cls, v: int) -> int:
        if not 0 <= v <= 23:
            raise ValueError("Hour must be between 0 and 23")
        return v

    @field_validator("MAX_SLOTS_PER_REQUEST")
    @classmethod
    def _validate_max_slots(cls, v: int) -> int:
        if not 1 <= v <= 5:
            raise ValueError("MAX_SLOTS_PER_REQUEST must be between 1 and 5")
        return v

    @property
    def is_production(self) -> bool:
        return self.APP_ENV.lower() == "production"

    @property
    def cors_origins(self) -> List[str]:
        raw = (self.ALLOW_ORIGINS or "").strip()
        if not raw or raw == "*":
            return ["*"]
        return [o.strip() for o in raw.split(",") if o.strip()]

    @property
    def admin_phone_set(self) -> set[str]:
        raw = (self.ADMIN_PHONES or "").strip()
        if not raw:
            return set()
        return {p.strip() for p in raw.split(",") if p.strip()}

    @property
    def tz(self) -> ZoneInfo:
        return ZoneInfo(self.SERVER_TIMEZONE)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()  # type: ignore[call-arg]
