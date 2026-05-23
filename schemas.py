# FILE: schemas.py
# -*- coding: utf-8 -*-

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, field_validator


# -------------------- Shared --------------------

class Location(BaseModel):
    latitude: float
    longitude: float


class CarInfo(BaseModel):
    brand: str
    model: str
    plate: str


class CarOrderItem(BaseModel):
    brand: str
    model: str
    plate: str
    wash_outside: bool = False
    wash_inside: bool = False
    polish: bool = False


# -------------------- Auth --------------------

class UserRegisterRequest(BaseModel):
    phone: str
    password: str
    address: Optional[str] = None

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v: str) -> str:
        if len(str(v or "").strip()) < 4:
            raise ValueError("password must be at least 4 characters")
        return v


class UserLoginRequest(BaseModel):
    phone: str
    password: str


class AdminLoginRequest(BaseModel):
    phone: str
    password: str


class RefreshAccessRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str
    device_token: Optional[str] = None


# -------------------- User --------------------

class UserProfileUpdate(BaseModel):
    phone: str
    name: str = ""
    address: str = ""


class CarListUpdateRequest(BaseModel):
    user_phone: str
    car_list: List[CarInfo]


# -------------------- Orders --------------------

VALID_SERVICE_PLACES = {"client", "provider"}


class OrderRequest(BaseModel):
    user_phone: str
    location: Location
    car_list: List[CarOrderItem] = []
    address: str
    home_number: Optional[str] = ""
    service_type: str
    price: int = 0
    request_datetime: Optional[str] = None
    payment_type: str = "cash"
    service_place: str = "client"
    service_types: Optional[List[str]] = None
    preferred_slots: Optional[List[str]] = None   # ✅ حداکثر 2 تا - کنترل در router

    @field_validator("service_place")
    @classmethod
    def validate_service_place(cls, v: str) -> str:
        val = str(v or "client").strip().lower()
        if val not in VALID_SERVICE_PLACES:
            raise ValueError(f"service_place must be one of {VALID_SERVICE_PLACES}")
        return val

    @field_validator("payment_type")
    @classmethod
    def validate_payment_type(cls, v: str) -> str:
        valid = {"cash", "card", "online"}
        val = str(v or "cash").strip().lower()
        if val not in valid:
            raise ValueError(f"payment_type must be one of {valid}")
        return val


class CancelRequest(BaseModel):
    user_phone: str
    service_type: str


# -------------------- Scheduling --------------------

class ProposedSlotsRequest(BaseModel):
    slots: List[str]

    @field_validator("slots")
    @classmethod
    def validate_slots(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("at least one slot required")
        if len(v) > 3:
            raise ValueError("maximum 3 slots allowed")
        return v


class ConfirmSlotRequest(BaseModel):
    slot: str


class PriceBody(BaseModel):
    price: int
    agree: bool
    exec_time: Optional[str] = None

    @field_validator("price")
    @classmethod
    def validate_price(cls, v: int) -> int:
        if int(v or 0) < 0:
            raise ValueError("price must be >= 0")
        return v


# -------------------- Push --------------------

class PushRegister(BaseModel):
    role: str
    token: str
    platform: str = "android"
    user_phone: Optional[str] = None

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        valid = {"user", "client", "manager", "admin"}
        val = str(v or "").strip().lower()
        if val not in valid:
            raise ValueError(f"role must be one of {valid}")
        return val

    @field_validator("platform")
    @classmethod
    def validate_platform(cls, v: str) -> str:
        valid = {"android", "ios"}
        val = str(v or "android").strip().lower()
        if val not in valid:
            raise ValueError(f"platform must be one of {valid}")
        return val


class PushUnregister(BaseModel):
    token: str


# -------------------- Reviews --------------------

class ReviewSubmitBody(BaseModel):
    rating: int
    comment: Optional[str] = ""

    @field_validator("rating")
    @classmethod
    def validate_rating(cls, v: int) -> int:
        if not (1 <= int(v or 0) <= 5):
            raise ValueError("rating must be between 1 and 5")
        return v


class ReviewDecisionBody(BaseModel):
    approve: bool


# -------------------- Notifications --------------------

class NotificationReadBody(BaseModel):
    notification_id: Optional[int] = None
    order_id: Optional[int] = None


# -------------------- Admin: services --------------------

class ServicePriceUpsertBody(BaseModel):
    service_type: str
    base_price: int

    @field_validator("base_price")
    @classmethod
    def validate_base_price(cls, v: int) -> int:
        if int(v or 0) < 0:
            raise ValueError("base_price must be >= 0")
        return v


# -------------------- AI Assistant --------------------

class AIChatMessage(BaseModel):
    role: str    # "user" | "assistant"
    content: str


class AIChatRequest(BaseModel):
    message: str
    lang: str = "fa"                                  # fa | en | de
    history: Optional[List[AIChatMessage]] = []       # تاریخچه مکالمه
    context: Optional[Dict[str, Any]] = {}            # اطلاعات context مثل سرویس‌ها

    @field_validator("lang")
    @classmethod
    def validate_lang(cls, v: str) -> str:
        valid = {"fa", "en", "de"}
        val = str(v or "fa").strip().lower()
        return val if val in valid else "fa"

    @field_validator("message")
    @classmethod
    def validate_message(cls, v: str) -> str:
        msg = str(v or "").strip()
        if not msg:
            raise ValueError("message cannot be empty")
        if len(msg) > 2000:
            raise ValueError("message too long (max 2000 chars)")
        return msg
