# FILE: schemas.py
# -*- coding: utf-8 -*-

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


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

class OrderRequest(BaseModel):
    user_phone: str
    location: Location
    car_list: List[CarOrderItem]
    address: str
    home_number: Optional[str] = ""
    service_type: str
    price: int = 0
    request_datetime: Optional[str] = None
    payment_type: str = "cash"
    service_place: str = "client"
    service_types: Optional[List[str]] = None
    preferred_slots: Optional[List[str]] = None


class CancelRequest(BaseModel):
    user_phone: str
    service_type: str


# -------------------- Scheduling --------------------

class ProposedSlotsRequest(BaseModel):
    slots: List[str]


class ConfirmSlotRequest(BaseModel):
    slot: str


class PriceBody(BaseModel):
    price: int
    agree: bool
    exec_time: Optional[str] = None


# -------------------- Push --------------------

class PushRegister(BaseModel):
    role: str
    token: str
    platform: str = "android"
    user_phone: Optional[str] = None


class PushUnregister(BaseModel):
    token: str


# -------------------- Reviews --------------------

class ReviewSubmitBody(BaseModel):
    rating: int
    comment: Optional[str] = ""


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
