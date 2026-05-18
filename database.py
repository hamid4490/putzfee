# FILE: database.py
# -*- coding: utf-8 -*-

from datetime import datetime, timezone

import sqlalchemy
from databases import Database
from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey,
    Index, Integer, String, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base

from config import DATABASE_URL, ENABLE_SCHEMA_CREATE, STATUS_NEW

# -------------------- Connection --------------------
database = Database(DATABASE_URL)
Base = declarative_base()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# -------------------- ORM Models --------------------

class UserTable(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    address = Column(String, default="", nullable=False)
    name = Column(String, default="", nullable=False)
    car_list = Column(JSONB, default=list, nullable=False)
    photo_path = Column(String, default="", nullable=False)
    photo_mime = Column(String, default="", nullable=False)
    photo_updated_at = Column(DateTime(timezone=True), nullable=True)


class RequestTable(Base):
    __tablename__ = "requests"
    id = Column(Integer, primary_key=True, index=True)
    user_phone = Column(String, index=True, nullable=False)
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    car_list = Column(JSONB, default=list, nullable=False)
    address = Column(String, default="", nullable=False)
    home_number = Column(String, default="", nullable=False)
    service_type = Column(String, index=True, nullable=False)
    service_types = Column(JSONB, default=list, nullable=False)
    preferred_slots = Column(JSONB, default=list, nullable=False)
    price = Column(Integer, default=0, nullable=False)
    request_datetime = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    finish_datetime = Column(DateTime(timezone=True), nullable=True)
    status = Column(String, default=STATUS_NEW, index=True, nullable=False)
    driver_name = Column(String, default="", nullable=False)
    driver_phone = Column(String, default="", nullable=False)
    payment_type = Column(String, default="", nullable=False)
    service_place = Column(String, default="client", nullable=False)
    scheduled_start = Column(DateTime(timezone=True), nullable=True)
    execution_start = Column(DateTime(timezone=True), nullable=True)


class ReviewTable(Base):
    __tablename__ = "reviews"
    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(Integer, ForeignKey("requests.id"), unique=True, index=True, nullable=False)
    user_phone = Column(String, index=True, nullable=False)
    rating = Column(Integer, nullable=False)
    comment = Column(String, default="", nullable=False)
    status = Column(String, default="PENDING", index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)
    decided_at = Column(DateTime(timezone=True), nullable=True)
    decided_by = Column(String, nullable=True)


class RefreshTokenTable(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    token_hash = Column(String, unique=True, index=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), index=True, nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    __table_args__ = (Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),)


class LoginAttemptTable(Base):
    __tablename__ = "login_attempts"
    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String, index=True, nullable=False)
    ip = Column(String, index=True, nullable=False)
    attempt_count = Column(Integer, default=0, nullable=False)
    window_start = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_attempt_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    __table_args__ = (Index("ix_login_attempt_phone_ip", "phone", "ip"),)


class ScheduleSlotTable(Base):
    __tablename__ = "schedule_slots"
    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(Integer, ForeignKey("requests.id"), index=True, nullable=False)
    provider_phone = Column(String, index=True, nullable=False)
    slot_start = Column(DateTime(timezone=True), index=True, nullable=False)
    status = Column(String, default="PROPOSED", nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    __table_args__ = (
        Index("ix_schedule_slots_req_status", "request_id", "status"),
        Index("ix_schedule_slots_provider_slot", "provider_phone", "slot_start"),
    )


class AppointmentTable(Base):
    __tablename__ = "appointments"
    id = Column(Integer, primary_key=True, index=True)
    provider_phone = Column(String, index=True, nullable=False)
    request_id = Column(Integer, ForeignKey("requests.id"), index=True, nullable=False)
    start_time = Column(DateTime(timezone=True), index=True, nullable=False)
    end_time = Column(DateTime(timezone=True), index=True, nullable=False)
    status = Column(String, default="BOOKED", nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    __table_args__ = (
        UniqueConstraint("provider_phone", "start_time", "end_time", name="uq_provider_slot"),
        Index("ix_provider_time", "provider_phone", "start_time", "end_time"),
    )


class NotificationTable(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True, index=True)
    user_phone = Column(String, index=True, nullable=False)
    title = Column(String, default="", nullable=False)
    body = Column(String, default="", nullable=False)
    data = Column(JSONB, default=dict, nullable=False)
    read = Column(Boolean, default=False, index=True, nullable=False)
    read_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)
    __table_args__ = (Index("ix_notifs_user_read_created", "user_phone", "read", "created_at"),)


class DeviceTokenTable(Base):
    __tablename__ = "device_tokens"
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True, nullable=False)
    role = Column(String, index=True, nullable=False)
    platform = Column(String, default="android", index=True, nullable=False)
    user_phone = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    __table_args__ = (Index("ix_tokens_role_platform", "role", "platform"),)


class PromotionTable(Base):
    __tablename__ = "promotions"
    id = Column(Integer, primary_key=True, index=True)
    active = Column(Boolean, default=True, index=True, nullable=False)
    sort_order = Column(Integer, default=0, index=True, nullable=False)
    title_i18n = Column(JSONB, default=dict, nullable=False)
    subtitle_i18n = Column(JSONB, default=dict, nullable=False)
    service_types = Column(JSONB, default=list, nullable=False)
    discount_amount = Column(Integer, default=0, nullable=False)
    image_path = Column(String, default="", nullable=False)
    image_mime = Column(String, default="", nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)


class ServicePriceTable(Base):
    __tablename__ = "service_prices"
    id = Column(Integer, primary_key=True, index=True)
    service_type = Column(String, unique=True, index=True, nullable=False)
    base_price = Column(Integer, default=0, nullable=False)
    active = Column(Boolean, default=True, index=True, nullable=False)
    sort_order = Column(Integer, default=0, index=True, nullable=False)
    name_i18n = Column(JSONB, default=dict, nullable=False)
    icon_path = Column(String, default="", nullable=False)
    icon_mime = Column(String, default="", nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)


# -------------------- Schema creation --------------------
def create_all_tables() -> None:
    if not ENABLE_SCHEMA_CREATE:
        return
    sync_url = str(DATABASE_URL).replace("+asyncpg", "")
    engine = sqlalchemy.create_engine(sync_url)
    Base.metadata.create_all(engine)
    engine.dispose()
