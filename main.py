# -*- coding: utf-8 -*-
# FastAPI server (clean and focused on: orders + hourly scheduling)
import os
import hashlib
import secrets
from datetime import datetime, timedelta, timezone, time as dtime
from typing import Optional, List, Dict

import bcrypt
import jwt
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Index, select, func, and_, text, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.declarative import declarative_base
import sqlalchemy
from databases import Database
from dotenv import load_dotenv

# -------------------- Config --------------------
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-secret")
PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "change-me-pepper")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))
ALLOW_ORIGINS_ENV = os.getenv("ALLOW_ORIGINS", "*")

LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "300"))
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_LOCK_SECONDS = int(os.getenv("LOGIN_LOCK_SECONDS", "900"))

database = Database(DATABASE_URL)
Base = declarative_base()

# -------------------- ORM models --------------------
class UserTable(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String, unique=True, index=True)
    password_hash = Column(String)
    address = Column(String)
    name = Column(String, default="")
    car_list = Column(JSONB, default=list)

class DriverTable(Base):
    __tablename__ = "drivers"
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    photo_url = Column(String)
    id_card_number = Column(String)
    phone = Column(String, unique=True, index=True)
    phone_verified = Column(Boolean, default=False)
    is_online = Column(Boolean, default=False)
    status = Column(String, default="فعال")

class RequestTable(Base):
    __tablename__ = "requests"
    id = Column(Integer, primary_key=True, index=True)
    user_phone = Column(String, index=True)
    latitude = Column(Float)
    longitude = Column(Float)
    car_list = Column(JSONB)
    address = Column(String)
    home_number = Column(String, default="")
    service_type = Column(String, index=True)
    price = Column(Integer)
    request_datetime = Column(String)
    status = Column(String)  # PENDING/ACTIVE/CANCELED/DONE
    driver_name = Column(String)
    driver_phone = Column(String)  # سفارش‌گیرنده
    finish_datetime = Column(String)
    payment_type = Column(String)
    # زمان انتخاب‌شده نهایی (اختیاری)
    scheduled_start = Column(DateTime(timezone=True), nullable=True)

class RefreshTokenTable(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    token_hash = Column(String, unique=True, index=True)
    expires_at = Column(DateTime(timezone=True), index=True)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),)

class LoginAttemptTable(Base):
    __tablename__ = "login_attempts"
    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String, index=True)
    ip = Column(String, index=True)
    attempt_count = Column(Integer, default=0)
    window_start = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_attempt_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (Index("ix_login_attempt_phone_ip", "phone", "ip"),)

# اسلات‌های پیشنهادی (سه زمان یک‌ساعته)
class ScheduleSlotTable(Base):
    __tablename__ = "schedule_slots"
    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)
    provider_phone = Column(String, index=True)
    slot_start = Column(DateTime(timezone=True), index=True)  # مدت: 1 ساعت ثابت
    status = Column(String, default="PROPOSED")  # PROPOSED/ACCEPTED/REJECTED
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (Index("ix_schedule_slots_req_status", "request_id", "status"),)

# بازه‌های رزرو نهایی (ساعت‌های اشغال‌شده)
class AppointmentTable(Base):
    __tablename__ = "appointments"
    id = Column(Integer, primary_key=True, index=True)
    provider_phone = Column(String, index=True)
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)
    start_time = Column(DateTime(timezone=True), index=True)
    end_time = Column(DateTime(timezone=True), index=True)
    status = Column(String, default="BOOKED")  # BOOKED/CANCELLED
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (
        UniqueConstraint("provider_phone", "start_time", "end_time", name="uq_provider_slot"),
        Index("ix_provider_time", "provider_phone", "start_time", "end_time"),
    )

# -------------------- Pydantic models --------------------
class CarInfo(BaseModel):
    brand: str
    model: str
    plate: str

class Location(BaseModel):
    latitude: float
    longitude: float

class OrderRequest(BaseModel):
    user_phone: str
    location: Location
    car_list: List[CarInfo]
    address: str
    home_number: Optional[str] = ""
    service_type: str
    price: int
    request_datetime: str
    payment_type: str

class CarListUpdateRequest(BaseModel):
    user_phone: str
    car_list: List[CarInfo]

class CancelRequest(BaseModel):
    user_phone: str
    service_type: str

class UserRegisterRequest(BaseModel):
    phone: str
    password: str
    address: Optional[str] = None

class UserLoginRequest(BaseModel):
    phone: str
    password: str

class UserProfileUpdate(BaseModel):
    phone: str
    name: str = ""
    address: str = ""

# زمان‌بندی
class ProposedSlotsRequest(BaseModel):
    provider_phone: str
    slots: List[str]  # ISO strings, هر کدام شروعِ بازه یک‌ساعته

class ConfirmSlotRequest(BaseModel):
    slot: str  # ISO start

# -------------------- Security helpers --------------------
def bcrypt_hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    mixed = (password + PASSWORD_PEPPER).encode("utf-8")
    return bcrypt.hashpw(mixed, salt).decode("utf-8")

def verify_password_secure(password: str, stored_hash: str) -> bool:
    try:
        if stored_hash.startswith("$2"):
            mixed = (password + PASSWORD_PEPPER).encode("utf-8")
            return bcrypt.checkpw(mixed, stored_hash.encode("utf-8"))
        old = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return old == stored_hash
    except Exception:
        return False

def create_access_token(phone: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": phone, "type": "access", "exp": exp}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def create_refresh_token() -> str:
    return secrets.token_urlsafe(48)

def hash_refresh_token(token: str) -> str:
    return hashlib.sha256((token + PASSWORD_PEPPER).encode("utf-8")).hexdigest()

def unified_response(status: str, code: str, message: str, data: Optional[dict] = None):
    return {"status": status, "code": code, "message": message, "data": data or {}}

# -------------------- Utils --------------------
def get_client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host or "unknown"

def parse_iso(ts: str) -> datetime:
    # "2025-09-09T10:00:00Z" → tz-aware UTC
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        raise HTTPException(status_code=400, detail=f"invalid datetime: {ts}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

async def provider_is_free(provider_phone: str, start: datetime, end: datetime) -> bool:
    # فقط رزروهای نهایی BOOKED به عنوان اشغال در نظر گرفته می‌شوند (ساده و مطابق نیاز)
    q = AppointmentTable.__table__.select().where(
        (AppointmentTable.provider_phone == provider_phone) &
        (AppointmentTable.status == "BOOKED") &
        (AppointmentTable.start_time < end) &
        (AppointmentTable.end_time > start)
    )
    rows = await database.fetch_all(q)
    return len(rows) == 0

# (اختیاری) Placeholder برای نوتیفیکیشن
async def notify_user(phone: str, title: str, body: str):
    # در اینجا سرویس نوتیفیکیشن (FCM/...) خود را صدا بزنید.
    pass

# -------------------- App & CORS --------------------
app = FastAPI()
allow_origins = ["*"] if ALLOW_ORIGINS_ENV.strip() == "*" else [o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------- Startup/Shutdown --------------------
@app.on_event("startup")
async def startup():
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))
    Base.metadata.create_all(engine)
    # اطمینان از ستون جدید (اگر قبلاً جدول ساخته شده باشد)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS scheduled_start TIMESTAMPTZ NULL;"))
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# -------------------- Health --------------------
@app.get("/")
def read_root():
    return {"message": "Putzfee FastAPI Server is running!"}

# -------------------- Auth/User --------------------
@app.get("/users/exists")
async def user_exists(phone: str):
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == phone)
    count = await database.fetch_val(q)
    exists = bool(count and int(count) > 0)
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "user exists check", {"exists": exists})

@app.post("/register_user")
async def register_user(user: UserRegisterRequest):
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == user.phone)
    count = await database.fetch_val(q)
    if count and int(count) > 0:
        raise HTTPException(status_code=400, detail="User already exists")
    password_hash = bcrypt_hash_password(user.password)
    ins = UserTable.__table__.insert().values(
        phone=user.phone, password_hash=password_hash, address=(user.address or "").strip(), name="", car_list=[]
    )
    await database.execute(ins)
    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": user.phone})

@app.post("/login")
async def login_user(user: UserLoginRequest, request: Request):
    client_ip = get_client_ip(request)
    now = datetime.now(timezone.utc)

    sel_attempt = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == user.phone, LoginAttemptTable.ip == client_ip))
    attempt_row = await database.fetch_one(sel_attempt)
    if attempt_row and attempt_row["locked_until"] and attempt_row["locked_until"] > now:
        retry_after = int((attempt_row["locked_until"] - now).total_seconds())
        raise HTTPException(status_code=429, detail={"code": "RATE_LIMITED", "lock_remaining": retry_after, "window_seconds": LOGIN_WINDOW_SECONDS})

    sel_user = UserTable.__table__.select().where(UserTable.phone == user.phone)
    db_user = await database.fetch_one(sel_user)
    if not db_user:
        await _register_login_failure(user.phone, client_ip)
        updated = await database.fetch_one(LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == user.phone, LoginAttemptTable.ip == client_ip)))
        remaining = max(0, LOGIN_MAX_ATTEMPTS - int(updated["attempt_count"] or 0)) if updated else 0
        lock_remaining = int((updated["locked_until"] - now).total_seconds()) if updated and updated["locked_until"] and updated["locked_until"] > now else 0
        raise HTTPException(status_code=404, detail={"code": "USER_NOT_FOUND", "remaining_attempts": remaining, "lock_remaining": lock_remaining, "window_seconds": LOGIN_WINDOW_SECONDS})

    if not verify_password_secure(user.password, db_user["password_hash"]):
        await _register_login_failure(user.phone, client_ip)
        updated = await database.fetch_one(LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == user.phone, LoginAttemptTable.ip == client_ip)))
        remaining = max(0, LOGIN_MAX_ATTEMPTS - int(updated["attempt_count"] or 0)) if updated else 0
        lock_remaining = int((updated["locked_until"] - now).total_seconds()) if updated and updated["locked_until"] and updated["locked_until"] > now else 0
        raise HTTPException(status_code=401, detail={"code": "WRONG_PASSWORD", "remaining_attempts": remaining, "lock_remaining": lock_remaining, "window_seconds": LOGIN_WINDOW_SECONDS})

    await _register_login_success(user.phone, client_ip)

    if not db_user["password_hash"].startswith("$2"):
        new_hash = bcrypt_hash_password(user.password)
        upd = UserTable.__table__.update().where(UserTable.id == db_user["id"]).values(password_hash=new_hash)
        await database.execute(upd)

    access_token = create_access_token(db_user["phone"])
    refresh_token = create_refresh_token()
    refresh_hash = hash_refresh_token(refresh_token)
    refresh_exp = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    ins_rt = RefreshTokenTable.__table__.insert().values(user_id=db_user["id"], token_hash=refresh_hash, expires_at=refresh_exp, revoked=False)
    await database.execute(ins_rt)

    mapping = getattr(db_user, "_mapping", {})
    name_val = mapping["name"] if "name" in mapping else ""
    address_val = mapping["address"] if "address" in mapping else ""

    return {
        "status": "ok", "message": "Login successful", "token": access_token, "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {"phone": db_user["phone"], "address": address_val or "", "name": name_val or ""}
    }

async def _register_login_failure(phone: str, ip: str):
    now = datetime.now(timezone.utc)
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))
    row = await database.fetch_one(sel)
    if row is None:
        ins = LoginAttemptTable.__table__.insert().values(phone=phone, ip=ip, attempt_count=1, window_start=now, locked_until=None, last_attempt_at=now)
        await database.execute(ins); return
    window_start = row["window_start"] or now
    within = (now - window_start).total_seconds() <= LOGIN_WINDOW_SECONDS
    new_count = (row["attempt_count"] + 1) if within else 1
    new_window_start = window_start if within else now
    locked_until = row["locked_until"]
    if new_count >= LOGIN_MAX_ATTEMPTS:
        locked_until = now + timedelta(seconds=LOGIN_LOCK_SECONDS)
    upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(
        attempt_count=new_count, window_start=new_window_start, locked_until=locked_until, last_attempt_at=now
    )
    await database.execute(upd)

async def _register_login_success(phone: str, ip: str):
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))
    row = await database.fetch_one(sel)
    if row:
        upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(
            attempt_count=0, window_start=datetime.now(timezone.utc), locked_until=None
        )
        await database.execute(upd)

@app.post("/auth/refresh")
async def refresh_access_token(req: Dict):
    refresh_token = req.get("refresh_token", "")
    if not refresh_token:
        raise HTTPException(status_code=400, detail="refresh_token required")
    token_hash = hash_refresh_token(refresh_token)
    now = datetime.now(timezone.utc)
    sel = RefreshTokenTable.__table__.select().where(
        (RefreshTokenTable.token_hash == token_hash) & (RefreshTokenTable.revoked == False) & (RefreshTokenTable.expires_at > now)
    )
    rt = await database.fetch_one(sel)
    if not rt:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    sel_user = UserTable.__table__.select().where(UserTable.id == rt["user_id"])
    db_user = await database.fetch_one(sel_user)
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    new_access = create_access_token(db_user["phone"])
    return unified_response("ok", "TOKEN_REFRESHED", "new access token", {"access_token": new_access})

@app.get("/verify_token/{token}")
async def verify_token_path(token: str):
    try:
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return {"status": "ok", "valid": True}
    except jwt.ExpiredSignatureError:
        return {"status": "error", "valid": False, "code": "TOKEN_EXPIRED"}
    except Exception:
        return {"status": "error", "valid": False, "code": "TOKEN_INVALID"}

@app.get("/verify_token")
async def verify_token_header(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        return {"status": "error", "valid": False, "code": "NO_AUTH_HEADER"}
    token = authorization.split(" ", 1)[1].strip()
    try:
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return {"status": "ok", "valid": True}
    except jwt.ExpiredSignatureError:
        return {"status": "error", "valid": False, "code": "TOKEN_EXPIRED"}
    except Exception:
        return {"status": "error", "valid": False, "code": "TOKEN_INVALID"}

# -------------------- Cars --------------------
@app.get("/user_cars/{user_phone}")
async def get_user_cars(user_phone: str):
    query = UserTable.__table__.select().where(UserTable.phone == user_phone)
    user = await database.fetch_one(query)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    items = user["car_list"] or []
    return unified_response("ok", "USER_CARS", "user cars", {"items": items})

@app.post("/user_cars")
async def update_user_cars(data: CarListUpdateRequest):
    sel = UserTable.__table__.select().where(UserTable.phone == data.user_phone)
    user = await database.fetch_one(sel)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    upd = UserTable.__table__.update().where(UserTable.phone == data.user_phone).values(
        car_list=[car.dict() for car in data.car_list]
    )
    await database.execute(upd)
    return unified_response("ok", "CARS_SAVED", "cars saved", {"count": len(data.car_list)})

# -------------------- Orders --------------------
@app.post("/order")
async def create_order(order: OrderRequest):
    ins = RequestTable.__table__.insert().values(
        user_phone=order.user_phone,
        latitude=order.location.latitude,
        longitude=order.location.longitude,
        car_list=[car.dict() for car in order.car_list],
        address=order.address.strip(),
        home_number=(order.home_number or "").strip(),
        service_type=order.service_type,
        price=order.price,
        request_datetime=order.request_datetime,
        status="PENDING",
        payment_type=order.payment_type.strip().lower()
    )
    await database.execute(ins)
    return unified_response("ok", "REQUEST_CREATED", "request created", {})

@app.post("/cancel_order")
async def cancel_order(cancel: CancelRequest):
    upd = (
        RequestTable.__table__.update()
        .where(
            (RequestTable.user_phone == cancel.user_phone) &
            (RequestTable.service_type == cancel.service_type) &
            (RequestTable.status.in_(["PENDING", "ACTIVE"]))
        )
        .values(status="CANCELED", scheduled_start=None)
        .returning(RequestTable.id)
    )
    rows = await database.fetch_all(upd)
    if rows and len(rows) > 0:
        return unified_response("ok", "ORDER_CANCELED", "canceled", {"count": len(rows)})
    raise HTTPException(status_code=404, detail="active order not found")

@app.get("/user_active_services/{user_phone}")
async def get_user_active_services(user_phone: str):
    sel = RequestTable.__table__.select().where(
        (RequestTable.user_phone == user_phone) &
        (RequestTable.status.in_(["PENDING", "ACTIVE"]))
    )
    result = await database.fetch_all(sel)
    # ساده: همان dict(row) برای سازگاری قبلی
    items = [dict(r) for r in result]
    return unified_response("ok", "USER_ACTIVE_SERVICES", "active services", {"items": items})

@app.get("/user_orders/{user_phone}")
async def get_user_orders(user_phone: str):
    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)
    result = await database.fetch_all(sel)
    items = [dict(r) for r in result]
    return unified_response("ok", "USER_ORDERS", "orders list", {"items": items})

# -------------------- Scheduling (1 hour slots) --------------------
# 1) ساعات آزاد یک‌روزه برای سفارش‌گیرنده (فقط BOOKED ها حذف می‌شوند)
@app.get("/provider/{provider_phone}/free_hours")
async def get_free_hours(
    provider_phone: str,
    date: str,                   # YYYY-MM-DD (UTC)
    work_start: int = 8,         # 8 → 08:00
    work_end: int = 20,          # 20 → 20:00
    limit: int = 24
):
    try:
        d = datetime.fromisoformat(date).date()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid date; expected YYYY-MM-DD")

    if not (0 <= work_start < 24 and 0 <= work_end <= 24 and work_start < work_end):
        raise HTTPException(status_code=400, detail="invalid work hours")

    day_start = datetime(d.year, d.month, d.day, work_start, 0, tzinfo=timezone.utc)
    day_end   = datetime(d.year, d.month, d.day, work_end,   0, tzinfo=timezone.utc)

    results = []
    cur = day_start
    while cur + timedelta(hours=1) <= day_end and len(results) < limit:
        s, e = cur, cur + timedelta(hours=1)
        if await provider_is_free(provider_phone, s, e):
            results.append(s.isoformat())
        cur = cur + timedelta(hours=1)

    return unified_response("ok", "FREE_HOURS", "free hourly slots", {"items": results})

# 2) سفارش‌گیرنده 3 زمان یک‌ساعته پیشنهاد می‌دهد (فقط زمان‌های خالی پذیرفته می‌شوند)
class ProposedSlotsIn(BaseModel):
    provider_phone: str
    slots: List[str]  # ISO start times (up to 3)

@app.post("/order/{order_id}/propose_slots")
async def propose_slots(order_id: int, body: ProposedSlotsIn):
    req = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == order_id))
    if not req:
        raise HTTPException(status_code=404, detail="order not found")

    accepted: List[str] = []
    for s in body.slots[:3]:
        start = parse_iso(s)
        end = start + timedelta(hours=1)
        if await provider_is_free(body.provider_phone, start, end):
            await database.execute(
                ScheduleSlotTable.__table__.insert().values(
                    request_id=order_id,
                    provider_phone=body.provider_phone,
                    slot_start=start,
                    status="PROPOSED",
                    created_at=datetime.now(timezone.utc)
                )
            )
            accepted.append(start.isoformat())

    # نوتیفیکیشن به کاربر (placeholder)
    if accepted:
        try:
            await notify_user(req["user_phone"], "زمان‌بندی", "درخواست شما بررسی شد؛ لطفاً یکی از زمان‌های پیشنهادی را انتخاب کنید.")
        except Exception:
            pass

    return unified_response("ok", "SLOTS_PROPOSED", "slots proposed", {"accepted": accepted})

# 3) خواندن زمان‌های پیشنهادی برای کاربر
@app.get("/order/{order_id}/proposed_slots")
async def get_proposed_slots(order_id: int):
    sel = ScheduleSlotTable.__table__.select().where(
        (ScheduleSlotTable.request_id == order_id) &
        (ScheduleSlotTable.status == "PROPOSED")
    ).order_by(ScheduleSlotTable.slot_start.asc())
    rows = await database.fetch_all(sel)
    items = [r["slot_start"].isoformat() for r in rows]
    return unified_response("ok", "PROPOSED_SLOTS", "proposed slots", {"items": items})

# 4) کاربر یکی از ۳ زمان را تأیید می‌کند → رزرو نهایی
@app.post("/order/{order_id}/confirm_slot")
async def confirm_slot(order_id: int, body: ConfirmSlotRequest):
    chosen_start = parse_iso(body.slot)
    sel_slot = ScheduleSlotTable.__table__.select().where(
        (ScheduleSlotTable.request_id == order_id) &
        (ScheduleSlotTable.slot_start == chosen_start) &
        (ScheduleSlotTable.status == "PROPOSED")
    )
    slot = await database.fetch_one(sel_slot)
    if not slot:
        raise HTTPException(status_code=404, detail="slot not found or not proposed")

    provider_phone = slot["provider_phone"]
    start = slot["slot_start"]
    end = start + timedelta(hours=1)

    # چک نهایی خالی بودن (Race-safe)
    if not await provider_is_free(provider_phone, start, end):
        await database.execute(
            ScheduleSlotTable.__table__.update().where(ScheduleSlotTable.id == slot["id"]).values(status="REJECTED")
        )
        raise HTTPException(status_code=409, detail="slot no longer available")

    # قبول انتخابی + رد بقیه
    await database.execute(
        ScheduleSlotTable.__table__.update().where(ScheduleSlotTable.id == slot["id"]).values(status="ACCEPTED")
    )
    await database.execute(
        ScheduleSlotTable.__table__.update().where(
            (ScheduleSlotTable.request_id == order_id) &
            (ScheduleSlotTable.status == "PROPOSED") &
            (ScheduleSlotTable.id != slot["id"])
        ).values(status="REJECTED")
    )

    # رزرو نهایی
    await database.execute(
        AppointmentTable.__table__.insert().values(
            provider_phone=provider_phone,
            request_id=order_id,
            start_time=start,
            end_time=end,
            status="BOOKED",
            created_at=datetime.now(timezone.utc)
        )
    )
    # ست در سفارش
    await database.execute(
        RequestTable.__table__.update().where(RequestTable.id == order_id).values(
            scheduled_start=start, status="ACTIVE", driver_phone=provider_phone
        )
    )

    return unified_response("ok", "SLOT_CONFIRMED", "slot confirmed", {"start": start.isoformat(), "end": end.isoformat()})

# 5) کاربر هیچ‌کدام را نمی‌پذیرد → رد همه و کنسل سفارش
@app.post("/order/{order_id}/reject_all_and_cancel")
async def reject_all_and_cancel(order_id: int):
    await database.execute(
        ScheduleSlotTable.__table__.update().where(
            (ScheduleSlotTable.request_id == order_id) &
            (ScheduleSlotTable.status == "PROPOSED")
        ).values(status="REJECTED")
    )
    await database.execute(
        RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="CANCELED", scheduled_start=None)
    )
    return unified_response("ok", "ORDER_CANCELED", "order canceled after rejecting proposals", {})

# -------------------- Profile --------------------
@app.post("/user/profile")
async def update_profile(body: UserProfileUpdate):
    if not body.phone.strip():
        raise HTTPException(status_code=400, detail="phone_required")
    sel = UserTable.__table__.select().where(UserTable.phone == body.phone)
    user = await database.fetch_one(sel)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    upd = UserTable.__table__.update().where(UserTable.phone == body.phone).values(
        name=body.name.strip(),
        address=body.address.strip()
    )
    await database.execute(upd)
    return unified_response("ok", "PROFILE_UPDATED", "profile saved", {"phone": body.phone})

@app.get("/user/profile/{phone}")
async def get_user_profile(phone: str):
    sel = UserTable.__table__.select().where(UserTable.phone == phone)
    db_user = await database.fetch_one(sel)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    mapping = getattr(db_user, "_mapping", {})
    name_val = mapping["name"] if "name" in mapping else ""
    address_val = mapping["address"] if "address" in mapping else ""
    return unified_response("ok", "PROFILE_FETCHED", "profile data", {
        "phone": db_user["phone"], "name": name_val or "", "address": address_val or ""
    })

@app.get("/debug/users")
async def debug_users():
    rows = await database.fetch_all(UserTable.__table__.select())
    out = []
    for r in rows:
        mapping = getattr(r, "_mapping", {})
        name_val = mapping["name"] if "name" in mapping else ""
        address_val = mapping["address"] if "address" in mapping else ""
        out.append({"id": r["id"], "phone": r["phone"], "name": name_val, "address": address_val})
    return out
