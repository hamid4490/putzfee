# -*- coding: utf-8 -*-
import os
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from typing import Optional, List

from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Index, select, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.declarative import declarative_base
import sqlalchemy

from databases import Database
from dotenv import load_dotenv

# ---------- Env / Config ----------
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-secret")
PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "change-me-pepper")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))
ALLOW_ORIGINS_ENV = os.getenv("ALLOW_ORIGINS", "*")

database = Database(DATABASE_URL)
Base = declarative_base()

# ---------- ORM Models ----------
class UserTable(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String, unique=True, index=True)
    password_hash = Column(String)
    address = Column(String)
    name = Column(String, default="")  # ستون جدید
    car_list = Column(JSONB, default=list)
    auth_token = Column(String, nullable=True)

class DriverTable(Base):
    __tablename__ = "drivers"
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    photo_url = Column(String)
    id_card_number = Column(String)
    phone = Column(String, unique=True)
    phone_verified = Column(Boolean, default=False)
    is_online = Column(Boolean, default=False)
    status = Column(String, default="فعال")

class RequestTable(Base):
    __tablename__ = "requests"
    id = Column(Integer, primary_key=True, index=True)
    user_phone = Column(String)
    latitude = Column(Float)
    longitude = Column(Float)
    car_list = Column(JSONB)
    address = Column(String)
    home_number = Column(String, default="")  # ستون جدید
    service_type = Column(String)
    price = Column(Integer)
    request_datetime = Column(String)
    status = Column(String)
    driver_name = Column(String)
    driver_phone = Column(String)
    finish_datetime = Column(String)
    payment_type = Column(String)

class RefreshTokenTable(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    token_hash = Column(String, unique=True, index=True)
    expires_at = Column(DateTime(timezone=True), index=True)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),)

# ---------- Pydantic Schemas ----------
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
    home_number: Optional[str] = ""  # جدید: پلاک منزل
    service_type: str
    price: int
    request_datetime: str            # بدون میلی‌ثانیه
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

# ---------- Security Helpers ----------
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

# ---------- App & CORS ----------
app = FastAPI()
allow_origins = ["*"] if ALLOW_ORIGINS_ENV.strip() == "*" else [o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Lifecycle ----------
@app.on_event("startup")
async def startup():
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))  # فقط برای create_all
    Base.metadata.create_all(engine)
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# ---------- Health ----------
@app.get("/")
def read_root():
    return {"message": "Putzfee FastAPI Server is running!"}

# ---------- Users Exists ----------
@app.get("/users/exists")
async def user_exists(phone: str):
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == phone)
    count = await database.fetch_val(q)
    exists = bool(count and int(count) > 0)
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "user exists check", {"exists": exists})

# ---------- Register ----------
@app.post("/register_user")
async def register_user(user: UserRegisterRequest):
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == user.phone)
    count = await database.fetch_val(q)
    if count and int(count) > 0:
        raise HTTPException(status_code=400, detail="User already exists")

    password_hash = bcrypt_hash_password(user.password)
    ins = UserTable.__table__.insert().values(
        phone=user.phone,
        password_hash=password_hash,
        address=user.address or "",
        name="",          # مقدار اولیه خالی
        car_list=[]
    )
    await database.execute(ins)
    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": user.phone})

# ---------- Login (fix for Record.get) ----------
@app.post("/login")
async def login_user(user: UserLoginRequest, request: Request):
    sel = UserTable.__table__.select().where(UserTable.phone == user.phone)
    db_user = await database.fetch_one(sel)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password_secure(user.password, db_user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid password")

    # ارتقای هش قدیمی → bcrypt
    if not db_user["password_hash"].startswith("$2"):
        new_hash = bcrypt_hash_password(user.password)
        upd = UserTable.__table__.update().where(UserTable.id == db_user["id"]).values(password_hash=new_hash)
        await database.execute(upd)

    access_token = create_access_token(db_user["phone"])
    refresh_token = create_refresh_token()
    refresh_hash = hash_refresh_token(refresh_token)
    refresh_exp = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    ins_rt = RefreshTokenTable.__table__.insert().values(
        user_id=db_user["id"],
        token_hash=refresh_hash,
        expires_at=refresh_exp,
        revoked=False
    )
    await database.execute(ins_rt)

    # NOTE: databases.Record متد get ندارد. از mapping داخلی استفاده می‌کنیم تا در نبود ستون name خطا ندهد.
    name_val = db_user["name"] if ("name" in getattr(db_user, "_mapping", {})) else ""  # مقدار امن name
    address_val = db_user["address"] if ("address" in getattr(db_user, "_mapping", {})) else ""

    return {
        "status": "ok",
        "message": "Login successful",
        "token": access_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "phone": db_user["phone"],
            "address": address_val or "",
            "name": name_val or ""
        }
    }

# ---------- Refresh Access Token ----------
@app.post("/auth/refresh")
async def refresh_access_token(req: dict):
    refresh_token = req.get("refresh_token", "")
    if not refresh_token:
        raise HTTPException(status_code=400, detail="refresh_token required")
    token_hash = hash_refresh_token(refresh_token)
    now = datetime.now(timezone.utc)
    sel = RefreshTokenTable.__table__.select().where(
        (RefreshTokenTable.token_hash == token_hash) &
        (RefreshTokenTable.revoked == False) &
        (RefreshTokenTable.expires_at > now)
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

# ---------- Verify Token: path + header ----------
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

# ---------- Cars ----------
@app.get("/user_cars/{user_phone}")
async def get_user_cars(user_phone: str):
    query = UserTable.__table__.select().where(UserTable.phone == user_phone)
    user = await database.fetch_one(query)
    if user:
        return user["car_list"] or []
    raise HTTPException(status_code=404, detail="User not found")

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
    return {"status": "ok", "message": "cars saved"}

# ---------- Orders (home_number supported) ----------
@app.post("/order")
async def create_order(order: OrderRequest):
    ins = RequestTable.__table__.insert().values(
        user_phone=order.user_phone,
        latitude=order.location.latitude,
        longitude=order.location.longitude,
        car_list=[car.dict() for car in order.car_list],
        address=order.address,
        home_number=(order.home_number or ""),  # ذخیره پلاک منزل
        service_type=order.service_type,
        price=order.price,
        request_datetime=order.request_datetime,
        status="در انتظار",
        driver_name="",
        driver_phone="",
        finish_datetime="",
        payment_type=order.payment_type
    )
    await database.execute(ins)
    return {"status": "ok", "message": "request created"}

@app.post("/cancel_order")
async def cancel_order(cancel: CancelRequest):
    upd = RequestTable.__table__.update().where(
        (RequestTable.user_phone == cancel.user_phone) &
        (RequestTable.service_type == cancel.service_type) &
        (RequestTable.status == "در انتظار")
    ).values(status="کنسل شده")
    result = await database.execute(upd)
    if result:
        return {"status": "ok", "message": "canceled"}
    raise HTTPException(status_code=404, detail="active order not found")

@app.get("/user_active_services/{user_phone}")
async def get_user_active_services(user_phone: str):
    sel = RequestTable.__table__.select().where(
        (RequestTable.user_phone == user_phone) &
        (RequestTable.status == "در انتظار")
    )
    result = await database.fetch_all(sel)
    return [dict(row) for row in result]

@app.get("/user_orders/{user_phone}")
async def get_user_orders(user_phone: str):
    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)
    result = await database.fetch_all(sel)
    return [dict(row) for row in result]

# ---------- Debug ----------
@app.get("/debug/users")
async def debug_users():
    rows = await database.fetch_all(UserTable.__table__.select())
    out = []
    for r in rows:
        # مانند login: Record.get وجود ندارد؛ از mapping استفاده کن
        name_val = r["name"] if ("name" in getattr(r, "_mapping", {})) else ""
        address_val = r["address"] if ("address" in getattr(r, "_mapping", {})) else ""
        out.append({"id": r["id"], "phone": r["phone"], "name": name_val, "address": address_val})
    return out

# ---------- Profile (NEW) ----------
@app.post("/user/profile")
async def update_profile(body: UserProfileUpdate):
    if not body.phone.strip():
        raise HTTPException(status_code=400, detail="phone_required")
    sel = UserTable.__table__.select().where(UserTable.phone == body.phone)
    user = await database.fetch_one(sel)
    if user is None:
        ins = UserTable.__table__.insert().values(
            phone=body.phone.strip(),
            password_hash="",
            address=(body.address or "").strip(),
            name=(body.name or "").strip(),
            car_list=[]
        )
        await database.execute(ins)
    else:
        upd = UserTable.__table__.update().where(UserTable.phone == body.phone).values(
            name=(body.name or "").strip(),
            address=(body.address or "").strip()
        )
        await database.execute(upd)
    return unified_response("ok", "PROFILE_UPDATED", "profile saved", {"phone": body.phone})
