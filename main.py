# -*- coding: utf-8 -*-  # -*-=اعلان کدینگ | utf-8=پشتیبانی فارسی/آلمانی
import os  # os=متغیرهای محیطی
import hashlib  # hashlib=هش (برای سازگاری/رفرش)
import secrets  # secrets=توکن امن
from datetime import datetime, timedelta, timezone  # datetime/timedelta/timezone=زمان
from typing import Optional, List  # typing=نوع‌های کمکی

import bcrypt  # bcrypt=هش امن پسورد
import jwt  # jwt=توکن‌های JWT

from fastapi import FastAPI, HTTPException, Request, Header  # FastAPI/HTTPException/Request/Header=چارچوب/خطا/درخواست/هدر
from fastapi.middleware.cors import CORSMiddleware  # CORSMiddleware=CORS
from pydantic import BaseModel  # BaseModel=مدل‌های Pydantic

from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Index, select, func  # SQLAlchemy=ORM
from sqlalchemy.dialects.postgresql import JSONB  # JSONB=نوع JSON بهینه
from sqlalchemy.ext.declarative import declarative_base  # declarative_base=پایه ORM
import sqlalchemy  # sqlalchemy=انجین

from databases import Database  # databases=کتابخانه اتصال async
from dotenv import load_dotenv  # load_dotenv=خواندن .env

from unidecode import unidecode  # unidecode=برای نگاشت به اسلاگ (فقط سرویس)

# ——— پیکربندی محیط ———
load_dotenv()  # بارگذاری .env
DATABASE_URL = os.getenv("DATABASE_URL")  # DATABASE_URL=آدرس دیتابیس
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-secret")  # JWT_SECRET=راز JWT
PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "change-me-pepper")  # PASSWORD_PEPPER=pepper پسورد
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))  # انقضای access
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))  # انقضای refresh
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))  # هزینه bcrypt
ALLOW_ORIGINS_ENV = os.getenv("ALLOW_ORIGINS", "*")  # دامنه‌های مجاز CORS

database = Database(DATABASE_URL)  # database=اتصال async
Base = declarative_base()  # Base=پایه ORM

# ——— نرمال‌سازی داده‌های ساختاری ———
FA_DIGITS = str.maketrans("۰۱۲۳۴۵۶۷۸۹", "0123456789")  # FA_DIGITS=نگاشت ارقام فارسی
AR_DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩", "0123456789")  # AR_DIGITS=نگاشت ارقام عربی

SERVICE_MAP = {  # SERVICE_MAP=نگاشت سرویس‌ها به اسلاگ انگلیسی
    "کارواش": "carwash", "Autowäsche": "carwash", "car wash": "carwash",
    "شستشوی مبل": "sofa_cleaning", "Sofareinigung": "sofa_cleaning",
    "نظافت کلی": "general_cleaning", "Allgemeine Reinigung": "general_cleaning",
    "شستشوی پنجره": "window_cleaning", "Fensterreinigung": "window_cleaning",
    "نظافت راه‌پله": "stairs_cleaning", "Treppenreinigung": "stairs_cleaning",
    "سرویس بهداشتی": "bathroom_cleaning", "Badezimmerreinigung": "bathroom_cleaning",
}

def normalize_digits(s: str) -> str:  # normalize_digits=تبدیل ارقام به انگلیسی
    if not s: return ""
    return s.translate(FA_DIGITS).translate(AR_DIGITS)

def map_service_type_to_slug(s: str) -> str:  # map_service_type_to_slug=نگاشت سرویس به اسلاگ
    if not s: return ""
    s_norm = s.strip().lower()  # s_norm=نرمال‌سازی اولیه
    for key, value in SERVICE_MAP.items():  # پیمایش نگاشت
        if s_norm == key.lower():  # اگر مطابقت دقیق داشت
            return value  # return=اسلاگ انگلیسی
    return s_norm.replace(" ", "_")  # fallback=استفاده از خود ورودی نرمال‌شده

# ——— مدل‌های ORM ———
class UserTable(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String, unique=True, index=True)
    password_hash = Column(String)
    address = Column(String)
    name = Column(String, default="")
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
    home_number = Column(String, default="")
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

# ——— مدل‌های Pydantic ———
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

# ——— توابع امنیت ———
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

# ——— اپ و CORS ———
app = FastAPI()
allow_origins = ["*"] if ALLOW_ORIGINS_ENV.strip() == "*" else [o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ——— چرخه عمر ———
@app.on_event("startup")
async def startup():
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))
    Base.metadata.create_all(engine)
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# ——— روت سلامت ———
@app.get("/")
def read_root():
    return {"message": "Putzfee FastAPI Server is running!"}

# ——— اندپوینت: بررسی وجود کاربر ———
@app.get("/users/exists")
async def user_exists(phone: str):
    phone_norm = normalize_digits(phone)
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == phone_norm)
    count = await database.fetch_val(q)
    exists = bool(count and int(count) > 0)
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "user exists check", {"exists": exists})

# ——— اندپوینت: ثبت‌نام (ذخیره UTF-8) ———
@app.post("/register_user")
async def register_user(user: UserRegisterRequest):
    phone_norm = normalize_digits(user.phone)
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == phone_norm)
    count = await database.fetch_val(q)
    if count and int(count) > 0:
        raise HTTPException(status_code=400, detail="User already exists")

    password_hash = bcrypt_hash_password(user.password)
    ins = UserTable.__table__.insert().values(
        phone=phone_norm,
        password_hash=password_hash,
        address=(user.address or "").strip(),
        name="",
        car_list=[]
    )
    await database.execute(ins)
    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": phone_norm})

# ——— اندپوینت: ورود ———
@app.post("/login")
async def login_user(user: UserLoginRequest, request: Request):
    phone_norm = normalize_digits(user.phone)
    sel = UserTable.__table__.select().where(UserTable.phone == phone_norm)
    db_user = await database.fetch_one(sel)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password_secure(user.password, db_user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid password")

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

    mapping = getattr(db_user, "_mapping", {})
    name_val = mapping["name"] if "name" in mapping else ""
    address_val = mapping["address"] if "address" in mapping else ""

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

# ——— اندپوینت: رفرش اکسس‌توکن ———
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

# ——— اندپوینت: بررسی اعتبار توکن (مسیر + هدر) ———
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

# ——— اندپوینت: لیست ماشین‌های کاربر (ذخیره UTF-8) ———
@app.get("/user_cars/{user_phone}")
async def get_user_cars(user_phone: str):
    phone_norm = normalize_digits(user_phone)
    query = UserTable.__table__.select().where(UserTable.phone == phone_norm)
    user = await database.fetch_one(query)
    if user:
        return user["car_list"] or []
    raise HTTPException(status_code=404, detail="User not found")

@app.post("/user_cars")
async def update_user_cars(data: CarListUpdateRequest):
    phone_norm = normalize_digits(data.user_phone)
    cars_norm = [
        {"brand": c.brand.strip(), "model": c.model.strip(), "plate": normalize_digits(c.plate)}
        for c in data.car_list
    ]
    sel = UserTable.__table__.select().where(UserTable.phone == phone_norm)
    user = await database.fetch_one(sel)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    upd = UserTable.__table__.update().where(UserTable.phone == phone_norm).values(
        car_list=cars_norm
    )
    await database.execute(upd)
    return {"status": "ok", "message": "cars saved"}

# ——— اندپوینت: ثبت سفارش (ذخیره UTF-8 + کدهای انگلیسی) ———
@app.post("/order")
async def create_order(order: OrderRequest):
    phone_norm = normalize_digits(order.user_phone)
    home_number_norm = normalize_digits(order.home_number or "")
    service_slug = map_service_type_to_slug(order.service_type)

    cars_norm = [
        {"brand": c.brand.strip(), "model": c.model.strip(), "plate": normalize_digits(c.plate)}
        for c in order.car_list
    ]

    ins = RequestTable.__table__.insert().values(
        user_phone=phone_norm,
        latitude=order.location.latitude,
        longitude=order.location.longitude,
        car_list=cars_norm,
        address=order.address.strip(),
        home_number=home_number_norm,
        service_type=service_slug,
        price=order.price,
        request_datetime=order.request_datetime,
        status="PENDING",
        payment_type=order.payment_type.strip().lower()
    )
    await database.execute(ins)
    return {"status": "ok", "message": "request created"}

# ——— اندپوینت: لغو سفارش ———
@app.post("/cancel_order")
async def cancel_order(cancel: CancelRequest):
    phone_norm = normalize_digits(cancel.user_phone)
    service_slug = map_service_type_to_slug(cancel.service_type)
    upd = RequestTable.__table__.update().where(
        (RequestTable.user_phone == phone_norm) &
        (RequestTable.service_type == service_slug) &
        (RequestTable.status.in_(["PENDING", "در انتظار"]))
    ).values(status="CANCELED")
    result = await database.execute(upd)
    if result:
        return {"status": "ok", "message": "canceled"}
    raise HTTPException(status_code=404, detail="active order not found")

# ——— اندپوینت: سرویس‌های فعال کاربر ———
@app.get("/user_active_services/{user_phone}")
async def get_user_active_services(user_phone: str):
    phone_norm = normalize_digits(user_phone)
    sel = RequestTable.__table__.select().where(
        (RequestTable.user_phone == phone_norm) &
        (RequestTable.status.in_(["PENDING", "ACTIVE", "در انتظار", "فعال"]))
    )
    result = await database.fetch_all(sel)
    return [dict(row) for row in result]

# ——— اندپوینت: تاریخچه سفارش‌های کاربر ———
@app.get("/user_orders/{user_phone}")
async def get_user_orders(user_phone: str):
    phone_norm = normalize_digits(user_phone)
    sel = RequestTable.__table__.select().where(RequestTable.phone == phone_norm)
    result = await database.fetch_all(sel)
    return [dict(row) for row in result]

# ——— اندپوینت: به‌روزرسانی پروفایل (ذخیره UTF-8) ———
@app.post("/user/profile")
async def update_profile(body: UserProfileUpdate):
    phone_norm = normalize_digits(body.phone)
    if not phone_norm:
        raise HTTPException(status_code=400, detail="phone_required")
    sel = UserTable.__table__.select().where(UserTable.phone == phone_norm)
    user = await database.fetch_one(sel)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    else:
        upd = UserTable.__table__.update().where(UserTable.phone == phone_norm).values(
            name=body.name.strip(),
            address=body.address.strip()
        )
        await database.execute(upd)
    return unified_response("ok", "PROFILE_UPDATED", "profile saved", {"phone": phone_norm})

# ——— اندپوینت: لیست کاربران (دیباگ) ———
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
