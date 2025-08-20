# -*- coding: utf-8 -*-  # اعلان کدینگ فایل | utf-8=یونیکد
import os  # os=کتابخانه سیستم‌عامل
import hashlib  # hashlib=هش
import secrets  # secrets=توکن امن
from datetime import datetime, timedelta, timezone  # datetime=زمان/تاریخ
from typing import Optional, List  # typing=نوع‌دهی

import bcrypt  # bcrypt=هش امن پسورد
import jwt  # jwt=ساخت/بررسی JSON Web Token
from fastapi import FastAPI, HTTPException, Request, Header  # FastAPI=فریم‌ورک وب | HTTPException=خطا
from fastapi.middleware.cors import CORSMiddleware  # CORSMiddleware=CORS
from pydantic import BaseModel  # BaseModel=مدل‌های ورودی/خروجی

from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Index, select, func, and_  # sqlalchemy=ORM
from sqlalchemy.dialects.postgresql import JSONB  # JSONB=نوع JSON در PostgreSQL
from sqlalchemy.ext.declarative import declarative_base  # declarative_base=پایه ORM
import sqlalchemy  # sqlalchemy=کتابخانه ORM
from databases import Database  # Database=اتصال async دیتابیس
from dotenv import load_dotenv  # load_dotenv=خواندن .env

# ——— پیکربندی محیط ———
load_dotenv()  # بارگذاری متغیرها از .env
DATABASE_URL = os.getenv("DATABASE_URL")  # آدرس پایگاه‌داده
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-secret")  # کلید JWT (پیش‌فرض توسعه)
PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "change-me-pepper")  # pepper برای پسورد
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))  # عمر access_token (دقیقه)
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))  # عمر refresh_token (روز)
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))  # هزینه bcrypt
ALLOW_ORIGINS_ENV = os.getenv("ALLOW_ORIGINS", "*")  # دامنه‌های مجاز CORS (CSV یا "*")

# ——— Rate limit / Lockout ———
LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "300"))  # پنجره تلاش‌ها (۵ دقیقه)
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))  # سقف تلاش ناموفق
LOGIN_LOCK_SECONDS = int(os.getenv("LOGIN_LOCK_SECONDS", "900"))  # مدت قفل (۱۵ دقیقه)

database = Database(DATABASE_URL)  # نمونه اتصال دیتابیس
Base = declarative_base()  # پایه ORM

# ——— مدل‌های ORM ———
class UserTable(Base):  # جدول کاربران
    __tablename__ = "users"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # کلید
    phone = Column(String, unique=True, index=True)  # شماره یکتا
    password_hash = Column(String)  # هش پسورد
    address = Column(String)  # آدرس
    name = Column(String, default="")  # نام
    car_list = Column(JSONB, default=list)  # لیست ماشین‌ها (JSON)

class DriverTable(Base):  # جدول راننده‌ها
    __tablename__ = "drivers"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    photo_url = Column(String)
    id_card_number = Column(String)
    phone = Column(String, unique=True)
    phone_verified = Column(Boolean, default=False)
    is_online = Column(Boolean, default=False)
    status = Column(String, default="فعال")

class RequestTable(Base):  # جدول سفارش‌ها
    __tablename__ = "requests"  # نام جدول
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

class RefreshTokenTable(Base):  # جدول رفرش‌توکن‌ها
    __tablename__ = "refresh_tokens"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    token_hash = Column(String, unique=True, index=True)
    expires_at = Column(DateTime(timezone=True), index=True)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),)

class LoginAttemptTable(Base):  # جدول تلاش‌های ورود (Rate limit)
    __tablename__ = "login_attempts"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # کلید
    phone = Column(String, index=True)  # شماره کاربر
    ip = Column(String, index=True)  # آی‌پی
    attempt_count = Column(Integer, default=0)  # تعداد تلاش‌ها
    window_start = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # شروع پنجره
    locked_until = Column(DateTime(timezone=True), nullable=True)  # تا این زمان قفل
    last_attempt_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # آخرین تلاش
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # ایجاد
    __table_args__ = (Index("ix_login_attempt_phone_ip", "phone", "ip"),)  # ایندکس phone+ip

# ——— مدل‌های Pydantic ———
class CarInfo(BaseModel):  # مدل ماشین
    brand: str  # برند
    model: str  # مدل
    plate: str  # پلاک

class Location(BaseModel):  # مدل موقعیت
    latitude: float  # عرض
    longitude: float  # طول

class OrderRequest(BaseModel):  # مدل ثبت سفارش
    user_phone: str  # شماره کاربر
    location: Location  # موقعیت
    car_list: List[CarInfo]  # لیست ماشین‌ها
    address: str  # آدرس
    home_number: Optional[str] = ""  # پلاک
    service_type: str  # کد سرویس انگلیسی
    price: int  # قیمت
    request_datetime: str  # زمان ثبت
    payment_type: str  # کد پرداخت انگلیسی

class CarListUpdateRequest(BaseModel):  # مدل به‌روزرسانی ماشین‌ها
    user_phone: str  # شماره کاربر
    car_list: List[CarInfo]  # لیست ماشین‌ها

class CancelRequest(BaseModel):  # مدل لغو سفارش
    user_phone: str  # شماره کاربر
    service_type: str  # کد سرویس انگلیسی

class UserRegisterRequest(BaseModel):  # مدل ثبت‌نام کاربر
    phone: str  # شماره
    password: str  # پسورد
    address: Optional[str] = None  # آدرس اختیاری

class UserLoginRequest(BaseModel):  # مدل ورود
    phone: str  # شماره
    password: str  # پسورد

class UserProfileUpdate(BaseModel):  # مدل ویرایش پروفایل
    phone: str  # شماره
    name: str = ""  # نام
    address: str = ""  # آدرس

# ——— توابع امنیت ———
def bcrypt_hash_password(password: str) -> str:  # هش bcrypt+pepper
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)  # تولید نمک
    mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # ترکیب پسورد+pepper
    return bcrypt.hashpw(mixed, salt).decode("utf-8")  # خروجی هش

def verify_password_secure(password: str, stored_hash: str) -> bool:  # بررسی پسورد
    try:
        if stored_hash.startswith("$2"):  # bcrypt؟
            mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # ترکیب ورودی
            return bcrypt.checkpw(mixed, stored_hash.encode("utf-8"))  # بررسی bcrypt
        old = hashlib.sha256(password.encode("utf-8")).hexdigest()  # سازگاری sha256 قدیمی
        return old == stored_hash  # مقایسه
    except Exception:
        return False  # هر خطا → نامعتبر

def create_access_token(phone: str) -> str:  # ساخت access_token
    now = datetime.now(timezone.utc)  # اکنون
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # انقضا
    payload = {"sub": phone, "type": "access", "exp": exp}  # payload=اطلاعات
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")  # امضا

def create_refresh_token() -> str:  # ساخت رفرش‌توکن
    return secrets.token_urlsafe(48)  # توکن امن

def hash_refresh_token(token: str) -> str:  # هش رفرش‌توکن
    return hashlib.sha256((token + PASSWORD_PEPPER).encode("utf-8")).hexdigest()  # sha256(توکن+pepper)

def unified_response(status: str, code: str, message: str, data: Optional[dict] = None):  # پاسخ یکدست
    return {"status": status, "code": code, "message": message, "data": data or {}}  # دیکشنری استاندارد

# ——— ابزارها ———
def get_client_ip(request: Request) -> str:  # گرفتن IP واقعی
    xff = request.headers.get("x-forwarded-for", "")  # X-Forwarded-For=زنجیره آی‌پی‌ها
    if xff:
        return xff.split(",")[0].strip()  # اولین IP=کلاینت واقعی
    return request.client.host or "unknown"  # در غیر این صورت از اتصال

# ——— اپ و CORS ———
app = FastAPI()  # نمونه FastAPI
allow_origins = ["*"] if ALLOW_ORIGINS_ENV.strip() == "*" else [o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()]  # لیست مبداها
app.add_middleware(  # افزودن CORS
    CORSMiddleware,
    allow_origins=allow_origins,  # دامنه‌های مجاز
    allow_credentials=True,  # اجازه کوکی
    allow_methods=["*"],  # همه متدها
    allow_headers=["*"],  # همه هدرها
)

# ——— چرخه عمر ———
@app.on_event("startup")  # شروع
async def startup():
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))  # Engine sync برای create_all
    Base.metadata.create_all(engine)  # ساخت جداول
    await database.connect()  # اتصال دیتابیس

@app.on_event("shutdown")  # پایان
async def shutdown():
    await database.disconnect()  # قطع اتصال

# ——— روت سلامت ———
@app.get("/")
def read_root():
    return {"message": "Putzfee FastAPI Server is running!"}  # پیام سلامت

# ——— اندپوینت‌ها ———
@app.get("/users/exists")
async def user_exists(phone: str):
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == phone)  # شمارش کاربر
    count = await database.fetch_val(q)  # نتیجه
    exists = bool(count and int(count) > 0)  # بولی
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "user exists check", {"exists": exists})  # پاسخ

@app.post("/register_user")
async def register_user(user: UserRegisterRequest):
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == user.phone)  # بررسی تکراری
    count = await database.fetch_val(q)  # نتیجه
    if count and int(count) > 0:
        raise HTTPException(status_code=400, detail="User already exists")  # کاربر موجود
    password_hash = bcrypt_hash_password(user.password)  # هش پسورد
    ins = UserTable.__table__.insert().values(
        phone=user.phone, password_hash=password_hash, address=(user.address or "").strip(), name="", car_list=[]
    )  # درج کاربر
    await database.execute(ins)  # اجرا
    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": user.phone})  # پاسخ

@app.post("/login")
async def login_user(user: UserLoginRequest, request: Request):
    client_ip = get_client_ip(request)  # آی‌پی کلاینت
    now = datetime.now(timezone.utc)  # اکنون

    # — قفل فعال؟ —
    sel_attempt = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == user.phone, LoginAttemptTable.ip == client_ip))  # انتخاب رکورد تلاش
    attempt_row = await database.fetch_one(sel_attempt)  # دریافت رکورد
    if attempt_row and attempt_row["locked_until"] and attempt_row["locked_until"] > now:  # اگر قفل است
        retry_after = int((attempt_row["locked_until"] - now).total_seconds())  # ثانیه باقیمانده
        raise HTTPException(status_code=429, detail={"code": "RATE_LIMITED", "lock_remaining": retry_after, "window_seconds": LOGIN_WINDOW_SECONDS})  # 429 با جزئیات

    # — یافتن کاربر —
    sel_user = UserTable.__table__.select().where(UserTable.phone == user.phone)  # انتخاب کاربر
    db_user = await database.fetch_one(sel_user)  # اجرا
    if not db_user:
        # ثبت تلاش ناموفق برای شماره/آی‌پی (عدد باقیمانده را هم برگردانیم)
        await _register_login_failure(user.phone, client_ip)  # ثبت ناموفق
        updated = await database.fetch_one(LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == user.phone, LoginAttemptTable.ip == client_ip)))  # رکورد به‌روز
        remaining = 0  # تعداد باقیمانده
        lock_remaining = 0  # زمان قفل باقیمانده
        if updated:
            remaining = max(0, LOGIN_MAX_ATTEMPTS - int(updated["attempt_count"] or 0))  # محاسبه باقیمانده
            if updated["locked_until"] and updated["locked_until"] > now:
                lock_remaining = int((updated["locked_until"] - now).total_seconds())  # ثانیه قفل
        raise HTTPException(status_code=404, detail={"code": "USER_NOT_FOUND", "remaining_attempts": remaining, "lock_remaining": lock_remaining, "window_seconds": LOGIN_WINDOW_SECONDS})  # 404 با جزئیات

    # — بررسی پسورد —
    if not verify_password_secure(user.password, db_user["password_hash"]):  # پسورد اشتباه
        await _register_login_failure(user.phone, client_ip)  # ثبت ناموفق
        updated = await database.fetch_one(LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == user.phone, LoginAttemptTable.ip == client_ip)))  # رکورد به‌روز
        remaining = 0  # باقیمانده
        lock_remaining = 0  # زمان قفل
        if updated:
            remaining = max(0, LOGIN_MAX_ATTEMPTS - int(updated["attempt_count"] or 0))  # محاسبه باقیمانده
            if updated["locked_until"] and updated["locked_until"] > now:
                lock_remaining = int((updated["locked_until"] - now).total_seconds())  # ثانیه قفل
        raise HTTPException(status_code=401, detail={"code": "WRONG_PASSWORD", "remaining_attempts": remaining, "lock_remaining": lock_remaining, "window_seconds": LOGIN_WINDOW_SECONDS})  # 401 با جزئیات

    # — موفقیت: ریست شمارنده —
    await _register_login_success(user.phone, client_ip)  # ریست تلاش‌ها

    # — ارتقای هش قدیمی (در صورت نیاز) —
    if not db_user["password_hash"].startswith("$2"):
        new_hash = bcrypt_hash_password(user.password)  # هش جدید
        upd = UserTable.__table__.update().where(UserTable.id == db_user["id"]).values(password_hash=new_hash)  # آپدیت
        await database.execute(upd)  # اجرا

    # — ساخت توکن‌ها —
    access_token = create_access_token(db_user["phone"])  # access_token
    refresh_token = create_refresh_token()  # refresh_token
    refresh_hash = hash_refresh_token(refresh_token)  # هش رفرش
    refresh_exp = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)  # انقضا رفرش
    ins_rt = RefreshTokenTable.__table__.insert().values(user_id=db_user["id"], token_hash=refresh_hash, expires_at=refresh_exp, revoked=False)  # درج رفرش
    await database.execute(ins_rt)  # اجرا

    mapping = getattr(db_user, "_mapping", {})  # سازگاری
    name_val = mapping["name"] if "name" in mapping else ""  # نام
    address_val = mapping["address"] if "address" in mapping else ""  # آدرس

    return {  # پاسخ ورود (سازگار با کلاینت)
        "status": "ok", "message": "Login successful", "token": access_token, "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {"phone": db_user["phone"], "address": address_val or "", "name": name_val or ""}
    }

async def _register_login_failure(phone: str, ip: str):  # ثبت تلاش ناموفق
    now = datetime.now(timezone.utc)  # اکنون
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))  # انتخاب رکورد
    row = await database.fetch_one(sel)  # نتیجه
    if row is None:  # اگر رکورد نیست
        ins = LoginAttemptTable.__table__.insert().values(  # درج جدید
            phone=phone, ip=ip, attempt_count=1, window_start=now, locked_until=None, last_attempt_at=now
        )
        await database.execute(ins)  # اجرا
        return  # پایان
    window_start = row["window_start"] or now  # شروع پنجره
    within_window = (now - window_start).total_seconds() <= LOGIN_WINDOW_SECONDS  # داخل پنجره؟
    new_count = (row["attempt_count"] + 1) if within_window else 1  # شمارنده جدید
    new_window_start = window_start if within_window else now  # شروع جدید (اگر خارج پنجره)
    locked_until = row["locked_until"]  # وضعیت قفل
    if new_count >= LOGIN_MAX_ATTEMPTS:  # اگر سقف رد شد
        locked_until = now + timedelta(seconds=LOGIN_LOCK_SECONDS)  # قفل ۱۵ دقیقه‌ای
    upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(  # آپدیت رکورد
        attempt_count=new_count, window_start=new_window_start, locked_until=locked_until, last_attempt_at=now
    )
    await database.execute(upd)  # اجرا

async def _register_login_success(phone: str, ip: str):  # ریست تلاش‌ها بعد موفقیت
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))  # انتخاب رکورد
    row = await database.fetch_one(sel)  # نتیجه
    if row:
        upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(  # ریست شمارنده/قفل
            attempt_count=0, window_start=datetime.now(timezone.utc), locked_until=None
        )
        await database.execute(upd)  # اجرا

@app.post("/auth/refresh")
async def refresh_access_token(req: dict):
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
        .values(status="CANCELED")
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
    items = [dict(row) for row in result]
    return unified_response("ok", "USER_ACTIVE_SERVICES", "active services", {"items": items})

@app.get("/user_orders/{user_phone}")
async def get_user_orders(user_phone: str):
    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)
    result = await database.fetch_all(sel)
    items = [dict(row) for row in result]
    return unified_response("ok", "USER_ORDERS", "orders list", {"items": items})

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
