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

from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Index, select, func  # sqlalchemy=ORM
from sqlalchemy.dialects.postgresql import JSONB  # JSONB=نوع JSON در PostgreSQL
from sqlalchemy.ext.declarative import declarative_base  # declarative_base=پایه ORM
import sqlalchemy  # sqlalchemy=کتابخانه ORM
from databases import Database  # Database=اتصال async دیتابیس
from dotenv import load_dotenv  # load_dotenv=خواندن .env

# ——— پیکربندی محیط ———
load_dotenv()  # بارگذاری متغیرها از .env
DATABASE_URL = os.getenv("DATABASE_URL")  # آدرس پایگاه‌داده
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-secret")  # کلید JWT (پیش‌فرض توسعه)
PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "change-me-pepper")  # PEPPER سراسری برای پسورد
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))  # مدت اعتبار access_token
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))  # مدت اعتبار refresh_token
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))  # تعداد راند bcrypt
ALLOW_ORIGINS_ENV = os.getenv("ALLOW_ORIGINS", "*")  # دامنه‌های مجاز CORS

database = Database(DATABASE_URL)  # نمونه اتصال دیتابیس
Base = declarative_base()  # پایه ORM

# ——— مدل‌های ORM ———
class UserTable(Base):  # جدول کاربران
    __tablename__ = "users"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    phone = Column(String, unique=True, index=True)  # phone=شماره یکتا
    password_hash = Column(String)  # password_hash=هش پسورد
    address = Column(String)  # address=آدرس
    name = Column(String, default="")  # name=نام
    car_list = Column(JSONB, default=list)  # car_list=لیست ماشین‌ها به‌صورت JSON
    # ستون auth_token حذف شد چون استفاده نمی‌شد

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

class RequestTable(Base):  # جدول سفارش‌ها/درخواست‌ها
    __tablename__ = "requests"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید
    user_phone = Column(String)  # user_phone=شماره کاربر
    latitude = Column(Float)  # latitude=عرض جغرافیایی
    longitude = Column(Float)  # longitude=طول جغرافیایی
    car_list = Column(JSONB)  # car_list=لیست ماشین‌ها
    address = Column(String)  # address=آدرس
    home_number = Column(String, default="")  # home_number=پلاک منزل
    service_type = Column(String)  # service_type=کد سرویس انگلیسی
    price = Column(Integer)  # price=قیمت
    request_datetime = Column(String)  # request_datetime=زمان ثبت
    status = Column(String)  # status=کد وضعیت انگلیسی
    driver_name = Column(String)  # driver_name=نام راننده
    driver_phone = Column(String)  # driver_phone=تلفن راننده
    finish_datetime = Column(String)  # finish_datetime=زمان پایان
    payment_type = Column(String)  # payment_type=کد پرداخت انگلیسی

class RefreshTokenTable(Base):  # جدول رفرش‌توکن‌ها
    __tablename__ = "refresh_tokens"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید
    user_id = Column(Integer, ForeignKey("users.id"), index=True)  # user_id=ارجاع به users
    token_hash = Column(String, unique=True, index=True)  # token_hash=هش رفرش‌توکن
    expires_at = Column(DateTime(timezone=True), index=True)  # expires_at=انقضا
    revoked = Column(Boolean, default=False)  # revoked=باطل شده؟
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at=ایجاد
    __table_args__ = (Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),)  # ایندکس ترکیبی

# ——— مدل‌های Pydantic ———
class CarInfo(BaseModel):  # مدل ماشین
    brand: str  # برند
    model: str  # مدل
    plate: str  # پلاک

class Location(BaseModel):  # مدل موقعیت
    latitude: float  # عرض
    longitude: float  # طول

class OrderRequest(BaseModel):  # مدل درخواست سفارش
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

class CancelRequest(BaseModel):  # مدل لغو
    user_phone: str  # شماره کاربر
    service_type: str  # کد سرویس انگلیسی

class UserRegisterRequest(BaseModel):  # مدل ثبت‌نام
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
def bcrypt_hash_password(password: str) -> str:  # هش کردن پسورد با bcrypt + pepper
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)  # تولید نمک
    mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # ترکیب پسورد و pepper
    return bcrypt.hashpw(mixed, salt).decode("utf-8")  # خروجی هش

def verify_password_secure(password: str, stored_hash: str) -> bool:  # بررسی پسورد
    try:  # محافظت در برابر خطا
        if stored_hash.startswith("$2"):  # اگر bcrypt است
            mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # ترکیب ورودی
            return bcrypt.checkpw(mixed, stored_hash.encode("utf-8"))  # بررسی bcrypt
        old = hashlib.sha256(password.encode("utf-8")).hexdigest()  # سازگاری با sha256 قدیمی
        return old == stored_hash  # مقایسه
    except Exception:  # هر خطا
        return False  # نامعتبر

def create_access_token(phone: str) -> str:  # ساخت access_token کوتاه‌عمر
    now = datetime.now(timezone.utc)  # اکنون
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # زمان انقضا
    payload = {"sub": phone, "type": "access", "exp": exp}  # محتوا
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")  # امضا

def create_refresh_token() -> str:  # ساخت رفرش‌توکن
    return secrets.token_urlsafe(48)  # توکن امن

def hash_refresh_token(token: str) -> str:  # هش رفرش‌توکن (برای ذخیره)
    return hashlib.sha256((token + PASSWORD_PEPPER).encode("utf-8")).hexdigest()  # sha256 با pepper

def unified_response(status: str, code: str, message: str, data: Optional[dict] = None):  # پاسخ یکدست
    return {"status": status, "code": code, "message": message, "data": data or {}}  # ساخت دیکشنری پاسخ

# ——— اپ و CORS ———
app = FastAPI()  # ساخت برنامه FastAPI
allow_origins = ["*"] if ALLOW_ORIGINS_ENV.strip() == "*" else [o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()]  # لیست مبداها
app.add_middleware(  # افزودن CORS
    CORSMiddleware,
    allow_origins=allow_origins,  # دامنه‌های مجاز
    allow_credentials=True,  # کوکی مجاز
    allow_methods=["*"],  # همه متدها
    allow_headers=["*"],  # همه هدرها
)

# ——— چرخه عمر ———
@app.on_event("startup")  # رویداد شروع
async def startup():  # تابع شروع
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))  # ساخت Engine sync برای create_all
    Base.metadata.create_all(engine)  # ساخت جداول
    await database.connect()  # اتصال دیتابیس

@app.on_event("shutdown")  # رویداد پایان
async def shutdown():  # تابع پایان
    await database.disconnect()  # قطع اتصال

# ——— روت سلامت ———
@app.get("/")  # GET /
def read_root():  # هندلر
    return {"message": "Putzfee FastAPI Server is running!"}  # پیام سلامت

# ——— اندپوینت‌ها ———
@app.get("/users/exists")  # GET وجود کاربر
async def user_exists(phone: str):  # phone=شماره
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == phone)  # کوئری شمارش
    count = await database.fetch_val(q)  # اجرا و گرفتن مقدار
    exists = bool(count and int(count) > 0)  # تبدیل به بولی
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "user exists check", {"exists": exists})  # پاسخ یکسان

@app.post("/register_user")  # POST ثبت‌نام
async def register_user(user: UserRegisterRequest):  # بدنه=UserRegisterRequest
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == user.phone)  # بررسی تکراری بودن
    count = await database.fetch_val(q)  # نتیجه
    if count and int(count) > 0:  # اگر وجود دارد
        raise HTTPException(status_code=400, detail="User already exists")  # 400

    password_hash = bcrypt_hash_password(user.password)  # هش پسورد
    ins = UserTable.__table__.insert().values(  # کوئری درج
        phone=user.phone,
        password_hash=password_hash,
        address=(user.address or "").strip(),
        name="",
        car_list=[]
    )
    await database.execute(ins)  # اجرا
    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": user.phone})  # پاسخ یکدست

@app.post("/login")  # POST ورود
async def login_user(user: UserLoginRequest, request: Request):  # بدنه=UserLoginRequest
    sel = UserTable.__table__.select().where(UserTable.phone == user.phone)  # انتخاب کاربر
    db_user = await database.fetch_one(sel)  # اجرای کوئری
    if not db_user:  # اگر نبود
        raise HTTPException(status_code=404, detail="User not found")  # 404

    if not verify_password_secure(user.password, db_user["password_hash"]):  # پسورد نادرست؟
        raise HTTPException(status_code=401, detail="Invalid password")  # 401

    if not db_user["password_hash"].startswith("$2"):  # اگر هش قدیمی است
        new_hash = bcrypt_hash_password(user.password)  # هش جدید
        upd = UserTable.__table__.update().where(UserTable.id == db_user["id"]).values(password_hash=new_hash)  # آپدیت
        await database.execute(upd)  # اجرا

    access_token = create_access_token(db_user["phone"])  # ساخت JWT
    refresh_token = create_refresh_token()  # ساخت رفرش
    refresh_hash = hash_refresh_token(refresh_token)  # هش رفرش
    refresh_exp = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)  # انقضا

    ins_rt = RefreshTokenTable.__table__.insert().values(  # درج رفرش‌توکن
        user_id=db_user["id"], token_hash=refresh_hash, expires_at=refresh_exp, revoked=False
    )
    await database.execute(ins_rt)  # اجرا

    mapping = getattr(db_user, "_mapping", {})  # سازگاری
    name_val = mapping["name"] if "name" in mapping else ""  # نام
    address_val = mapping["address"] if "address" in mapping else ""  # آدرس

    return {  # پاسخ ورود (سازگار با کلاینت فعلی)
        "status": "ok", "message": "Login successful", "token": access_token, "access_token": access_token,
        "refresh_token": refresh_token,
        "user": { "phone": db_user["phone"], "address": address_val or "", "name": name_val or "" }
    }

@app.post("/auth/refresh")  # POST رفرش access_token
async def refresh_access_token(req: dict):  # req=بدنه خام
    refresh_token = req.get("refresh_token", "")  # گرفتن رفرش‌توکن
    if not refresh_token: raise HTTPException(status_code=400, detail="refresh_token required")  # نبود → 400
    token_hash = hash_refresh_token(refresh_token)  # هش
    now = datetime.now(timezone.utc)  # اکنون
    sel = RefreshTokenTable.__table__.select().where(  # انتخاب رفرش معتبر
        (RefreshTokenTable.token_hash == token_hash) & (RefreshTokenTable.revoked == False) & (RefreshTokenTable.expires_at > now)
    )
    rt = await database.fetch_one(sel)  # اجرای کوئری
    if not rt: raise HTTPException(status_code=401, detail="Invalid refresh token")  # نامعتبر → 401
    sel_user = UserTable.__table__.select().where(UserTable.id == rt["user_id"])  # انتخاب کاربر
    db_user = await database.fetch_one(sel_user)  # اجرا
    if not db_user: raise HTTPException(status_code=401, detail="Invalid refresh token")  # نبود کاربر
    new_access = create_access_token(db_user["phone"])  # ساخت access_token جدید
    return unified_response("ok", "TOKEN_REFRESHED", "new access token", {"access_token": new_access})  # پاسخ یکدست

@app.get("/verify_token/{token}")  # GET بررسی توکن با مسیر
async def verify_token_path(token: str):  # token=پارامتر مسیر
    try:
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # بررسی امضا/انقضا
        return {"status": "ok", "valid": True}  # معتبر
    except jwt.ExpiredSignatureError:
        return {"status": "error", "valid": False, "code": "TOKEN_EXPIRED"}  # منقضی
    except Exception:
        return {"status": "error", "valid": False, "code": "TOKEN_INVALID"}  # نامعتبر

@app.get("/verify_token")  # GET بررسی توکن با هدر Authorization
async def verify_token_header(authorization: Optional[str] = Header(None)):  # authorization=هدر
    if not authorization or not authorization.lower().startswith("bearer "):  # نبود هدر صحیح
        return {"status": "error", "valid": False, "code": "NO_AUTH_HEADER"}  # خطا
    token = authorization.split(" ", 1)[1].strip()  # جدا کردن «Bearer »
    try:
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # بررسی
        return {"status": "ok", "valid": True}  # معتبر
    except jwt.ExpiredSignatureError:
        return {"status": "error", "valid": False, "code": "TOKEN_EXPIRED"}  # منقضی
    except Exception:
        return {"status": "error", "valid": False, "code": "TOKEN_INVALID"}  # نامعتبر

@app.get("/user_cars/{user_phone}")  # GET لیست ماشین‌های کاربر
async def get_user_cars(user_phone: str):  # user_phone=پارامتر مسیر
    query = UserTable.__table__.select().where(UserTable.phone == user_phone)  # انتخاب کاربر
    user = await database.fetch_one(query)  # اجرا
    if user: return user["car_list"] or []  # بازگرداندن لیست خام (برای سازگاری فعلی کلاینت)
    raise HTTPException(status_code=404, detail="User not found")  # نبود کاربر

@app.post("/user_cars")  # POST ذخیره لیست ماشین‌ها
async def update_user_cars(data: CarListUpdateRequest):  # بدنه=CarListUpdateRequest
    sel = UserTable.__table__.select().where(UserTable.phone == data.user_phone)  # انتخاب کاربر
    user = await database.fetch_one(sel)  # اجرا
    if not user: raise HTTPException(status_code=404, detail="User not found")  # نبود کاربر
    upd = UserTable.__table__.update().where(UserTable.phone == data.user_phone).values(  # آپدیت
        car_list=[car.dict() for car in data.car_list]  # لیست دیکشنری ماشین‌ها
    )
    await database.execute(upd)  # اجرا
    return {"status": "ok", "message": "cars saved"}  # پاسخ ساده (سازگاری)

@app.post("/order")  # POST ثبت سفارش
async def create_order(order: OrderRequest):  # بدنه=OrderRequest
    ins = RequestTable.__table__.insert().values(  # درج سفارش
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
    await database.execute(ins)  # اجرا
    return {"status": "ok", "message": "request created"}  # پاسخ

@app.post("/cancel_order")  # POST لغو سفارش
async def cancel_order(cancel: CancelRequest):  # بدنه=CancelRequest
    upd = (  # آپدیت با RETURNING برای تشخیص موفقیت
        RequestTable.__table__.update()
        .where(
            (RequestTable.user_phone == cancel.user_phone) &
            (RequestTable.service_type == cancel.service_type) &
            (RequestTable.status.in_(["PENDING", "ACTIVE"]))
        )
        .values(status="CANCELED")
        .returning(RequestTable.id)
    )
    rows = await database.fetch_all(upd)  # اجرای آپدیت و دریافت ردیف‌های تغییر یافته
    if rows and len(rows) > 0:  # اگر حداقل یک ردیف تغییر کرد
        return {"status": "ok", "message": "canceled"}  # موفق
    raise HTTPException(status_code=404, detail="active order not found")  # نبود سفارش فعال

@app.get("/user_active_services/{user_phone}")  # GET سرویس‌های فعال کاربر
async def get_user_active_services(user_phone: str):  # پارامتر=شماره کاربر
    sel = RequestTable.__table__.select().where(  # انتخاب سفارش‌های فعال
        (RequestTable.user_phone == user_phone) &
        (RequestTable.status.in_(["PENDING", "ACTIVE"]))
    )
    result = await database.fetch_all(sel)  # اجرای کوئری
    items = [dict(row) for row in result]  # تبدیل به لیست دیکشنری
    return unified_response("ok", "USER_ACTIVE_SERVICES", "active services", {"items": items})  # پاسخ یکدست

@app.get("/user_orders/{user_phone}")  # GET همه سفارش‌های کاربر
async def get_user_orders(user_phone: str):  # پارامتر=شماره کاربر
    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)  # انتخاب همه سفارش‌ها
    result = await database.fetch_all(sel)  # اجرای کوئری
    items = [dict(row) for row in result]  # تبدیل به لیست دیکشنری
    return unified_response("ok", "USER_ORDERS", "orders list", {"items": items})  # پاسخ یکدست

@app.post("/user/profile")  # POST ذخیره پروفایل
async def update_profile(body: UserProfileUpdate):  # بدنه=UserProfileUpdate
    if not body.phone.strip():  # اعتبارسنجی شماره
        raise HTTPException(status_code=400, detail="phone_required")  # 400
    sel = UserTable.__table__.select().where(UserTable.phone == body.phone)  # انتخاب کاربر
    user = await database.fetch_one(sel)  # اجرا
    if user is None:  # نبود کاربر
        raise HTTPException(status_code=404, detail="User not found")  # 404
    else:
        upd = UserTable.__table__.update().where(UserTable.phone == body.phone).values(  # آپدیت نام/آدرس
            name=body.name.strip(),
            address=body.address.strip()
        )
        await database.execute(upd)  # اجرا
    return unified_response("ok", "PROFILE_UPDATED", "profile saved", {"phone": body.phone})  # پاسخ یکدست

@app.get("/user/profile/{phone}")  # GET دریافت پروفایل
async def get_user_profile(phone: str):  # پارامتر=شماره
    sel = UserTable.__table__.select().where(UserTable.phone == phone)  # انتخاب کاربر
    db_user = await database.fetch_one(sel)  # اجرا
    if db_user is None:  # نبود کاربر
        raise HTTPException(status_code=404, detail="User not found")  # 404
    mapping = getattr(db_user, "_mapping", {})  # سازگاری
    name_val = mapping["name"] if "name" in mapping else ""  # نام
    address_val = mapping["address"] if "address" in mapping else ""  # آدرس
    return unified_response("ok", "PROFILE_FETCHED", "profile data", {  # پاسخ یکدست
        "phone": db_user["phone"], "name": name_val or "", "address": address_val or ""
    })

@app.get("/debug/users")  # GET دیباگ کاربران
async def debug_users():  # هندلر
    rows = await database.fetch_all(UserTable.__table__.select())  # انتخاب همه کاربران
    out = []  # خروجی
    for r in rows:  # برای هر سطر
        mapping = getattr(r, "_mapping", {})  # سازگاری
        name_val = mapping["name"] if "name" in mapping else ""  # نام
        address_val = mapping["address"] if "address" in mapping else ""  # آدرس
        out.append({"id": r["id"], "phone": r["phone"], "name": name_val, "address": address_val})  # افزودن به خروجی
    return out  # بازگرداندن
