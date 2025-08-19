# -*- coding: utf-8 -*-  # -*- coding: utf-8 -*-=کدینگ فایل پایتون
import os  # import os=کتابخانه سیستم‌عامل
import hashlib  # import hashlib=هش
import secrets  # import secrets=توکن امن
from datetime import datetime, timedelta, timezone  # import datetime=زمان
from typing import Optional, List  # import typing=نوع‌دهی

import bcrypt  # import bcrypt=هش امن
import jwt  # import jwt=توکن JWT
from fastapi import FastAPI, HTTPException, Request, Header  # import FastAPI=فریم‌ورک وب
from fastapi.middleware.cors import CORSMiddleware  # import CORSMiddleware=CORS
from pydantic import BaseModel  # import BaseModel=مدل‌های ورودی/خروجی

from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Index, select, func  # import sqlalchemy=ORM
from sqlalchemy.dialects.postgresql import JSONB  # import JSONB=نوع JSON مخصوص Postgres
from sqlalchemy.ext.declarative import declarative_base  # import declarative_base=پایه ORM
import sqlalchemy  # import sqlalchemy=کتابخانه ORM
from databases import Database  # import Database=کتابخانه async پایگاه‌داده
from dotenv import load_dotenv  # import load_dotenv=خواندن .env

# ——— پیکربندی محیط ———
load_dotenv()  # load_dotenv=بارگذاری متغیرهای محیطی از .env
DATABASE_URL = os.getenv("DATABASE_URL")  # DATABASE_URL=آدرس دیتابیس
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-secret")  # JWT_SECRET=کلید JWT (پیش‌فرض برای توسعه)
PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "change-me-pepper")  # PASSWORD_PEPPER=نمک سراسری
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))  # مدت اعتبار توکن دسترسی
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))  # مدت اعتبار رفرش
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))  # تعداد راند bcrypt
ALLOW_ORIGINS_ENV = os.getenv("ALLOW_ORIGINS", "*")  # دامنه‌های مجاز CORS

database = Database(DATABASE_URL)  # database=نمونه دیتابیس async
Base = declarative_base()  # Base=پایه ORM

# ——— مدل‌های ORM ———
class UserTable(Base):  # کلاس جدول کاربران
    __tablename__ = "users"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    phone = Column(String, unique=True, index=True)  # phone=شماره یکتا
    password_hash = Column(String)  # password_hash=هش پسورد
    address = Column(String)  # address=آدرس
    name = Column(String, default="")  # name=نام
    car_list = Column(JSONB, default=list)  # car_list=لیست ماشین‌ها (JSON)
    

class DriverTable(Base):  # کلاس جدول راننده‌ها
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

class RequestTable(Base):  # کلاس جدول درخواست‌ها/سفارش‌ها
    __tablename__ = "requests"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید
    user_phone = Column(String)  # user_phone=شماره کاربر
    latitude = Column(Float)  # latitude=عرض جغرافیایی
    longitude = Column(Float)  # longitude=طول جغرافیایی
    car_list = Column(JSONB)  # car_list=لیست ماشین‌ها (JSON)
    address = Column(String)  # address=آدرس
    home_number = Column(String, default="")  # home_number=پلاک منزل
    service_type = Column(String)  # service_type=کد انگلیسی سرویس (مثلاً carwash)
    price = Column(Integer)  # price=قیمت
    request_datetime = Column(String)  # request_datetime=زمان ثبت (String)
    status = Column(String)  # status=کد وضعیت (PENDING/ACTIVE/...)
    driver_name = Column(String)  # driver_name=نام راننده
    driver_phone = Column(String)  # driver_phone=شماره راننده
    finish_datetime = Column(String)  # finish_datetime=زمان پایان
    payment_type = Column(String)  # payment_type=کد انگلیسی پرداخت (cash/online)

class RefreshTokenTable(Base):  # کلاس جدول رفرش‌توکن‌ها
    __tablename__ = "refresh_tokens"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید
    user_id = Column(Integer, ForeignKey("users.id"), index=True)  # user_id=ارجاع به users.id
    token_hash = Column(String, unique=True, index=True)  # token_hash=هش رفرش‌توکن
    expires_at = Column(DateTime(timezone=True), index=True)  # expires_at=انقضا
    revoked = Column(Boolean, default=False)  # revoked=باطل شده؟
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at=زمان ایجاد
    __table_args__ = (Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),)  # ایندکس ترکیبی

# ——— مدل‌های Pydantic ———
class CarInfo(BaseModel):  # مدل ماشین برای API
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
    service_type: str  # کد انگلیسی سرویس
    price: int  # قیمت
    request_datetime: str  # زمان ثبت
    payment_type: str  # کد انگلیسی پرداخت

class CarListUpdateRequest(BaseModel):  # مدل به‌روزرسانی لیست ماشین‌ها
    user_phone: str  # شماره کاربر
    car_list: List[CarInfo]  # لیست ماشین‌ها

class CancelRequest(BaseModel):  # مدل لغو سفارش
    user_phone: str  # شماره کاربر
    service_type: str  # کد انگلیسی سرویس

class UserRegisterRequest(BaseModel):  # مدل ثبت‌نام کاربر
    phone: str  # شماره
    password: str  # رمز
    address: Optional[str] = None  # آدرس

class UserLoginRequest(BaseModel):  # مدل ورود
    phone: str  # شماره
    password: str  # رمز

class UserProfileUpdate(BaseModel):  # مدل ویرایش پروفایل
    phone: str  # شماره
    name: str = ""  # نام
    address: str = ""  # آدرس

# ——— توابع امنیت ———
def bcrypt_hash_password(password: str) -> str:  # تابع هش bcrypt
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)  # salt=نمک تصادفی
    mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # mixed=پسورد+pepper به بایت
    return bcrypt.hashpw(mixed, salt).decode("utf-8")  # خروجی=هش متن

def verify_password_secure(password: str, stored_hash: str) -> bool:  # تابع اعتبارسنجی پسورد
    try:  # try=جلوگیری از کرش
        if stored_hash.startswith("$2"):  # اگر=هش bcrypt
            mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # آماده‌سازی ورودی
            return bcrypt.checkpw(mixed, stored_hash.encode("utf-8"))  # چک bcrypt
        old = hashlib.sha256(password.encode("utf-8")).hexdigest()  # old=هش قدیمی sha256
        return old == stored_hash  # مقایسه
    except Exception:  # در خطا
        return False  # نتیجه=false

def create_access_token(phone: str) -> str:  # ساخت توکن دسترسی
    now = datetime.now(timezone.utc)  # زمان فعلی UTC
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # exp=انقضا
    payload = {"sub": phone, "type": "access", "exp": exp}  # payload=اطلاعات
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")  # encode=JWT

def create_refresh_token() -> str:  # ساخت رفرش‌توکن
    return secrets.token_urlsafe(48)  # توکن امن

def hash_refresh_token(token: str) -> str:  # هش رفرش‌توکن
    return hashlib.sha256((token + PASSWORD_PEPPER).encode("utf-8")).hexdigest()  # sha256 با pepper

def unified_response(status: str, code: str, message: str, data: Optional[dict] = None):  # پاسخ یکپارچه
    return {"status": status, "code": code, "message": message, "data": data or {}}  # دیکشنری پاسخ

# ——— اپ و CORS ———
app = FastAPI()  # app=نمونه FastAPI
allow_origins = ["*"] if ALLOW_ORIGINS_ENV.strip() == "*" else [o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()]  # allow_origins=دامنه‌ها
app.add_middleware(  # افزودن میدل‌ویر CORS
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ——— چرخه عمر ———
@app.on_event("startup")  # رویداد شروع
async def startup():  # تابع async شروع
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))  # engine=ساخت انجین sync برای create_all
    Base.metadata.create_all(engine)  # ساخت جداول
    await database.connect()  # اتصال دیتابیس

@app.on_event("shutdown")  # رویداد پایان
async def shutdown():  # تابع async پایان
    await database.disconnect()  # قطع اتصال

# ——— روت سلامت ———
@app.get("/")  # GET /
def read_root():  # تابع هندلر
    return {"message": "Putzfee FastAPI Server is running!"}  # پیام سالم بودن

# ——— اندپوینت‌ها ———
@app.get("/users/exists")  # GET وجود کاربر
async def user_exists(phone: str):  # phone=شماره
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == phone)  # q=کوئری شمارش
    count = await database.fetch_val(q)  # count=نتیجه
    exists = bool(count and int(count) > 0)  # exists=بولی
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "user exists check", {"exists": exists})  # پاسخ

@app.post("/register_user")  # POST ثبت‌نام
async def register_user(user: UserRegisterRequest):  # ورودی=مدل
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == user.phone)  # q=بررسی وجود
    count = await database.fetch_val(q)  # count=نتیجه
    if count and int(count) > 0:  # اگر=قبلاً وجود دارد
        raise HTTPException(status_code=400, detail="User already exists")  # خطا 400

    password_hash = bcrypt_hash_password(user.password)  # password_hash=هش پسورد
    ins = UserTable.__table__.insert().values(  # ins=کوئری درج
        phone=user.phone,
        password_hash=password_hash,
        address=(user.address or "").strip(),
        name="",
        car_list=[]
    )
    await database.execute(ins)  # اجرای درج
    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": user.phone})  # پاسخ

@app.post("/login")  # POST ورود
async def login_user(user: UserLoginRequest, request: Request):  # ورودی=مدل + request
    sel = UserTable.__table__.select().where(UserTable.phone == user.phone)  # sel=کوئری کاربر
    db_user = await database.fetch_one(sel)  # db_user=کاربر
    if not db_user:  # اگر=یافت نشد
        raise HTTPException(status_code=404, detail="User not found")  # 404

    if not verify_password_secure(user.password, db_user["password_hash"]):  # اگر=پسورد غلط
        raise HTTPException(status_code=401, detail="Invalid password")  # 401

    if not db_user["password_hash"].startswith("$2"):  # اگر=هش قدیمی
        new_hash = bcrypt_hash_password(user.password)  # new_hash=هش جدید
        upd = UserTable.__table__.update().where(UserTable.id == db_user["id"]).values(password_hash=new_hash)  # upd=آپدیت
        await database.execute(upd)  # اجرا

    access_token = create_access_token(db_user["phone"])  # access_token=ساخت JWT
    refresh_token = create_refresh_token()  # refresh_token=ساخت رفرش
    refresh_hash = hash_refresh_token(refresh_token)  # refresh_hash=هش رفرش
    refresh_exp = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)  # refresh_exp=انقضا

    ins_rt = RefreshTokenTable.__table__.insert().values(  # درج رفرش‌توکن
        user_id=db_user["id"], token_hash=refresh_hash, expires_at=refresh_exp, revoked=False
    )
    await database.execute(ins_rt)  # اجرا

    mapping = getattr(db_user, "_mapping", {})  # mapping=سازگاری
    name_val = mapping["name"] if "name" in mapping else ""  # name_val=نام
    address_val = mapping["address"] if "address" in mapping else ""  # address_val=آدرس

    return {
        "status": "ok", "message": "Login successful", "token": access_token, "access_token": access_token,
        "refresh_token": refresh_token,
        "user": { "phone": db_user["phone"], "address": address_val or "", "name": name_val or "" }
    }  # پاسخ ورود

@app.post("/auth/refresh")  # POST رفرش توکن
async def refresh_access_token(req: dict):  # req=بدنه خام
    refresh_token = req.get("refresh_token", "")  # refresh_token=گرفتن از بدنه
    if not refresh_token: raise HTTPException(status_code=400, detail="refresh_token required")  # بدون رفرش → 400
    token_hash = hash_refresh_token(refresh_token)  # token_hash=هش
    now = datetime.now(timezone.utc)  # now=اکنون
    sel = RefreshTokenTable.__table__.select().where(  # sel=کوئری رفرش معتبر
        (RefreshTokenTable.token_hash == token_hash) & (RefreshTokenTable.revoked == False) & (RefreshTokenTable.expires_at > now)
    )
    rt = await database.fetch_one(sel)  # rt=رکورد
    if not rt: raise HTTPException(status_code=401, detail="Invalid refresh token")  # نامعتبر → 401
    sel_user = UserTable.__table__.select().where(UserTable.id == rt["user_id"])  # sel_user=کوئری کاربر
    db_user = await database.fetch_one(sel_user)  # db_user=کاربر
    if not db_user: raise HTTPException(status_code=401, detail="Invalid refresh token")  # نبود کاربر → 401
    new_access = create_access_token(db_user["phone"])  # new_access=ساخت JWT جدید
    return unified_response("ok", "TOKEN_REFRESHED", "new access token", {"access_token": new_access})  # پاسخ

@app.get("/verify_token/{token}")  # GET بررسی توکن با مسیر
async def verify_token_path(token: str):  # token=مسیر
    try:
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # decode=اعتبارسنجی
        return {"status": "ok", "valid": True}  # معتبر
    except jwt.ExpiredSignatureError:
        return {"status": "error", "valid": False, "code": "TOKEN_EXPIRED"}  # منقضی
    except Exception:
        return {"status": "error", "valid": False, "code": "TOKEN_INVALID"}  # نامعتبر

@app.get("/verify_token")  # GET بررسی توکن با هدر Authorization
async def verify_token_header(authorization: Optional[str] = Header(None)):  # authorization=هدر
    if not authorization or not authorization.lower().startswith("bearer "):  # نبود هدر صحیح
        return {"status": "error", "valid": False, "code": "NO_AUTH_HEADER"}  # کد خطا
    token = authorization.split(" ", 1)[1].strip()  # token=جدا کردن
    try:
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # decode=چک
        return {"status": "ok", "valid": True}  # معتبر
    except jwt.ExpiredSignatureError:
        return {"status": "error", "valid": False, "code": "TOKEN_EXPIRED"}  # منقضی
    except Exception:
        return {"status": "error", "valid": False, "code": "TOKEN_INVALID"}  # نامعتبر

@app.get("/user_cars/{user_phone}")  # GET لیست ماشین‌های کاربر
async def get_user_cars(user_phone: str):  # user_phone=مسیر
    query = UserTable.__table__.select().where(UserTable.phone == user_phone)  # query=کوئری کاربر
    user = await database.fetch_one(query)  # user=نتیجه
    if user: return user["car_list"] or []  # در صورت وجود=برگرداندن لیست
    raise HTTPException(status_code=404, detail="User not found")  # نبود=404

@app.post("/user_cars")  # POST ذخیره لیست ماشین‌ها
async def update_user_cars(data: CarListUpdateRequest):  # data=بدنه
    sel = UserTable.__table__.select().where(UserTable.phone == data.user_phone)  # sel=کوئری کاربر
    user = await database.fetch_one(sel)  # user=نتیجه
    if not user: raise HTTPException(status_code=404, detail="User not found")  # نبود=404
    upd = UserTable.__table__.update().where(UserTable.phone == data.user_phone).values(  # upd=آپدیت
        car_list=[car.dict() for car in data.car_list]  # car_list=لیست دیکشنری‌ها
    )
    await database.execute(upd)  # اجرا
    return {"status": "ok", "message": "cars saved"}  # پاسخ

@app.post("/order")  # POST ثبت سفارش
async def create_order(order: OrderRequest):  # order=بدنه
    ins = RequestTable.__table__.insert().values(  # ins=درج سفارش
        user_phone=order.user_phone,
        latitude=order.location.latitude,
        longitude=order.location.longitude,
        car_list=[car.dict() for car in order.car_list],
        address=order.address.strip(),
        home_number=(order.home_number or "").strip(),
        service_type=order.service_type,  # service_type=کد انگلیسی از کلاینت
        price=order.price,
        request_datetime=order.request_datetime,
        status="PENDING",  # status=کد انگلیسی ثابت
        payment_type=order.payment_type.strip().lower()  # payment_type=کد انگلیسی از کلاینت
    )
    await database.execute(ins)  # اجرا
    return {"status": "ok", "message": "request created"}  # پاسخ

@app.post("/cancel_order")  # POST لغو سفارش
async def cancel_order(cancel: CancelRequest):  # cancel=بدنه
    # استفاده از RETURNING برای تشخیص قطعی تعداد رکوردهای آپدیت‌شده
    upd = (  # upd=کوئری آپدیت با RETURNING
        RequestTable.__table__.update()
        .where(
            (RequestTable.user_phone == cancel.user_phone) &  # شرط=بر اساس شماره کاربر
            (RequestTable.service_type == cancel.service_type) &  # شرط=بر اساس کد انگلیسی سرویس
            (RequestTable.status.in_(["PENDING", "ACTIVE"]))  # شرط=فقط وضعیت‌های فعال
        )
        .values(status="CANCELED")  # مقداردهی=تغییر وضعیت به CANCELED
        .returning(RequestTable.id)  # returning=شناسه‌های تغییر یافته (برای تشخیص موفقیت)
    )
    rows = await database.fetch_all(upd)  # rows=لیست رکوردهای تغییر یافته
    if rows and len(rows) > 0:  # وجود حداقل یک رکورد تغییر یافته
        return {"status": "ok", "message": "canceled"}  # پاسخ موفق
    raise HTTPException(status_code=404, detail="active order not found")  # نبود رکورد فعال=404

@app.get("/user_active_services/{user_phone}")  # GET سرویس‌های فعال کاربر
async def get_user_active_services(user_phone: str):  # user_phone=مسیر
    sel = RequestTable.__table__.select().where(
        (RequestTable.user_phone == user_phone) &
        (RequestTable.status.in_(["PENDING", "ACTIVE"]))
    )
    result = await database.fetch_all(sel)  # result=لیست
    return [dict(row) for row in result]  # خروجی=لیست دیکشنری

@app.get("/user_orders/{user_phone}")  # GET همه سفارش‌های کاربر
async def get_user_orders(user_phone: str):  # user_phone=مسیر
    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)  # sel=کوئری
    result = await database.fetch_all(sel)  # result=لیست
    return [dict(row) for row in result]  # برگرداندن لیست دیکشنری

@app.post("/user/profile")  # POST ذخیره پروفایل
async def update_profile(body: UserProfileUpdate):  # body=بدنه
    if not body.phone.strip():  # اعتبارسنجی=شماره لازم
        raise HTTPException(status_code=400, detail="phone_required")  # 400
    sel = UserTable.__table__.select().where(UserTable.phone == body.phone)  # sel=کاربر
    user = await database.fetch_one(sel)  # user=نتیجه
    if user is None:  # نبود کاربر
        raise HTTPException(status_code=404, detail="User not found")  # 404
    else:
        upd = UserTable.__table__.update().where(UserTable.phone == body.phone).values(  # upd=آپدیت
            name=body.name.strip(),
            address=body.address.strip()
        )
        await database.execute(upd)  # اجرا
    return unified_response("ok", "PROFILE_UPDATED", "profile saved", {"phone": body.phone})  # پاسخ

@app.get("/user/profile/{phone}")  # GET دریافت پروفایل
async def get_user_profile(phone: str):  # phone=مسیر
    sel = UserTable.__table__.select().where(UserTable.phone == phone)  # sel=کوئری
    db_user = await database.fetch_one(sel)  # db_user=نتیجه
    if db_user is None:  # نبود کاربر
        raise HTTPException(status_code=404, detail="User not found")  # 404
    mapping = getattr(db_user, "_mapping", {})  # mapping=سازگاری
    name_val = mapping["name"] if "name" in mapping else ""  # name_val
    address_val = mapping["address"] if "address" in mapping else ""  # address_val
    return unified_response("ok", "PROFILE_FETCHED", "profile data", {  # پاسخ
        "phone": db_user["phone"], "name": name_val or "", "address": address_val or ""
    })

@app.get("/debug/users")  # GET دیباگ کاربران
async def debug_users():  # تابع
    rows = await database.fetch_all(UserTable.__table__.select())  # rows=همه کاربران
    out = []  # out=لیست خروجی
    for r in rows:  # حلقه=هر کاربر
        mapping = getattr(r, "_mapping", {})  # mapping=سازگاری
        name_val = mapping["name"] if "name" in mapping else ""  # name
        address_val = mapping["address"] if "address" in mapping else ""  # address
        out.append({"id": r["id"], "phone": r["phone"], "name": name_val, "address": address_val})  # افزودن ردیف
    return out  # خروجی

