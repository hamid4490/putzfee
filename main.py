# -*- coding: utf-8 -*-  # کدینگ فایل=یونیکد
# FastAPI server (orders + hourly scheduling + DB notifications + FCM push)  # توضیح=سرور سفارش/زمان‌بندی با اعلان‌های DB و پوش

import os  # ماژول=سیستم/مسیر
import hashlib  # ماژول=هش امن
import secrets  # ماژول=توکن امن
from datetime import datetime, timedelta, timezone  # کلاس‌ها=تاریخ/زمان | timedelta=بازه | timezone=منطقه زمانی
from typing import Optional, List, Dict  # نوع‌دهی=اختیاری/لیست/دیکشنری

import bcrypt  # کتابخانه=هش bcrypt
import jwt  # کتابخانه=توکن JWT
from fastapi import FastAPI, HTTPException, Request, Header  # FastAPI=چارچوب | HTTPException=خطا | Request/Header=درخواست/هدر
from fastapi.middleware.cors import CORSMiddleware  # CORS=میان‌افزار مجوز مبداها
from pydantic import BaseModel  # BaseModel=مدل‌های ورودی/خروجی

from sqlalchemy import (  # SQLAlchemy=ORM/SQL
    Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Index, select, func, and_, text, UniqueConstraint  # اجزای ORM/SQL
)
from sqlalchemy.dialects.postgresql import JSONB  # JSONB=نوع JSON باینری
from sqlalchemy.ext.declarative import declarative_base  # declarative_base=پایه ORM
import sqlalchemy  # sqlalchemy=پکیج اصلی ORM/SQL
from databases import Database  # databases=اتصال async به DB
from dotenv import load_dotenv  # load_dotenv=خواندن .env
import httpx  # httpx=کلاینت HTTP async برای FCM

# -------------------- Config --------------------
load_dotenv()  # بارگذاری متغیرهای محیطی از .env
DATABASE_URL = os.getenv("DATABASE_URL")  # آدرس اتصال پایگاه‌داده
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-secret")  # کلید امضای JWT
PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "change-me-pepper")  # pepper رمز
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))  # مدت اعتبار توکن دسترسی (دقیقه)
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))  # مدت اعتبار رفرش‌توکن (روز)
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))  # دورهای bcrypt
ALLOW_ORIGINS_ENV = os.getenv("ALLOW_ORIGINS", "*")  # مبداهای مجاز CORS

LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "300"))  # پنجره شمارش تلاش ورود (ثانیه)
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))  # حداکثر تلاش ورود
LOGIN_LOCK_SECONDS = int(os.getenv("LOGIN_LOCK_SECONDS", "900"))  # مدت قفل پس از اتمام تلاش (ثانیه)

FCM_SERVER_KEY = os.getenv("FCM_SERVER_KEY", "")  # کلید سرور FCM برای ارسال پوش

database = Database(DATABASE_URL)  # نمونه اتصال async DB
Base = declarative_base()  # پایه مدل‌های ORM

# -------------------- ORM models --------------------
class UserTable(Base):  # مدل=جدول کاربران
    __tablename__ = "users"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # ستون=id کلید اصلی
    phone = Column(String, unique=True, index=True)  # ستون=phone یکتا با ایندکس
    password_hash = Column(String)  # ستون=hash رمز
    address = Column(String)  # ستون=آدرس
    name = Column(String, default="")  # ستون=نام
    car_list = Column(JSONB, default=list)  # ستون=لیست ماشین‌ها (JSONB)

class DriverTable(Base):  # مدل=سرویس‌گیرنده‌ها
    __tablename__ = "drivers"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    first_name = Column(String)  # نام
    last_name = Column(String)  # نام‌خانوادگی
    photo_url = Column(String)  # آدرس عکس
    id_card_number = Column(String)  # کد ملی
    phone = Column(String, unique=True, index=True)  # شماره
    phone_verified = Column(Boolean, default=False)  # تأیید شماره
    is_online = Column(Boolean, default=False)  # آنلاین؟
    status = Column(String, default="فعال")  # وضعیت

class RequestTable(Base):  # مدل=سفارش‌ها
    __tablename__ = "requests"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    user_phone = Column(String, index=True)  # user_phone=شماره کاربر
    latitude = Column(Float)  # latitude=عرض جغرافیایی
    longitude = Column(Float)  # longitude=طول جغرافیایی
    car_list = Column(JSONB)  # car_list=لیست خدمات/ماشین‌ها
    address = Column(String)  # address=آدرس
    home_number = Column(String, default="")  # home_number=پلاک
    service_type = Column(String, index=True)  # service_type=نوع سرویس
    price = Column(Integer)  # price=قیمت
    request_datetime = Column(String)  # request_datetime=زمان ثبت
    status = Column(String)  # status=NEW/WAITING/ASSIGNED/IN_PROGRESS/STARTED/FINISH/CANCELED
    driver_name = Column(String)  # driver_name=نام سرویس‌گیرنده
    driver_phone = Column(String)  # driver_phone=شماره سرویس‌گیرنده
    finish_datetime = Column(String)  # finish_datetime=زمان پایان
    payment_type = Column(String)  # payment_type=نوع پرداخت
    scheduled_start = Column(DateTime(timezone=True), nullable=True)  # scheduled_start=شروع قطعی (اختیاری)
    service_place = Column(String, default="client")  # service_place=محل سرویس

class RefreshTokenTable(Base):  # مدل=رفرش‌توکن‌ها
    __tablename__ = "refresh_tokens"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    user_id = Column(Integer, ForeignKey("users.id"), index=True)  # user_id=ارجاع کاربر
    token_hash = Column(String, unique=True, index=True)  # token_hash=هش رفرش‌توکن
    expires_at = Column(DateTime(timezone=True), index=True)  # expires_at=انقضا
    revoked = Column(Boolean, default=False)  # revoked=باطل؟
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at=ایجاد
    __table_args__ = (Index("ix_refresh_token_user_id_expires", "user_id", "expires_at"),)  # ایندکس مرکب

class LoginAttemptTable(Base):  # مدل=تلاش‌های ورود
    __tablename__ = "login_attempts"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    phone = Column(String, index=True)  # phone=شماره
    ip = Column(String, index=True)  # ip=آی‌پی
    attempt_count = Column(Integer, default=0)  # attempt_count=تعداد تلاش
    window_start = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # window_start=شروع پنجره
    locked_until = Column(DateTime(timezone=True), nullable=True)  # locked_until=قفل تا
    last_attempt_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # last_attempt_at=آخرین تلاش
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at=ایجاد
    __table_args__ = (Index("ix_login_attempt_phone_ip", "phone", "ip"),)  # ایندکس مرکب

class ScheduleSlotTable(Base):  # مدل=اسلات‌های پیشنهادی
    __tablename__ = "schedule_slots"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)  # request_id=ارجاع سفارش
    provider_phone = Column(String, index=True)  # provider_phone=شماره سرویس‌گیرنده
    slot_start = Column(DateTime(timezone=True), index=True)  # slot_start=شروع بازه
    status = Column(String, default="PROPOSED")  # status=PROPOSED/ACCEPTED/REJECTED
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at=ایجاد
    __table_args__ = (Index("ix_schedule_slots_req_status", "request_id", "status"),)  # ایندکس مرکب

class AppointmentTable(Base):  # مدل=نوبت‌های قطعی
    __tablename__ = "appointments"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    provider_phone = Column(String, index=True)  # provider_phone=شماره سرویس‌گیرنده
    request_id = Column(Integer, ForeignKey("requests.id"), index=True)  # request_id=ارجاع سفارش
    start_time = Column(DateTime(timezone=True), index=True)  # start_time=شروع
    end_time = Column(DateTime(timezone=True), index=True)  # end_time=پایان
    status = Column(String, default="BOOKED")  # status=BOOKED/CANCELLED
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at=ایجاد
    __table_args__ = (
        UniqueConstraint("provider_phone", "start_time", "end_time", name="uq_provider_slot"),  # Unique=جلوگیری تداخل
        Index("ix_provider_time", "provider_phone", "start_time", "end_time"),  # Index=ایندکس
    )

class NotificationTable(Base):  # مدل=اعلان‌ها (ذخیره در DB)
    __tablename__ = "notifications"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    user_phone = Column(String, index=True)  # user_phone=شماره کاربر گیرنده
    title = Column(String)  # title=عنوان اعلان
    body = Column(String)  # body=متن اعلان
    data = Column(JSONB, default=dict)  # data=اطلاعات اضافی (JSONB)
    read = Column(Boolean, default=False, index=True)  # read=خوانده‌شده؟
    read_at = Column(DateTime(timezone=True), nullable=True)  # read_at=زمان خوانده‌شدن
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)  # created_at=زمان ایجاد
    __table_args__ = (Index("ix_notifs_user_read_created", "user_phone", "read", "created_at"),)  # ایندکس مرکب

class DeviceTokenTable(Base):  # مدل=توکن‌های پوش دستگاه
    __tablename__ = "device_tokens"  # نام جدول
    id = Column(Integer, primary_key=True, index=True)  # id=کلید اصلی
    token = Column(String, unique=True, index=True)  # token=توکن FCM یکتا
    role = Column(String, index=True)  # role=نقش گیرنده (manager/user)
    platform = Column(String, default="android", index=True)  # platform=اندروید/…
    user_phone = Column(String, nullable=True)  # user_phone=شماره کاربر (اختیاری)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # created_at=زمان ایجاد
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # updated_at=آخرین به‌روزرسانی
    __table_args__ = (Index("ix_tokens_role_platform", "role", "platform"),)  # ایندکس مرکب

# -------------------- Pydantic models --------------------
class CarInfo(BaseModel):  # مدل=ماشین ساده
    brand: str  # برند
    model: str  # مدل
    plate: str  # پلاک

class Location(BaseModel):  # مدل=مختصات
    latitude: float  # عرض
    longitude: float  # طول

class CarOrderItem(BaseModel):  # مدل=گزینه‌های سفارش
    brand: str  # برند
    model: str  # مدل
    plate: str  # پلاک
    wash_outside: bool = False  # روشویی
    wash_inside: bool = False  # توشویی
    polish: bool = False  # پولیش

class OrderRequest(BaseModel):  # مدل=ثبت سفارش
    user_phone: str  # شماره کاربر
    location: Location  # مختصات
    car_list: List[CarOrderItem]  # خدمات
    address: str  # آدرس
    home_number: Optional[str] = ""  # پلاک
    service_type: str  # نوع سرویس
    price: int  # قیمت
    request_datetime: str  # زمان ثبت
    payment_type: str  # نوع پرداخت
    service_place: str  # محل انجام

class CarListUpdateRequest(BaseModel):  # مدل=آپدیت ماشین‌های کاربر
    user_phone: str  # شماره
    car_list: List[CarInfo]  # ماشین‌ها

class CancelRequest(BaseModel):  # مدل=لغو سفارش
    user_phone: str  # شماره
    service_type: str  # نوع سرویس

class UserRegisterRequest(BaseModel):  # مدل=ثبت‌نام
    phone: str  # شماره
    password: str  # رمز
    address: Optional[str] = None  # آدرس

class UserLoginRequest(BaseModel):  # مدل=ورود
    phone: str  # شماره
    password: str  # رمز

class UserProfileUpdate(BaseModel):  # مدل=آپدیت پروفایل
    phone: str  # شماره
    name: str = ""  # نام
    address: str = ""  # آدرس

class ProposedSlotsRequest(BaseModel):  # مدل=ارسال اسلات‌ها
    provider_phone: str  # شماره سرویس‌گیرنده
    slots: List[str]  # لیست شروع‌های یک‌ساعته (ISO)

class ConfirmSlotRequest(BaseModel):  # مدل=تأیید اسلات
    slot: str  # شروع ISO انتخاب‌شده

class PriceBody(BaseModel):  # مدل=ثبت قیمت/توافق
    price: int  # قیمت
    agree: bool  # توافق؟

class PushRegister(BaseModel):  # مدل=ثبت توکن پوش
    role: str  # نقش
    token: str  # توکن
    platform: str = "android"  # پلتفرم
    user_phone: Optional[str] = None  # شماره کاربر (اختیاری)

# -------------------- Security helpers --------------------
def bcrypt_hash_password(password: str) -> str:  # تابع=هش رمز با bcrypt+pepper
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)  # تولید نمک bcrypt
    mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # ترکیب رمز+pepper
    return bcrypt.hashpw(mixed, salt).decode("utf-8")  # خروجی=هش

def verify_password_secure(password: str, stored_hash: str) -> bool:  # تابع=اعتبارسنجی رمز
    try:  # try
        if stored_hash.startswith("$2"):  # اگر فرمت bcrypt است
            mixed = (password + PASSWORD_PEPPER).encode("utf-8")  # ترکیب
            return bcrypt.checkpw(mixed, stored_hash.encode("utf-8"))  # بررسی bcrypt
        old = hashlib.sha256(password.encode("utf-8")).hexdigest()  # هش قدیمی
        return old == stored_hash  # مقایسه
    except Exception:  # خطا
        return False  # بازگشت False

def create_access_token(phone: str) -> str:  # تابع=ساخت JWT دسترسی
    now = datetime.now(timezone.utc)  # اکنون UTC
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # انقضا
    payload = {"sub": phone, "type": "access", "exp": exp}  # payload=داده توکن
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")  # امضا و خروجی

def create_refresh_token() -> str:  # تابع=ساخت رفرش‌توکن
    return secrets.token_urlsafe(48)  # خروجی=توکن تصادفی

def hash_refresh_token(token: str) -> str:  # تابع=هش رفرش‌توکن
    return hashlib.sha256((token + PASSWORD_PEPPER).encode("utf-8")).hexdigest()  # sha256

def unified_response(status: str, code: str, message: str, data: Optional[dict] = None):  # تابع=قالب پاسخ
    return {"status": status, "code": code, "message": message, "data": data or {}}  # دیکشنری پاسخ

# -------------------- Utils --------------------
def get_client_ip(request: Request) -> str:  # تابع=گرفتن IP کلاینت
    xff = request.headers.get("x-forwarded-for", "")  # خواندن هدر x-forwarded-for
    if xff:  # اگر هدر وجود داشت
        return xff.split(",")[0].strip()  # بازگشت اولین IP
    return request.client.host or "unknown"  # بازگشت IP مستقیم یا unknown

def parse_iso(ts: str) -> datetime:  # تابع=پارس رشته ISO به datetime «محلی بدون شیفت»
    """
    ورودی‌های قابل قبول:
    - 2025-09-09T10:00
    - 2025-09-09T10:00:00
    - 2025-09-09T10:00:00Z
    - 2025-09-09T10:00:00+03:30
    خروجی: datetime با tzinfo=UTC اما بدون اعمال هیچ شیفتی (همان اعداد محلی ذخیره می‌شوند)
    """
    try:  # try=پارس ورودی
        raw = ts.strip()  # raw=پاکسازی فاصله‌ها
        if "T" not in raw:  # اگر=فرمت نادرست
            raise ValueError("no T in ISO")  # خطا=عدم وجود T
        date_part, time_part = raw.split("T", 1)  # جداکردن تاریخ/زمان
        time_part = time_part.replace("Z", "")  # حذف Z در انتها
        for sign in ["+", "-"]:  # حلقه=علامت‌های offset
            idx = time_part.find(sign)  # idx=محل علامت
            if idx > 0:  # اگر=offset وجود دارد
                time_part = time_part[:idx]  # بریدن بخش offset
                break  # خروج از حلقه
        if time_part.count(":") == 1:  # اگر=فقط HH:MM
            time_part = f"{time_part}:00"  # افزودن :00 ثانیه
        y, m, d = map(int, date_part.split("-"))  # پارس تاریخ
        hh, mm, ss = map(int, time_part.split(":"))  # پارس زمان
        dt = datetime(y, m, d, hh, mm, ss, tzinfo=timezone.utc)  # dt=شیء datetime با UTC اما بدون شیفت
        return dt  # بازگشت=همان اعداد محلی
    except Exception:  # خطا در پارس
        raise HTTPException(status_code=400, detail=f"invalid datetime: {ts}")  # برگرداندن خطا 400

async def provider_is_free(provider_phone: str, start: datetime, end: datetime) -> bool:  # تابع=بررسی خالی بودن بازه
    q = AppointmentTable.__table__.select().where(  # q=انتخاب رزروهای BOOKED متداخل
        (AppointmentTable.provider_phone == provider_phone) &
        (AppointmentTable.status == "BOOKED") &
        (AppointmentTable.start_time < end) &
        (AppointmentTable.end_time > start)
    )  # پایان شرط‌ها
    rows = await database.fetch_all(q)  # اجرا
    return len(rows) == 0  # True=آزاد است

async def notify_user(phone: str, title: str, body: str, data: Optional[dict] = None):  # تابع=ثبت اعلان برای کاربر در DB
    ins = NotificationTable.__table__.insert().values(  # دستور=درج اعلان
        user_phone=phone,  # شماره گیرنده
        title=title,  # عنوان
        body=body,  # متن
        data=(data or {}),  # داده‌های اضافی
        read=False,  # خوانده نشده
        created_at=datetime.now(timezone.utc)  # زمان ایجاد
    )  # پایان values
    await database.execute(ins)  # اجرا=درج

# -------------------- Push helpers (FCM) --------------------
async def get_manager_tokens() -> List[str]:  # تابع=گرفتن توکن‌های نقش مدیر
    sel = DeviceTokenTable.__table__.select().where(  # sel=انتخاب ردیف‌های نقش مدیر/اندروید
        (DeviceTokenTable.role == "manager") & (DeviceTokenTable.platform == "android")
    )  # پایان where
    rows = await database.fetch_all(sel)  # اجرا
    tokens = []  # لیست توکن‌ها
    seen = set()  # مجموعه=حذف تکراری
    for r in rows:  # حلقه روی ردیف‌ها
        t = r["token"]  # t=توکن
        if t and t not in seen:  # اگر=نو و غیرخالی
            seen.add(t)  # ثبت در مجموعه
            tokens.append(t)  # افزودن به لیست
    return tokens  # بازگشت لیست

async def send_push_to_tokens(tokens: List[str], title: str, body: str, data: Optional[dict] = None):  # تابع=ارسال پوش به لیست توکن
    if not FCM_SERVER_KEY or not tokens:  # اگر=کلید FCM یا لیست خالی
        return  # خروج
    url = "https://fcm.googleapis.com/fcm/send"  # url=آدرس legacy FCM
    headers = {  # headers=هدرهای درخواست
        "Authorization": f"key={FCM_SERVER_KEY}",  # Authorization=کلید سرور
        "Content-Type": "application/json"  # Content-Type=JSON
    }  # پایان headers
    async with httpx.AsyncClient(timeout=10.0) as client:  # AsyncClient=کلاینت HTTP async
        for t in tokens:  # حلقه روی توکن‌ها
            payload = {  # payload=بدنه ارسال
                "to": t,  # to=توکن مقصد
                "priority": "high",  # priority=اولویت بالا
                "notification": {  # notification=بخش نمایش اعلان توسط سیستم
                    "title": title,  # title=عنوان
                    "body": body,  # body=متن
                    "android_channel_id": "putz_manager_general"  # android_channel_id=شناسه کانال
                },  # پایان notification
                "data": data or {}  # data=داده‌های الحاقی (برای رفتار اپ)
            }  # پایان payload
            try:  # try=ارسال
                await client.post(url, headers=headers, json=payload)  # ارسال=POST به FCM
            except Exception:  # خطا
                pass  # نادیده گرفتن خطا برای تک توکن

async def send_push_to_managers(title: str, body: str, data: Optional[dict] = None):  # تابع=ارسال پوش به مدیران
    tokens = await get_manager_tokens()  # tokens=خواندن توکن‌های مدیر
    await send_push_to_tokens(tokens, title, body, data)  # ارسال=فراخوانی ارسال به لیست

# -------------------- App & CORS --------------------
app = FastAPI()  # نمونه برنامه FastAPI
allow_origins = ["*"] if ALLOW_ORIGINS_ENV.strip() == "*" else [o.strip() for o in ALLOW_ORIGINS_ENV.split(",") if o.strip()]  # لیست مبداها
app.add_middleware(  # افزودن میان‌افزار CORS
    CORSMiddleware,  # کلاس CORS
    allow_origins=allow_origins,  # مبداهای مجاز
    allow_credentials=True,  # اجازه کوکی
    allow_methods=["*"],  # تمام متدها
    allow_headers=["*"],  # تمام هدرها
)

# -------------------- Startup/Shutdown --------------------
@app.on_event("startup")  # رویداد=شروع
async def startup():  # تابع=راه‌اندازی
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))  # موتور sync برای create_all
    Base.metadata.create_all(engine)  # ساخت جداول (در صورت نبود)
    with engine.begin() as conn:  # شروع تراکنش
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS scheduled_start TIMESTAMPTZ NULL;"))  # تضمین ستون scheduled_start
        conn.execute(text("ALTER TABLE requests ADD COLUMN IF NOT EXISTS service_place TEXT DEFAULT 'client';"))  # تضمین ستون service_place
    await database.connect()  # اتصال به DB

@app.on_event("shutdown")  # رویداد=پایان
async def shutdown():  # تابع=خاموشی
    await database.disconnect()  # قطع اتصال DB

# -------------------- Health --------------------
@app.get("/")  # مسیر=ریشه
def read_root():  # تابع=سلامتی
    return {"message": "Putzfee FastAPI Server is running!"}  # پاسخ=وضعیت OK

# -------------------- Push endpoints --------------------
@app.post("/push/register")  # مسیر=ثبت توکن پوش دستگاه
async def register_push_token(body: PushRegister, request: Request):  # تابع=ثبت/به‌روزرسانی توکن
    now = datetime.now(timezone.utc)  # now=اکنون UTC
    sel = DeviceTokenTable.__table__.select().where(DeviceTokenTable.token == body.token)  # sel=یافتن توکن
    row = await database.fetch_one(sel)  # row=نتیجه
    if row is None:  # اگر=وجود ندارد
        ins = DeviceTokenTable.__table__.insert().values(  # ins=درج رکورد جدید
            token=body.token, role=body.role, platform=body.platform, user_phone=body.user_phone, created_at=now, updated_at=now
        )  # پایان values
        await database.execute(ins)  # اجرا
    else:  # اگر=وجود دارد
        upd = DeviceTokenTable.__table__.update().where(DeviceTokenTable.id == row["id"]).values(  # upd=به‌روزرسانی
            role=body.role, platform=body.platform, user_phone=body.user_phone or row["user_phone"], updated_at=now
        )  # پایان values
        await database.execute(upd)  # اجرا
    return unified_response("ok", "TOKEN_REGISTERED", "registered", {"role": body.role})  # پاسخ

# -------------------- Auth/User --------------------
@app.get("/users/exists")  # مسیر=بررسی وجود کاربر
async def user_exists(phone: str):  # تابع=ورودی phone
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == phone)  # کوئری شمارش
    count = await database.fetch_val(q)  # اجرا
    exists = bool(count and int(count) > 0)  # بولین=وجود؟
    return unified_response("ok", "USER_EXISTS" if exists else "USER_NOT_FOUND", "user exists check", {"exists": exists})  # پاسخ

@app.post("/register_user")  # مسیر=ثبت‌نام
async def register_user(user: UserRegisterRequest):  # تابع=ثبت‌نام
    q = select(func.count()).select_from(UserTable).where(UserTable.phone == user.phone)  # بررسی تکرار
    count = await database.fetch_val(q)  # اجرا
    if count and int(count) > 0:  # اگر وجود دارد
        raise HTTPException(status_code=400, detail="User already exists")  # خطا=کاربر موجود
    password_hash = bcrypt_hash_password(user.password)  # تولید هش bcrypt
    ins = UserTable.__table__.insert().values(phone=user.phone, password_hash=password_hash, address=(user.address or "").strip(), name="", car_list=[])  # درج کاربر
    await database.execute(ins)  # اجرا
    return unified_response("ok", "USER_REGISTERED", "registered", {"phone": user.phone})  # پاسخ موفق

@app.post("/login")  # مسیر=ورود
async def login_user(user: UserLoginRequest, request: Request):  # تابع=ورود
    now = datetime.now(timezone.utc)  # اکنون UTC
    client_ip = get_client_ip(request)  # IP کلاینت

    sel_attempt = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == user.phone, LoginAttemptTable.ip == client_ip))  # رکورد تلاش
    attempt_row = await database.fetch_one(sel_attempt)  # اجرا
    if attempt_row and attempt_row["locked_until"] and attempt_row["locked_until"] > now:  # قفل فعال؟
        retry_after = int((attempt_row["locked_until"] - now).total_seconds())  # زمان باقی
        raise HTTPException(status_code=429, detail={"code": "RATE_LIMITED", "lock_remaining": retry_after})  # خطا

    sel_user = UserTable.__table__.select().where(UserTable.phone == user.phone)  # یافتن کاربر
    db_user = await database.fetch_one(sel_user)  # اجرا
    if not db_user:  # نبود کاربر
        await _register_login_failure(user.phone, client_ip)  # ثبت شکست
        raise HTTPException(status_code=404, detail={"code": "USER_NOT_FOUND"})  # خطا

    if not verify_password_secure(user.password, db_user["password_hash"]):  # رمز غلط؟
        await _register_login_failure(user.phone, client_ip)  # ثبت شکست
        raise HTTPException(status_code=401, detail={"code": "WRONG_PASSWORD"})  # خطا

    await _register_login_success(user.phone, client_ip)  # ثبت موفقیت

    if not db_user["password_hash"].startswith("$2"):  # اگر هش قدیمی است
        new_hash = bcrypt_hash_password(user.password)  # هش جدید
        upd = UserTable.__table__.update().where(UserTable.id == db_user["id"]).values(password_hash=new_hash)  # آپدیت
        await database.execute(upd)  # اجرا

    access_token = create_access_token(db_user["phone"])  # ساخت توکن دسترسی
    refresh_token = create_refresh_token()  # ساخت رفرش
    refresh_hash = hash_refresh_token(refresh_token)  # هش رفرش
    refresh_exp = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)  # انقضا رفرش
    ins_rt = RefreshTokenTable.__table__.insert().values(user_id=db_user["id"], token_hash=refresh_hash, expires_at=refresh_exp, revoked=False)  # درج رفرش‌توکن
    await database.execute(ins_rt)  # اجرا

    mapping = getattr(db_user, "_mapping", {})  # سازگاری RowMapping
    name_val = mapping["name"] if "name" in mapping else ""  # نام
    address_val = mapping["address"] if "address" in mapping else ""  # آدرس

    return {  # پاسخ=ورود موفق
        "status": "ok", "access_token": access_token, "refresh_token": refresh_token,  # توکن‌ها
        "user": {"phone": db_user["phone"], "address": address_val or "", "name": name_val or ""}  # کاربر
    }

async def _register_login_failure(phone: str, ip: str):  # تابع=ثبت شکست ورود
    now = datetime.now(timezone.utc)  # اکنون
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))  # رکورد
    row = await database.fetch_one(sel)  # اجرا
    if row is None:  # اگر رکوردی نیست
        ins = LoginAttemptTable.__table__.insert().values(phone=phone, ip=ip, attempt_count=1, window_start=now, locked_until=None, last_attempt_at=now)  # درج رکورد
        await database.execute(ins); return  # اجرا و خروج
    window_start = row["window_start"] or now  # شروع پنجره
    within = (now - window_start).total_seconds() <= LOGIN_WINDOW_SECONDS  # داخل پنجره؟
    new_count = (row["attempt_count"] + 1) if within else 1  # شمارش جدید
    new_window_start = window_start if within else now  # شروع جدید
    locked_until = row["locked_until"]  # قفل فعلی
    if new_count >= LOGIN_MAX_ATTEMPTS:  # عبور از حد؟
        locked_until = now + timedelta(seconds=LOGIN_LOCK_SECONDS)  # تنظیم قفل
    upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(attempt_count=new_count, window_start=new_window_start, locked_until=locked_until, last_attempt_at=now)  # آپدیت
    await database.execute(upd)  # اجرا

async def _register_login_success(phone: str, ip: str):  # تابع=ثبت موفقیت ورود
    sel = LoginAttemptTable.__table__.select().where(and_(LoginAttemptTable.phone == phone, LoginAttemptTable.ip == ip))  # رکورد
    row = await database.fetch_one(sel)  # اجرا
    if row:  # اگر هست
        upd = LoginAttemptTable.__table__.update().where(LoginAttemptTable.id == row["id"]).values(attempt_count=0, window_start=datetime.now(timezone.utc), locked_until=None)  # ریست شمارنده
        await database.execute(upd)  # اجرا

@app.post("/auth/refresh")  # مسیر=رفرش توکن
async def refresh_access_token(req: Dict):  # تابع=دریافت رفرش‌توکن
    refresh_token = req.get("refresh_token", "")  # خواندن رفرش
    if not refresh_token:  # خالی؟
        raise HTTPException(status_code=400, detail="refresh_token required")  # خطا
    token_hash = hash_refresh_token(refresh_token)  # هش
    now = datetime.now(timezone.utc)  # اکنون
    sel = RefreshTokenTable.__table__.select().where((RefreshTokenTable.token_hash == token_hash) & (RefreshTokenTable.revoked == False) & (RefreshTokenTable.expires_at > now))  # انتخاب معتبر
    rt = await database.fetch_one(sel)  # اجرا
    if not rt:  # نبود
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # خطا
    sel_user = UserTable.__table__.select().where(UserTable.id == rt["user_id"])  # یافتن کاربر
    db_user = await database.fetch_one(sel_user)  # اجرا
    if not db_user:  # نبود
        raise HTTPException(status_code=401, detail="Invalid refresh token")  # خطا
    new_access = create_access_token(db_user["phone"])  # تولید توکن دسترسی
    return unified_response("ok", "TOKEN_REFRESHED", "new access token", {"access_token": new_access})  # پاسخ

# -------------------- Notifications --------------------
@app.get("/user/{phone}/notifications")  # مسیر=لیست اعلان‌های کاربر
async def get_notifications(phone: str, only_unread: bool = True, limit: int = 50, offset: int = 0):  # تابع=گرفتن اعلان‌ها
    base_sel = NotificationTable.__table__.select().where(NotificationTable.user_phone == phone)  # انتخاب=بر اساس شماره کاربر
    if only_unread:  # فیلتر=خوانده‌نشده‌ها
        base_sel = base_sel.where(NotificationTable.read == False)  # شرط=read=False
    base_sel = base_sel.order_by(NotificationTable.created_at.desc()).limit(limit).offset(offset)  # مرتب‌سازی/صفحه‌بندی
    rows = await database.fetch_all(base_sel)  # اجرا
    items = [dict(r) for r in rows]  # تبدیل به dict
    return unified_response("ok", "NOTIFICATIONS", "user notifications", {"items": items})  # پاسخ

@app.post("/user/{phone}/notifications/{notif_id}/read")  # مسیر=علامت خوانده‌شدن یک اعلان
async def mark_notification_read(phone: str, notif_id: int):  # تابع=خوانده‌شده
    now = datetime.now(timezone.utc)  # اکنون
    upd = NotificationTable.__table__.update().where(
        (NotificationTable.id == notif_id) & (NotificationTable.user_phone == phone)
    ).values(read=True, read_at=now)  # آپدیت=read=True
    res = await database.execute(upd)  # اجرا
    return unified_response("ok", "NOTIF_READ", "notification marked as read", {"id": notif_id})  # پاسخ

@app.post("/user/{phone}/notifications/mark_all_read")  # مسیر=خوانده‌شدن همه اعلان‌های کاربر
async def mark_all_notifications_read(phone: str):  # تابع=خوانده‌شدن همه
    now = datetime.now(timezone.utc)  # اکنون
    upd = NotificationTable.__table__.update().where(
        (NotificationTable.user_phone == phone) & (NotificationTable.read == False)
    ).values(read=True, read_at=now)  # آپدیت=read=True
    await database.execute(upd)  # اجرا
    return unified_response("ok", "NOTIFS_READ_ALL", "all notifications marked as read", {})  # پاسخ

# -------------------- Cars --------------------
@app.get("/user_cars/{user_phone}")  # مسیر=ماشین‌های کاربر
async def get_user_cars(user_phone: str):  # تابع=لیست ماشین‌ها
    query = UserTable.__table__.select().where(UserTable.phone == user_phone)  # انتخاب کاربر
    user = await database.fetch_one(query)  # اجرا
    if not user:  # نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا
    items = user["car_list"] or []  # لیست ماشین‌ها
    return unified_response("ok", "USER_CARS", "user cars", {"items": items})  # پاسخ

@app.post("/user_cars")  # مسیر=آپدیت ماشین‌ها
async def update_user_cars(data: CarListUpdateRequest):  # تابع=آپدیت
    sel = UserTable.__table__.select().where(UserTable.phone == data.user_phone)  # یافتن کاربر
    user = await database.fetch_one(sel)  # اجرا
    if not user:  # نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا
    upd = UserTable.__table__.update().where(UserTable.phone == data.user_phone).values(car_list=[car.dict() for car in data.car_list])  # آپدیت
    await database.execute(upd)  # اجرا
    return unified_response("ok", "CARS_SAVED", "cars saved", {"count": len(data.car_list)})  # پاسخ

# -------------------- Orders --------------------
@app.post("/order")  # مسیر=ثبت سفارش
async def create_order(order: OrderRequest):  # تابع=ایجاد سفارش
    ins = RequestTable.__table__.insert().values(  # درج سفارش
        user_phone=order.user_phone,  # شماره کاربر
        latitude=order.location.latitude,  # عرض
        longitude=order.location.longitude,  # طول
        car_list=[car.dict() for car in order.car_list],  # خدمات/ماشین‌ها
        address=order.address.strip(),  # آدرس
        home_number=(order.home_number or "").strip(),  # پلاک
        service_type=order.service_type,  # نوع سرویس
        price=order.price,  # قیمت
        request_datetime=order.request_datetime,  # زمان ثبت
        status="NEW",  # وضعیت اولیه
        payment_type=order.payment_type.strip().lower(),  # نوع پرداخت
        service_place=order.service_place.strip().lower()  # محل سرویس
    ).returning(RequestTable.id)  # بازگردانی id
    row = await database.fetch_one(ins)  # اجرا
    new_id = row[0] if isinstance(row, (tuple, list)) else (row["id"] if row else None)  # استخراج id

    # پوش نوتیفیکیشن به مدیران: "درخواست جدید"
    try:  # try=محافظ خطا
        await send_push_to_managers("درخواست جدید", "درخواست جدید ثبت شد.", {"type": "new_request", "order_id": str(new_id)})  # ارسال پوش
    except Exception:  # خطا
        pass  # نادیده گرفتن

    return unified_response("ok", "REQUEST_CREATED", "request created", {"id": new_id})  # پاسخ

@app.post("/cancel_order")  # مسیر=لغو سفارش
async def cancel_order(cancel: CancelRequest):  # تابع=لغو
    upd = (  # آپدیت وضعیت
        RequestTable.__table__.update()
        .where(
            (RequestTable.user_phone == cancel.user_phone) &
            (RequestTable.service_type == cancel.service_type) &
            (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS"]))  # وضعیت‌های قابل لغو
        )
        .values(status="CANCELED", scheduled_start=None)  # مقداردهی لغو
        .returning(RequestTable.id)  # بازگردانی id
    )
    rows = await database.fetch_all(upd)  # اجرا
    if rows and len(rows) > 0:  # اگر حداقل یک رکورد
        return unified_response("ok", "ORDER_CANCELED", "canceled", {"count": len(rows)})  # پاسخ
    raise HTTPException(status_code=404, detail="active order not found")  # خطا

@app.get("/user_active_services/{user_phone}")  # مسیر=سرویس‌های فعال کاربر
async def get_user_active_services(user_phone: str):  # تابع=خواندن سفارش‌های فعال
    sel = RequestTable.__table__.select().where(
        (RequestTable.user_phone == user_phone) &
        (RequestTable.status.in_(["NEW", "WAITING", "ASSIGNED", "IN_PROGRESS", "STARTED"]))  # وضعیت‌های فعال
    )
    result = await database.fetch_all(sel)  # اجرا
    items = [dict(r) for r in result]  # دیکشنری
    return unified_response("ok", "USER_ACTIVE_SERVICES", "active services", {"items": items})  # پاسخ

@app.get("/user_orders/{user_phone}")  # مسیر=تاریخچه سفارش‌های کاربر
async def get_user_orders(user_phone: str):  # تابع=تمام سفارش‌ها
    sel = RequestTable.__table__.select().where(RequestTable.user_phone == user_phone)  # انتخاب
    result = await database.fetch_all(sel)  # اجرا
    items = [dict(r) for r in result]  # دیکشنری
    return unified_response("ok", "USER_ORDERS", "orders list", {"items": items})  # پاسخ

# -------------------- Scheduling (1 hour slots) --------------------
@app.get("/provider/{provider_phone}/free_hours")  # مسیر=ساعات آزاد سرویس‌گیرنده
async def get_free_hours(
    provider_phone: str,  # پارامتر=شماره سرویس‌گیرنده (یا any)
    date: str,  # پارامتر=تاریخ YYYY-MM-DD
    work_start: int = 8,  # پارامتر=شروع کاری
    work_end: int = 20,  # پارامتر=پایان کاری
    limit: int = 24  # پارامتر=سقف خروجی
):
    try:  # try
        d = datetime.fromisoformat(date).date()  # پارس تاریخ
    except Exception:  # خطا
        raise HTTPException(status_code=400, detail="invalid date; expected YYYY-MM-DD")  # خطا تاریخ

    if not (0 <= work_start < 24 and 0 <= work_end <= 24 and work_start < work_end):  # اعتبارسنجی ساعت کاری
        raise HTTPException(status_code=400, detail="invalid work hours")  # خطا ساعت

    provider = provider_phone.strip()  # تمیز کردن شماره
    day_start = datetime(d.year, d.month, d.day, work_start, 0, tzinfo=timezone.utc)  # شروع روز (UTC)
    day_end = datetime(d.year, d.month, d.day, work_end, 0, tzinfo=timezone.utc)  # پایان روز (UTC)

    results: List[str] = []  # خروجی
    cur = day_start  # زمان جاری
    while cur + timedelta(hours=1) <= day_end and len(results) < limit:  # حلقه=تولید اسلات‌های یک‌ساعته
        s, e = cur, cur + timedelta(hours=1)  # بازه
        if provider.lower() == "any" or await provider_is_free(provider, s, e):  # اگر آزاد است یا any
            results.append(s.isoformat())  # افزودن زمان ISO
        cur = cur + timedelta(hours=1)  # حرکت به بازه بعدی

    return unified_response("ok", "FREE_HOURS", "free hourly slots", {"items": results})  # پاسخ

@app.get("/busy_slots")  # مسیر=ساعات مشغول (پیشنهادشده یا رزروشده) برای جلوگیری از تداخل
async def get_busy_slots(provider_phone: str, date: str, exclude_order_id: Optional[int] = None):  # تابع=گرفتن اسلات‌های مشغول
    """
    خروجی: لیست شروع‌های ساعتی که یا در schedule_slots (PROPOSED/ACCEPTED) وجود دارند یا در appointments (BOOKED) هستند.  # توضیح=تعریف
    exclude_order_id: حذف اسلات‌های مربوط به همین سفارش از نتایج busy (برای نمایش به خود سفارش)  # توضیح=استثناء
    provider_phone: وقتی 'any' باشد، همه را درنظر می‌گیرد؛ در غیر این صورت فیلتر بر اساس provider_phone  # توضیح=فیلتر ارائه‌دهنده
    """
    try:  # try=پارس تاریخ
        d = datetime.fromisoformat(date).date()  # d=تاریخ
    except Exception:  # خطا
        raise HTTPException(status_code=400, detail="invalid date; expected YYYY-MM-DD")  # خطا تاریخ

    day_start = datetime(d.year, d.month, d.day, 0, 0, tzinfo=timezone.utc)  # day_start=شروع روز (UTC)
    day_end = day_start + timedelta(days=1)  # day_end=پایان روز (UTC+1 روز)

    # --- اسلات‌های پیشنهادی (PROPOSED/ACCEPTED) ---
    sel_sched = ScheduleSlotTable.__table__.select().where(  # sel_sched=انتخاب اسلات‌های پیشنهادی/پذیرفته
        (ScheduleSlotTable.slot_start >= day_start) &
        (ScheduleSlotTable.slot_start < day_end) &
        (ScheduleSlotTable.status.in_(["PROPOSED", "ACCEPTED"]))
    )  # پایان where
    if provider_phone.strip().lower() != "any":  # فیلتر=وقتی provider مشخص است
        sel_sched = sel_sched.where(ScheduleSlotTable.provider_phone == provider_phone)  # شرط=provider_phone
    if exclude_order_id is not None:  # فیلتر=حذف اسلات‌های سفارش جاری
        sel_sched = sel_sched.where(ScheduleSlotTable.request_id != exclude_order_id)  # شرط=عدم برابری request_id

    rows_sched = await database.fetch_all(sel_sched)  # اجرا=واکشی اسلات‌ها

    # --- رزروهای قطعی (BOOKED) ---
    sel_app = AppointmentTable.__table__.select().where(  # sel_app=انتخاب رزروهای قطعی
        (AppointmentTable.start_time >= day_start) &
        (AppointmentTable.start_time < day_end) &
        (AppointmentTable.status == "BOOKED")
    )  # پایان where
    if provider_phone.strip().lower() != "any":  # فیلتر=وقتی provider مشخص است
        sel_app = sel_app.where(AppointmentTable.provider_phone == provider_phone)  # شرط=provider_phone

    rows_app = await database.fetch_all(sel_app)  # اجرا=واکشی رزروها

    # --- تجمیع خروجی ---
    busy: set[str] = set()  # busy=مجموعه زمان‌های مشغول
    for r in rows_sched:  # حلقه=روی اسلات‌های پیشنهادی/پذیرفته
        busy.add(r["slot_start"].isoformat())  # افزودن=slot_start به صورت ISO
    for r in rows_app:  # حلقه=روی رزروهای BOOKED
        busy.add(r["start_time"].isoformat())  # افزودن=start_time به صورت ISO

    items = sorted(busy)  # items=مرتب‌سازی رشته‌ای
    return unified_response("ok", "BUSY_SLOTS", "busy slots", {"items": items})  # پاسخ=لیست مشغول

@app.post("/order/{order_id}/propose_slots")  # مسیر=پیشنهاد اسلات‌ها (مدیر)
async def propose_slots(order_id: int, body: ProposedSlotsRequest):  # تابع=ثبت اسلات‌های پیشنهادی
    req = await database.fetch_one(RequestTable.__table__.select().where(RequestTable.id == order_id))  # یافتن سفارش
    if not req:  # نبود سفارش
        raise HTTPException(status_code=404, detail="order not found")  # خطا

    accepted: List[str] = []  # لیست پذیرفته‌شده‌ها
    for s in body.slots[:3]:  # حداکثر ۳ زمان
        start = parse_iso(s)  # پارس ISO
        end = start + timedelta(hours=1)  # پایان یک‌ساعت بعد
        if await provider_is_free(body.provider_phone, start, end):  # بررسی آزاد بودن
            await database.execute(  # درج اسلات پیشنهادی
                ScheduleSlotTable.__table__.insert().values(
                    request_id=order_id,  # شناسه سفارش
                    provider_phone=body.provider_phone,  # شماره سرویس‌گیرنده
                    slot_start=start,  # شروع
                    status="PROPOSED",  # وضعیت
                    created_at=datetime.now(timezone.utc)  # زمان ایجاد
                )
            )
            accepted.append(start.isoformat())  # افزودن ISO به accepted

    if accepted:  # اگر حداقل یک اسلات ثبت شد
        await database.execute(  # وضعیت سفارش=WAITING (منتظر کاربر برای انتخاب)
            RequestTable.__table__.update().where(RequestTable.id == order_id).values(
                status="WAITING", driver_phone=body.provider_phone, scheduled_start=None
            )
        )
        try:  # ثبت اعلان برای کاربر
            await notify_user(req["user_phone"], "زمان‌بندی", "لطفاً یکی از زمان‌های پیشنهادی را انتخاب کنید.", data={"order_id": order_id, "slots": accepted})
        except Exception:  # بی‌صدا
            pass  # بدون وقفه

    return unified_response("ok", "SLOTS_PROPOSED", "slots proposed", {"accepted": accepted})  # پاسخ

@app.get("/order/{order_id}/proposed_slots")  # مسیر=گرفتن اسلات‌های پیشنهادی یک سفارش
async def get_proposed_slots(order_id: int):  # تابع=خواندن اسلات‌ها
    sel = ScheduleSlotTable.__table__.select().where(
        (ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.status == "PROPOSED")
    ).order_by(ScheduleSlotTable.slot_start.asc())  # مرتب‌سازی صعودی
    rows = await database.fetch_all(sel)  # اجرا
    items = [r["slot_start"].isoformat() for r in rows]  # استخراج ISO
    return unified_response("ok", "PROPOSED_SLOTS", "proposed slots", {"items": items})  # پاسخ

@app.post("/order/{order_id}/confirm_slot")  # مسیر=تأیید یک اسلات توسط کاربر
async def confirm_slot(order_id: int, body: ConfirmSlotRequest):  # تابع=تأیید
    chosen_start = parse_iso(body.slot)  # پارس شروع انتخاب‌شده
    sel_slot = ScheduleSlotTable.__table__.select().where(
        (ScheduleSlotTable.request_id == order_id) &
        (ScheduleSlotTable.slot_start == chosen_start) &
        (ScheduleSlotTable.status == "PROPOSED")
    )  # یافتن اسلات
    slot = await database.fetch_one(sel_slot)  # اجرا
    if not slot:  # نبود اسلات
        raise HTTPException(status_code=404, detail="slot not found or not proposed")  # خطا

    provider_phone = slot["provider_phone"]  # شماره سرویس‌گیرنده
    start = slot["slot_start"]  # شروع
    end = start + timedelta(hours=1)  # پایان

    if not await provider_is_free(provider_phone, start, end):  # اگر بازه آزاد نیست
        await database.execute(ScheduleSlotTable.__table__.update().where(ScheduleSlotTable.id == slot["id"]).values(status="REJECTED"))  # رد اسلات
        raise HTTPException(status_code=409, detail="slot no longer available")  # خطا

    await database.execute(ScheduleSlotTable.__table__.update().where(ScheduleSlotTable.id == slot["id"]).values(status="ACCEPTED"))  # قبول اسلات انتخابی
    await database.execute(ScheduleSlotTable.__table__.update().where(
        (ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.status == "PROPOSED") & (ScheduleSlotTable.id != slot["id"])
    ).values(status="REJECTED"))  # رد سایر اسلات‌ها

    await database.execute(AppointmentTable.__table__.insert().values(
        provider_phone=provider_phone, request_id=order_id, start_time=start, end_time=end, status="BOOKED", created_at=datetime.now(timezone.utc)
    ))  # درج رزرو قطعی

    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(
        scheduled_start=start, status="ASSIGNED", driver_phone=provider_phone
    ))  # وضعیت=ASSIGNED (کاربر زمان را انتخاب کرد)

    # پوش نوتیفیکیشن به مدیران: "تأیید زمان"
    try:  # try=محافظ خطا
        await send_push_to_managers("تأیید زمان", "کاربر زمان را تأیید کرد.", {"type": "time_confirm", "order_id": str(order_id)})  # ارسال پوش
    except Exception:  # خطا
        pass  # نادیده گرفتن

    return unified_response("ok", "SLOT_CONFIRMED", "slot confirmed", {"start": start.isoformat(), "end": end.isoformat()})  # پاسخ

@app.post("/order/{order_id}/reject_all_and_cancel")  # مسیر=رد همه پیشنهادها و کنسل
async def reject_all_and_cancel(order_id: int):  # تابع=رد و کنسل
    await database.execute(ScheduleSlotTable.__table__.update().where(
        (ScheduleSlotTable.request_id == order_id) & (ScheduleSlotTable.status == "PROPOSED")
    ).values(status="REJECTED"))  # رد همه اسلات‌های پیشنهادی
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="CANCELED", scheduled_start=None))  # کنسل سفارش
    return unified_response("ok", "ORDER_CANCELED", "order canceled after rejecting proposals", {})  # پاسخ

# -------------------- Admin/Workflow --------------------
@app.post("/admin/order/{order_id}/price")  # مسیر=ثبت قیمت و وضعیت بعدی
async def admin_set_price_and_status(order_id: int, body: PriceBody):  # تابع=ثبت قیمت/وضعیت
    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)  # یافتن سفارش
    req = await database.fetch_one(sel)  # اجرا
    if not req:  # نبود سفارش
        raise HTTPException(status_code=404, detail="order not found")  # خطا

    new_status = "IN_PROGRESS" if body.agree else "CANCELED"  # توافق قیمت → IN_PROGRESS | عدم توافق → CANCELED
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(price=body.price, status=new_status))  # آپدیت سفارش

    return unified_response("ok", "PRICE_SET", "price and status updated", {"order_id": order_id, "price": body.price, "status": new_status})  # پاسخ

@app.post("/order/{order_id}/start")  # مسیر=شروع کار
async def start_order(order_id: int):  # تابع=شروع
    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)  # یافتن سفارش
    req = await database.fetch_one(sel)  # اجرا
    if not req:  # نبود
        raise HTTPException(status_code=404, detail="order not found")  # خطا
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="STARTED"))  # وضعیت=STARTED
    return unified_response("ok", "ORDER_STARTED", "order started", {"order_id": order_id, "status": "STARTED"})  # پاسخ

@app.post("/order/{order_id}/finish")  # مسیر=پایان کار
async def finish_order(order_id: int):  # تابع=پایان
    sel = RequestTable.__table__.select().where(RequestTable.id == order_id)  # یافتن سفارش
    req = await database.fetch_one(sel)  # اجرا
    if not req:  # نبود
        raise HTTPException(status_code=404, detail="order not found")  # خطا
    now_iso = datetime.now(timezone.utc).isoformat()  # زمان=ISO
    await database.execute(RequestTable.__table__.update().where(RequestTable.id == order_id).values(status="FINISH", finish_datetime=now_iso))  # وضعیت=FINISH
    return unified_response("ok", "ORDER_FINISHED", "order finished", {"order_id": order_id, "status": "FINISH"})  # پاسخ

# -------------------- Profile --------------------
@app.post("/user/profile")  # مسیر=ذخیره پروفایل
async def update_profile(body: UserProfileUpdate):  # تابع=آپدیت پروفایل
    if not body.phone.strip():  # اعتبارسنجی شماره
        raise HTTPException(status_code=400, detail="phone_required")  # خطا=شماره لازم
    sel = UserTable.__table__.select().where(UserTable.phone == body.phone)  # یافتن کاربر
    user = await database.fetch_one(sel)  # اجرا
    if user is None:  # نبود کاربر
        raise HTTPException(status_code=404, detail="User not found")  # خطا
    await database.execute(UserTable.__table__.update().where(UserTable.phone == body.phone).values(name=body.name.strip(), address=body.address.strip()))  # آپدیت
    return unified_response("ok", "PROFILE_UPDATED", "profile saved", {"phone": body.phone})  # پاسخ

@app.get("/user/profile/{phone}")  # مسیر=خواندن پروفایل
async def get_user_profile(phone: str):  # تابع=خواندن پروفایل
    sel = UserTable.__table__.select().where(UserTable.phone == phone)  # کوئری
    db_user = await database.fetch_one(sel)  # اجرا
    if db_user is None:  # نبود
        raise HTTPException(status_code=404, detail="User not found")  # خطا
    mapping = getattr(db_user, "_mapping", {})  # سازگاری RowMapping
    name_val = mapping["name"] if "name" in mapping else ""  # نام
    address_val = mapping["address"] if "address" in mapping else ""  # آدرس
    return unified_response("ok", "PROFILE_FETCHED", "profile data", {"phone": db_user["phone"], "name": name_val or "", "address": address_val or ""})  # پاسخ

@app.get("/debug/users")  # مسیر=دیباگ لیست کاربران
async def debug_users():  # تابع=لیست ساده کاربران
    rows = await database.fetch_all(UserTable.__table__.select())  # انتخاب همه کاربران
    out = []  # خروجی
    for r in rows:  # حلقه=هر کاربر
        mapping = getattr(r, "_mapping", {})  # سازگاری RowMapping
        name_val = mapping["name"] if "name" in mapping else ""  # نام
        address_val = mapping["address"] if "address" in mapping else ""  # آدرس
        out.append({"id": r["id"], "phone": r["phone"], "name": name_val, "address": address_val})  # افزودن به خروجی
    return out  # بازگشت لیست
