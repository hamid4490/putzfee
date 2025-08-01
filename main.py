# ایمپورت‌های لازم
import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from sqlalchemy import Column, Integer, String, Float, Boolean
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.declarative import declarative_base
from databases import Database
from dotenv import load_dotenv
import datetime

# بارگذاری متغیرهای محیطی (مثلاً DATABASE_URL)
load_dotenv()

# گرفتن آدرس دیتابیس از env
DATABASE_URL = os.getenv("DATABASE_URL")

# ساخت آبجکت دیتابیس و بیس مدل SQLAlchemy
database = Database(DATABASE_URL)
Base = declarative_base()

# ساخت اپلیکیشن FastAPI
app = FastAPI()

# مدل دیتابیس کاربر (UserTable) با لیست ماشین‌ها به صورت JSONB
class UserTable(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String, unique=True, index=True)
    address = Column(String)
    car_list = Column(JSONB, default=list)  # لیست ماشین‌ها به صورت JSONB

# مدل دیتابیس راننده (DriverTable)
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

# مدل دیتابیس سفارش (RequestTable)
class RequestTable(Base):
    __tablename__ = "requests"
    id = Column(Integer, primary_key=True, index=True)
    user_phone = Column(String)
    latitude = Column(Float)
    longitude = Column(Float)
    car_list = Column(JSONB)  # لیست ماشین‌ها به صورت JSONB
    address = Column(String)
    service_type = Column(String)
    price = Column(Integer)
    request_datetime = Column(String)
    status = Column(String)
    driver_name = Column(String)
    driver_phone = Column(String)
    finish_datetime = Column(String)
    payment_type = Column(String)

# مدل Pydantic برای اطلاعات ماشین
class CarInfo(BaseModel):
    brand: str
    model: str
    plate: str

# مدل Pydantic برای لوکیشن
class Location(BaseModel):
    latitude: float
    longitude: float

# مدل Pydantic برای ثبت سفارش
class OrderRequest(BaseModel):
    user_phone: str
    location: Location
    car_list: List[CarInfo]
    address: str
    service_type: str
    price: int
    request_datetime: str
    payment_type: str

# مدل Pydantic برای ثبت/ویرایش ماشین کاربر
class CarListUpdateRequest(BaseModel):
    user_phone: str
    car_list: List[CarInfo]

# مدل Pydantic برای کنسل کردن سفارش
class CancelRequest(BaseModel):
    user_phone: str
    service_type: str

# رویداد استارتاپ: ساخت جداول و اتصال به دیتابیس
@app.on_event("startup")
async def startup():
    import sqlalchemy
    engine = sqlalchemy.create_engine(str(DATABASE_URL).replace("+asyncpg", ""))
    Base.metadata.create_all(engine)
    await database.connect()

# رویداد شات‌داون: قطع اتصال دیتابیس
@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# روت اصلی برای تست سرور
@app.get("/")
def read_root():
    return {"message": "Putzfee FastAPI Server is running!"}

# --- مدیریت ماشین‌های کاربر ---

# گرفتن لیست ماشین‌های کاربر
@app.get("/user_cars/{user_phone}")
async def get_user_cars(user_phone: str):
    query = UserTable.__table__.select().where(UserTable.phone == user_phone)
    user = await database.fetch_one(query)
    if user:
        return user["car_list"] or []
    else:
        raise HTTPException(status_code=404, detail="User not found")

@app.post("/user_cars")
async def update_user_cars(data: CarListUpdateRequest):
    query = UserTable.select().where(UserTable.c.phone == data.user_phone)
    user = await database.fetch_one(query)

    if user:
        query = UserTable.update().where(UserTable.c.phone == data.user_phone).values(
            car_list=[car.dict() for car in data.car_list]
        )
    else:
        query = UserTable.insert().values(
            phone=data.user_phone,
            car_list=[car.dict() for car in data.car_list]
        )

    await database.execute(query)
    return {"status": "ok", "message": "لیست ماشین‌ها ذخیره شد"}
# --- مدیریت سفارش‌ها ---

# ثبت سفارش جدید
@app.post("/order")
async def create_order(order: OrderRequest):
    query = RequestTable.__table__.insert().values(
        user_phone=order.user_phone,
        latitude=order.location.latitude,
        longitude=order.location.longitude,
        car_list=[car.dict() for car in order.car_list],
        address=order.address,
        service_type=order.service_type,
        price=order.price,
        request_datetime=order.request_datetime,
        status="در انتظار",
        driver_name="",
        driver_phone="",
        finish_datetime="",
        payment_type=order.payment_type
    )
    await database.execute(query)
    return {"status": "ok", "message": "درخواست ثبت شد"}

# گرفتن لیست همه سفارش‌ها
@app.get("/orders")
async def get_orders():
    query = RequestTable.__table__.select()
    result = await database.fetch_all(query)
    return [dict(row) for row in result]

# کنسل کردن سفارش (بر اساس شماره تلفن و نوع سرویس)
@app.post("/cancel_order")
async def cancel_order(cancel: CancelRequest):
    """
    این endpoint سفارش فعال کاربر را بر اساس شماره تلفن و نوع سرویس پیدا می‌کند
    و وضعیت آن را به "کنسل شده" تغییر می‌دهد.
    """
    query = RequestTable.__table__.update().where(
        (RequestTable.user_phone == cancel.user_phone) &
        (RequestTable.service_type == cancel.service_type) &
        (RequestTable.status == "در انتظار")
    ).values(
        status="کنسل شده"
    )
    result = await database.execute(query)
    if result:
        return {"status": "ok", "message": "درخواست کنسل شد"}
    else:
        return {"status": "error", "message": "سفارشی پیدا نشد یا قبلاً کنسل شده"}

# گرفتن سفارش‌های فعال کاربر (در انتظار) بر اساس شماره تلفن
@app.get("/user_active_services/{user_phone}")
async def get_user_active_services(user_phone: str):
    query = RequestTable.__table__.select().where(
        (RequestTable.user_phone == user_phone) &
        (RequestTable.status == "در انتظار")
    )
    result = await database.fetch_all(query)
    return [dict(row) for row in result]

    # مدل Pydantic برای ثبت‌نام کاربر
class UserRegisterRequest(BaseModel):
    phone: str
    address: Optional[str] = None

@app.post("/register_user")
async def register_user(user: UserRegisterRequest):
    # چک کن کاربر وجود دارد یا نه
    query = UserTable.__table__.select().where(UserTable.phone == user.phone)
    existing = await database.fetch_one(query)
    if existing:
        return {"status": "ok", "message": "User already exists"}
    # اگر وجود ندارد، بساز
    query = UserTable.__table__.insert().values(
        phone=user.phone,
        address=user.address or "",
        car_list=[]
    )
    await database.execute(query)
    return {"status": "ok", "message": "User registered"}
