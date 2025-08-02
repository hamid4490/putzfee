# فایل: main.py

from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
import models, schemas, crud, database, logger
from utils import verify_password
from loguru import logger

models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(
    title="Putzfee API",
    version="1.0.0"
)

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/api/v1/register_user")
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    logger.info(f"ثبت‌نام کاربر: {user.phone}")
    db_user = crud.get_user_by_phone(db, user.phone)
    if db_user:
        raise HTTPException(status_code=400, detail="کاربر قبلاً ثبت شده است")
    return crud.create_user(db, user)

@app.post("/api/v1/login")
def login(phone: str, password: str, db: Session = Depends(get_db)):
    logger.info(f"ورود کاربر: {phone}")
    db_user = crud.get_user_by_phone(db, phone)
    if not db_user or not verify_password(password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="شماره یا رمز اشتباه است")
    return {"message": "ورود موفق"}

@app.post("/api/v1/add_car")
def add_car(phone: str, car: schemas.CarCreate, db: Session = Depends(get_db)):
    logger.info(f"افزودن ماشین برای کاربر: {phone}")
    db_user = crud.get_user_by_phone(db, phone)
    if not db_user:
        raise HTTPException(status_code=404, detail="کاربر یافت نشد")
    return crud.create_car(db, db_user.id, car)

@app.post("/api/v1/order")
def create_order(order: schemas.OrderCreate, db: Session = Depends(get_db)):
    logger.info(f"ثبت سفارش جدید: {order.user_phone} - {order.service_type}")
    db_user = crud.get_user_by_phone(db, order.user_phone)
    if not db_user:
        raise HTTPException(status_code=404, detail="کاربر یافت نشد")
    car = db.query(models.Car).filter(models.Car.plate == order.car_plate, models.Car.user_id == db_user.id).first()
    if not car:
        raise HTTPException(status_code=404, detail="ماشین یافت نشد")
    return crud.create_order(db, db_user.id, car.id, order)

# سایر endpointها مثل لیست سفارش‌ها، کنسل سفارش و ... را مشابه همین بنویس

@app.exception_handler(Exception)
def global_exception_handler(request, exc):
    logger.error(f"خطای سرور: {exc}")
    return HTTPException(status_code=500, detail="خطای داخلی سرور")