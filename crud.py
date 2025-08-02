# فایل: crud.py

from sqlalchemy.orm import Session
import models, schemas, utils

def create_user(db: Session, user: schemas.UserCreate):
    db_user = models.User(
        phone=user.phone,
        name=user.name,
        address=user.address,
        password_hash=utils.hash_password(user.password)
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_user_by_phone(db: Session, phone: str):
    return db.query(models.User).filter(models.User.phone == phone).first()

def create_car(db: Session, user_id: int, car: schemas.CarCreate):
    db_car = models.Car(
        user_id=user_id,
        brand=car.brand,
        model=car.model,
        plate=car.plate
    )
    db.add(db_car)
    db.commit()
    db.refresh(db_car)
    return db_car

def create_order(db: Session, user_id: int, car_id: int, order: schemas.OrderCreate):
    db_order = models.Order(
        user_id=user_id,
        car_id=car_id,
        service_type=order.service_type,
        status="در انتظار تایید",
        address=order.address,
        price=order.price,
        payment_type=order.payment_type
    )
    db.add(db_order)
    db.commit()
    db.refresh(db_order)
    return db_order