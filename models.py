# فایل: models.py

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, default="")
    address = Column(String, default="")
    password_hash = Column(String, nullable=False)

class Car(Base):
    __tablename__ = "cars"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    brand = Column(String)
    model = Column(String)
    plate = Column(String)
    user = relationship("User", back_populates="cars")

User.cars = relationship("Car", back_populates="user")

class Order(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    car_id = Column(Integer, ForeignKey("cars.id"))
    service_type = Column(String)
    status = Column(String)
    driver_name = Column(String, default="")
    driver_phone = Column(String, default="")
    driver_photo_url = Column(String, default="")
    request_datetime = Column(DateTime)
    finish_datetime = Column(DateTime, nullable=True)
    price = Column(Integer)
    address = Column(String)
    payment_type = Column(String)