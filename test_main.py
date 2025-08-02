# فایل: test_main.py

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_register_user():
    response = client.post(
        "/api/v1/register_user",
        json={
            "phone": "09123456789",
            "password": "testpass123",
            "name": "علی",
            "address": "تهران"
        }
    )
    assert response.status_code == 200 or response.status_code == 400  # اگر قبلاً ثبت شده باشد 400 می‌دهد

def test_login_success():
    response = client.post(
        "/api/v1/login",
        params={"phone": "09123456789", "password": "testpass123"}
    )
    assert response.status_code == 200

def test_login_fail():
    response = client.post(
        "/api/v1/login",
        params={"phone": "09123456789", "password": "غلط"}
    )
    assert response.status_code == 401

def test_add_car():
    response = client.post(
        "/api/v1/add_car?phone=09123456789",
        json={
            "brand": "پراید",
            "model": "131",
            "plate": "12الف-3456"
        }
    )
    assert response.status_code == 200