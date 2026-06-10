import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert "message" in response.json()

def test_login_invalid_credentials():
    response = client.post("/api/auth/login", json={
        "email": "wrong@test.com",
        "password": "wrong"
    })
    assert response.status_code == 401

def test_protected_endpoint_without_token():
    response = client.get("/api/incidents")
    assert response.status_code in [401, 403]

def test_register():
    response = client.post("/api/auth/register", json={
        "email": "ci_test@example.com",
        "password": "test123",
        "full_name": "CI Test User"
    })
    assert response.status_code == 200
    assert "access_token" in response.json()