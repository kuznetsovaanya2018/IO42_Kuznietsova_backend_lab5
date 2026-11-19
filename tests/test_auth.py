import pytest
from flask_jwt_extended import decode_token

from auth import hash_password, verify_password
from models import UserModel, db

CREDS = {"name": "Ann", "password": "Password123"}


def test_liveness_timestamp(client):
    response = client.get("/healthz/live")
    assert response.status_code == 200
    assert response.json["status"] == "alive"


@pytest.mark.freeze_time("2026-10-05 12:00:00")
def test_frozen_time_check(client):
    response = client.get("/healthz/live")
    assert response.json["timestamp"].startswith("2026-10-05T12:00:00")


def test_readiness(client):
    response = client.get("/healthz/ready")
    assert response.status_code == 200
    assert response.json["status"] == "ready"


def test_register_success(client):
    r = client.post("/register", json=CREDS)
    assert r.status_code == 201
    assert r.json["name"] == "Ann"
    assert r.json["role"] == "user"
    assert "password" not in r.json and "password_hash" not in r.json


def test_register_duplicate(client):
    client.post("/register", json=CREDS)
    assert client.post("/register", json=CREDS).status_code == 409


@pytest.mark.parametrize("payload", [
    {},
    {"name": "Ann"},
    {"password": "Password123"},
    {"name": "Ann", "password": "short"},
    {"name": "   ", "password": "Password123"},
])
def test_register_validation(client, payload):
    r = client.post("/register", json=payload)
    assert r.status_code == 400
    assert r.json["error"] == "invalid_request"


def test_password_stored_as_argon2_hash(client):
    client.post("/register", json=CREDS)
    user = db.session.scalars(db.select(UserModel)).first()
    assert user.password_hash.startswith("$argon2id$")
    assert CREDS["password"] not in user.password_hash


def test_login_success_returns_jwt_with_roles(client):
    client.post("/register", json=CREDS)
    r = client.post("/login", json=CREDS)
    assert r.status_code == 200
    assert decode_token(r.json["access_token"])["roles"] == ["user"]


def test_login_wrong_password(client):
    client.post("/register", json=CREDS)
    r = client.post("/login", json={"name": "Ann", "password": "WrongPassword1"})
    assert r.status_code == 401
    assert r.json["error"] == "unauthorized"


def test_login_unknown_user(client):
    r = client.post("/login", json={"name": "Nobody", "password": "Password123"})
    assert r.status_code == 401


@pytest.mark.parametrize("method,path", [
    ("get", "/users"),
    ("get", "/user/1"),
    ("delete", "/user/1"),
    ("post", "/record"),
    ("get", "/record?user_id=1"),
    ("post", "/category"),
    ("post", "/category/global"),
])
def test_protected_endpoints_require_token(client, method, path):
    assert getattr(client, method)(path).status_code == 401


def test_invalid_token_returns_401(client):
    r = client.get("/users", headers={"Authorization": "Bearer not-a-token"})
    assert r.status_code == 401


def test_hash_and_verify_password():
    hashed = hash_password("secret123")
    assert hashed != "secret123"
    assert verify_password("secret123", hashed)
    assert not verify_password("wrong", hashed)


def test_verify_rejects_malformed_hash():
    assert verify_password("x", "not-a-hash") is False