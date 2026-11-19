import os

os.environ.setdefault(
    "DATABASE_URL", "postgresql+psycopg://expenses:expenses@localhost:5432/expenses_test"
)
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-pytest-0123456789abcdef")

import pytest

from app import app as flask_app
from auth import hash_password
from models import UserModel, db

PASSWORD = "Password123"


@pytest.fixture()
def app():
    # Захист: тести стирають таблиці, тож працюємо лише з тестовою базою
    assert "test" in flask_app.config["SQLALCHEMY_DATABASE_URI"]
    flask_app.config.update(TESTING=True)
    with flask_app.app_context():
        db.drop_all()
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def _create_user(client, name, role):
    user = UserModel(name=name, password_hash=hash_password(PASSWORD), role=role)
    db.session.add(user)
    db.session.commit()
    token = client.post("/login", json={"name": name, "password": PASSWORD}).json["access_token"]
    return {"id": user.id, "headers": {"Authorization": f"Bearer {token}"}}


@pytest.fixture()
def user(client):
    return _create_user(client, "user_1", "user")


@pytest.fixture()
def other_user(client):
    return _create_user(client, "user_2", "user")


@pytest.fixture()
def auditor(client):
    return _create_user(client, "auditor_1", "auditor")


@pytest.fixture()
def admin(client):
    return _create_user(client, "admin_1", "admin")


@pytest.fixture()
def user_jwt_header(user):
    return user["headers"]