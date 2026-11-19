import os
from datetime import datetime, timedelta, timezone

import click
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token
from flask_migrate import Migrate
from marshmallow import ValidationError
from sqlalchemy import or_, text
from sqlalchemy.exc import IntegrityError

from auth import (
    current_role, current_user_id, hash_password, roles_required, verify_password,
)
from models import db, UserModel, CategoryModel, AccountModel, RecordModel
from schemas import (
    AccountSchema, CategorySchema, LoginSchema, RecordSchema,
    RegisterSchema, RoleSchema, TopUpSchema,
)


def database_url():
    url = os.getenv(
        "DATABASE_URL", "postgresql+psycopg://expenses:expenses@localhost:5432/expenses"
    )
    if url.startswith("postgresql://"):  # у CI адреса без назви драйвера
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = database_url()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.getenv(
    "JWT_SECRET_KEY", "dev-secret-key-change-me-0123456789abcdef"
)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

register_schema = RegisterSchema()
login_schema = LoginSchema()
role_schema = RoleSchema()
category_schema = CategorySchema()
record_schema = RecordSchema()
account_schema = AccountSchema()
topup_schema = TopUpSchema()


# ---------- Помилки та допоміжні функції ----------

@jwt.unauthorized_loader
def missing_token(reason):
    return jsonify({"error": "unauthorized", "message": reason}), 401


@jwt.invalid_token_loader
def invalid_token(reason):
    return jsonify({"error": "unauthorized", "message": reason}), 401


@jwt.expired_token_loader
def expired_token(jwt_header, jwt_payload):
    return jsonify({"error": "unauthorized", "message": "Token has expired"}), 401


def validation_error(err):
    return jsonify({"error": "invalid_request", "errors": err.messages}), 400


def not_found(message):
    return jsonify({"error": "not_found", "message": message}), 404


def can_see_all():
    return current_role() in ("auditor", "admin")


# ---------- Системний стан ----------

@app.route("/healthz/live", methods=["GET"])
def healthz_live():
    return jsonify({
        "status": "alive",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }), 200


@app.route("/healthz/ready", methods=["GET"])
def healthz_ready():
    try:
        db.session.execute(text("SELECT 1"))
    except Exception:
        return jsonify({"status": "not_ready"}), 503
    return jsonify({"status": "ready"}), 200


# ---------- Реєстрація та логін ----------

@app.route("/register", methods=["POST"])
def register():
    try:
        data = register_schema.load(request.get_json(silent=True))
    except ValidationError as err:
        return validation_error(err)

    name = data["name"].strip()
    exists = db.session.scalars(
        db.select(UserModel).where(UserModel.name == name)
    ).first()
    if exists is not None:
        return jsonify({"error": "conflict", "message": "User already exists"}), 409

    user = UserModel(name=name, password_hash=hash_password(data["password"]), role="user")
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "conflict", "message": "User already exists"}), 409
    return jsonify(user.to_dict()), 201


@app.route("/login", methods=["POST"])
def login():
    try:
        data = login_schema.load(request.get_json(silent=True))
    except ValidationError as err:
        return validation_error(err)

    user = db.session.scalars(
        db.select(UserModel).where(UserModel.name == data["name"].strip())
    ).first()
    if user is None or not verify_password(data["password"], user.password_hash):
        return jsonify({"error": "unauthorized", "message": "Invalid credentials"}), 401

    token = create_access_token(
        identity=str(user.id), additional_claims={"roles": [user.role]}
    )
    return jsonify({"access_token": token, "token_type": "Bearer"}), 200


# ---------- Users ----------

@app.route("/users", methods=["GET"])
@roles_required("auditor", "admin")
def get_users():
    users = db.session.scalars(db.select(UserModel).order_by(UserModel.id)).all()
    return jsonify([u.to_dict() for u in users]), 200


@app.route("/user/<int:user_id>", methods=["GET"])
@roles_required("user", "auditor", "admin")
def get_user(user_id):
    if not can_see_all() and user_id != current_user_id():
        return not_found("User not found")
    user = db.session.get(UserModel, user_id)
    if user is None:
        return not_found("User not found")
    return jsonify(user.to_dict()), 200


@app.route("/user/<int:user_id>", methods=["DELETE"])
@roles_required("admin")
def delete_user(user_id):
    user = db.session.get(UserModel, user_id)
    if user is None:
        return not_found("User not found")
    db.session.delete(user)
    db.session.commit()
    return "", 204


@app.route("/user/<int:user_id>/role", methods=["PATCH"])
@roles_required("admin")
def change_role(user_id):
    try:
        data = role_schema.load(request.get_json(silent=True))
    except ValidationError as err:
        return validation_error(err)
    user = db.session.get(UserModel, user_id)
    if user is None:
        return not_found("User not found")
    user.role = data["role"]
    db.session.commit()
    return jsonify(user.to_dict()), 200


# ---------- Categories ----------

@app.route("/category", methods=["GET"])
@roles_required("user", "auditor", "admin")
def get_categories():
    query = db.select(CategoryModel).order_by(CategoryModel.id)
    if current_role() == "user":
        query = query.where(
            or_(CategoryModel.user_id.is_(None), CategoryModel.user_id == current_user_id())
        )
    categories = db.session.scalars(query).all()
    return jsonify([c.to_dict() for c in categories]), 200


@app.route("/category", methods=["POST"])
@roles_required("user", "admin")
def create_category():
    try:
        data = category_schema.load(request.get_json(silent=True))
    except ValidationError as err:
        return validation_error(err)
    category = CategoryModel(name=data["name"].strip(), user_id=current_user_id())
    db.session.add(category)
    db.session.commit()
    return jsonify(category.to_dict()), 201


@app.route("/category/global", methods=["POST"])
@roles_required("admin")
def create_global_category():
    try:
        data = category_schema.load(request.get_json(silent=True))
    except ValidationError as err:
        return validation_error(err)
    category = CategoryModel(name=data["name"].strip(), user_id=None)
    db.session.add(category)
    db.session.commit()
    return jsonify(category.to_dict()), 201


@app.route("/category/<int:category_id>", methods=["DELETE"])
@roles_required("admin")
def delete_category(category_id):
    category = db.session.get(CategoryModel, category_id)
    if category is None:
        return not_found("Category not found")
    db.session.delete(category)
    db.session.commit()
    return "", 204


# ---------- Accounts ----------

@app.route("/account", methods=["POST"])
@roles_required("user", "admin")
def create_account():
    try:
        data = account_schema.load(request.get_json(silent=True))
    except ValidationError as err:
        return validation_error(err)

    if current_role() == "user" and data["user_id"] != current_user_id():
        return not_found("User not found")
    if db.session.get(UserModel, data["user_id"]) is None:
        return not_found("User not found")

    existing = db.session.scalars(
        db.select(AccountModel).where(AccountModel.user_id == data["user_id"])
    ).first()
    if existing is not None:
        return jsonify({"error": "conflict", "message": "User already has an account"}), 409

    account = AccountModel(user_id=data["user_id"], balance=0.0)
    db.session.add(account)
    db.session.commit()
    return jsonify(account.to_dict()), 201


@app.route("/account/<int:account_id>", methods=["GET"])
@roles_required("user", "auditor", "admin")
def get_account(account_id):
    account = db.session.get(AccountModel, account_id)
    if account is None:
        return not_found("Account not found")
    if not can_see_all() and account.user_id != current_user_id():
        return not_found("Account not found")
    return jsonify(account.to_dict()), 200


@app.route("/account/<int:account_id>/topup", methods=["POST"])
@roles_required("user", "admin")
def top_up_account(account_id):
    try:
        data = topup_schema.load(request.get_json(silent=True))
    except ValidationError as err:
        return validation_error(err)

    account = db.session.scalars(
        db.select(AccountModel).where(AccountModel.id == account_id).with_for_update()
    ).first()
    if account is None:
        return not_found("Account not found")
    if current_role() == "user" and account.user_id != current_user_id():
        return not_found("Account not found")

    account.balance = round(account.balance + data["amount"], 2)
    db.session.commit()
    return jsonify(account.to_dict()), 200


# ---------- Records ----------

@app.route("/record", methods=["POST"])
@roles_required("user", "admin")
def create_record():
    try:
        data = record_schema.load(request.get_json(silent=True))
    except ValidationError as err:
        return validation_error(err)

    if current_role() == "user" and data["user_id"] != current_user_id():
        return not_found("User not found")
    if db.session.get(UserModel, data["user_id"]) is None:
        return not_found("User not found")

    category = db.session.get(CategoryModel, data["category_id"])
    if category is None or (
        category.user_id is not None and category.user_id != data["user_id"]
    ):
        return not_found("Category not found")

    account = db.session.scalars(
        db.select(AccountModel)
        .where(AccountModel.user_id == data["user_id"])
        .with_for_update()
    ).first()
    if account is None:
        return not_found("User has no account")
    if account.balance < data["amount"]:
        return jsonify({
            "error": "insufficient_funds",
            "message": "Insufficient account balance",
        }), 400

    account.balance = round(account.balance - data["amount"], 2)
    record = RecordModel(
        user_id=data["user_id"],
        category_id=data["category_id"],
        amount=data["amount"],
    )
    db.session.add(record)
    db.session.commit()

    result = record.to_dict()
    result["remaining_balance"] = account.balance
    return jsonify(result), 201


@app.route("/record/<int:record_id>", methods=["GET"])
@roles_required("user", "auditor", "admin")
def get_record(record_id):
    record = db.session.get(RecordModel, record_id)
    if record is None:
        return not_found("Record not found")
    if not can_see_all() and record.user_id != current_user_id():
        return not_found("Record not found")
    return jsonify(record.to_dict()), 200


@app.route("/record/<int:record_id>", methods=["DELETE"])
@roles_required("user", "admin")
def delete_record(record_id):
    record = db.session.get(RecordModel, record_id)
    if record is None:
        return not_found("Record not found")
    if current_role() == "user" and record.user_id != current_user_id():
        return not_found("Record not found")
    db.session.delete(record)
    db.session.commit()
    return "", 204


@app.route("/record", methods=["GET"])
@roles_required("user", "auditor", "admin")
def get_records():
    user_id_raw = request.args.get("user_id")
    category_id_raw = request.args.get("category_id")

    if user_id_raw is None and category_id_raw is None:
        return jsonify({
            "error": "invalid_request",
            "message": "At least one query parameter ('user_id' or 'category_id') is required for filtration",
        }), 400

    try:
        user_id = int(user_id_raw) if user_id_raw is not None else None
        category_id = int(category_id_raw) if category_id_raw is not None else None
    except ValueError:
        return jsonify({
            "error": "invalid_request",
            "message": "Query parameters 'user_id' and 'category_id' must be integers",
        }), 400

    if current_role() == "user":
        if user_id is not None and user_id != current_user_id():
            return not_found("User not found")
        user_id = current_user_id()

    query = db.select(RecordModel).order_by(RecordModel.id)
    if user_id is not None:
        query = query.where(RecordModel.user_id == user_id)
    if category_id is not None:
        query = query.where(RecordModel.category_id == category_id)

    records = db.session.scalars(query).all()
    return jsonify([r.to_dict() for r in records]), 200


# ---------- CLI: створення адміністратора ----------

@app.cli.command("create-admin")
@click.argument("name")
@click.argument("password")
def create_admin(name, password):
    """Створює адміністратора (або підвищує існуючого користувача до admin)."""
    if len(password) < 8:
        raise click.ClickException("Password must be at least 8 characters long")
    user = db.session.scalars(db.select(UserModel).where(UserModel.name == name)).first()
    if user is None:
        user = UserModel(name=name, password_hash=hash_password(password), role="admin")
        db.session.add(user)
        click.echo(f"Admin '{name}' created")
    else:
        user.role = "admin"
        click.echo(f"User '{name}' promoted to admin")
    db.session.commit()


if __name__ == "__main__":
    app.run(debug=True)