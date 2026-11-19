import pytest


def make_account(client, owner, balance=1000):
    r = client.post("/account", headers=owner["headers"], json={"user_id": owner["id"]})
    assert r.status_code == 201
    account_id = r.json["id"]
    r = client.post(
        f"/account/{account_id}/topup", headers=owner["headers"], json={"amount": balance}
    )
    assert r.status_code == 200
    return account_id


def make_global_category(client, admin, name="Food"):
    r = client.post("/category/global", headers=admin["headers"], json={"name": name})
    assert r.status_code == 201
    return r.json["id"]


def make_record(client, owner, category_id, amount=10):
    r = client.post(
        "/record",
        headers=owner["headers"],
        json={"user_id": owner["id"], "category_id": category_id, "amount": amount},
    )
    assert r.status_code == 201
    return r.json["id"]


@pytest.mark.parametrize("role,expected", [("user", 403), ("auditor", 200), ("admin", 200)])
def test_users_list_access(client, user, auditor, admin, role, expected):
    actor = {"user": user, "auditor": auditor, "admin": admin}[role]
    assert client.get("/users", headers=actor["headers"]).status_code == expected


def test_profile_access(client, user, other_user, auditor):
    assert client.get(f"/user/{user['id']}", headers=user["headers"]).status_code == 200
    assert client.get(f"/user/{other_user['id']}", headers=user["headers"]).status_code == 404
    assert client.get(f"/user/{other_user['id']}", headers=auditor["headers"]).status_code == 200


@pytest.mark.parametrize("role,expected", [("user", 403), ("auditor", 403), ("admin", 204)])
def test_delete_user_access(client, user, other_user, auditor, admin, role, expected):
    actor = {"user": user, "auditor": auditor, "admin": admin}[role]
    r = client.delete(f"/user/{other_user['id']}", headers=actor["headers"])
    assert r.status_code == expected


def test_change_role(client, user, admin):
    path = f"/user/{user['id']}/role"
    assert client.patch(path, headers=user["headers"], json={"role": "admin"}).status_code == 403
    r = client.patch(path, headers=admin["headers"], json={"role": "auditor"})
    assert r.status_code == 200 and r.json["role"] == "auditor"
    assert client.patch(path, headers=admin["headers"], json={"role": "root"}).status_code == 400


def test_rbac_forbidden_access(client, user_jwt_header):
    response = client.post("/category/global", headers=user_jwt_header, json={"name": "Global"})
    assert response.status_code == 403
    assert response.json["error"] == "forbidden"


@pytest.mark.parametrize("role,expected", [("user", 403), ("auditor", 403), ("admin", 201)])
def test_global_category_creation(client, user, auditor, admin, role, expected):
    actor = {"user": user, "auditor": auditor, "admin": admin}[role]
    r = client.post("/category/global", headers=actor["headers"], json={"name": "G"})
    assert r.status_code == expected


def test_personal_categories_visibility(client, user, other_user, auditor, admin):
    global_id = make_global_category(client, admin)
    mine = client.post("/category", headers=user["headers"], json={"name": "Mine"}).json["id"]
    theirs = client.post("/category", headers=other_user["headers"], json={"name": "Theirs"}).json["id"]

    user_ids = {c["id"] for c in client.get("/category", headers=user["headers"]).json}
    assert user_ids == {global_id, mine}

    auditor_ids = {c["id"] for c in client.get("/category", headers=auditor["headers"]).json}
    assert auditor_ids == {global_id, mine, theirs}

    assert client.post("/category", headers=auditor["headers"], json={"name": "X"}).status_code == 403


def test_delete_category_admin_only(client, user, auditor, admin):
    category_id = make_global_category(client, admin)
    assert client.delete(f"/category/{category_id}", headers=user["headers"]).status_code == 403
    assert client.delete(f"/category/{category_id}", headers=auditor["headers"]).status_code == 403
    assert client.delete(f"/category/{category_id}", headers=admin["headers"]).status_code == 204


def test_auditor_cannot_create_record(client, user, auditor, admin):
    category_id = make_global_category(client, admin)
    make_account(client, user)
    r = client.post(
        "/record",
        headers=auditor["headers"],
        json={"user_id": user["id"], "category_id": category_id, "amount": 5},
    )
    assert r.status_code == 403


def test_user_cannot_create_record_for_another_user(client, user, other_user, admin):
    category_id = make_global_category(client, admin)
    make_account(client, other_user)
    r = client.post(
        "/record",
        headers=user["headers"],
        json={"user_id": other_user["id"], "category_id": category_id, "amount": 5},
    )
    assert r.status_code == 404


def test_user_cannot_use_foreign_personal_category(client, user, other_user):
    foreign = client.post("/category", headers=other_user["headers"], json={"name": "T"}).json["id"]
    make_account(client, user)
    r = client.post(
        "/record",
        headers=user["headers"],
        json={"user_id": user["id"], "category_id": foreign, "amount": 5},
    )
    assert r.status_code == 404


def test_record_access_matrix(client, user, other_user, auditor, admin):
    category_id = make_global_category(client, admin)
    make_account(client, user)
    record_id = make_record(client, user, category_id)
    path = f"/record/{record_id}"

    assert client.get(path, headers=user["headers"]).status_code == 200
    assert client.get(path, headers=other_user["headers"]).status_code == 404
    assert client.get(path, headers=auditor["headers"]).status_code == 200
    assert client.get(path, headers=admin["headers"]).status_code == 200

    assert client.delete(path, headers=other_user["headers"]).status_code == 404
    assert client.delete(path, headers=auditor["headers"]).status_code == 403
    assert client.delete(path, headers=user["headers"]).status_code == 204
    assert client.get(path, headers=user["headers"]).status_code == 404


def test_admin_can_delete_any_record(client, user, admin):
    category_id = make_global_category(client, admin)
    make_account(client, user)
    record_id = make_record(client, user, category_id)
    assert client.delete(f"/record/{record_id}", headers=admin["headers"]).status_code == 204


def test_record_filtering_rules(client, user, other_user, auditor, admin):
    category_id = make_global_category(client, admin)
    make_account(client, user)
    make_account(client, other_user)
    make_record(client, user, category_id)
    make_record(client, other_user, category_id)

    assert client.get("/record", headers=user["headers"]).status_code == 400

    r = client.get(f"/record?user_id={user['id']}", headers=user["headers"])
    assert r.status_code == 200 and len(r.json) == 1

    r = client.get(f"/record?user_id={other_user['id']}", headers=user["headers"])
    assert r.status_code == 404

    r = client.get(f"/record?category_id={category_id}", headers=user["headers"])
    assert len(r.json) == 1

    r = client.get(f"/record?user_id={other_user['id']}", headers=auditor["headers"])
    assert r.status_code == 200 and len(r.json) == 1

    r = client.get(f"/record?category_id={category_id}", headers=admin["headers"])
    assert len(r.json) == 2


def test_balance_deduction_and_insufficient_funds(client, user, admin):
    category_id = make_global_category(client, admin)
    account_id = make_account(client, user, balance=100)

    r = client.post(
        "/record",
        headers=user["headers"],
        json={"user_id": user["id"], "category_id": category_id, "amount": 40},
    )
    assert r.status_code == 201 and r.json["remaining_balance"] == 60

    r = client.post(
        "/record",
        headers=user["headers"],
        json={"user_id": user["id"], "category_id": category_id, "amount": 100},
    )
    assert r.status_code == 400 and r.json["error"] == "insufficient_funds"

    r = client.get(f"/account/{account_id}", headers=user["headers"])
    assert r.json["balance"] == 60


def test_account_access(client, user, other_user, auditor):
    account_id = make_account(client, user)
    path = f"/account/{account_id}"

    assert client.get(path, headers=other_user["headers"]).status_code == 404
    assert client.post(path + "/topup", headers=other_user["headers"], json={"amount": 5}).status_code == 404
    assert client.get(path, headers=auditor["headers"]).status_code == 200
    assert client.post(path + "/topup", headers=auditor["headers"], json={"amount": 5}).status_code == 403