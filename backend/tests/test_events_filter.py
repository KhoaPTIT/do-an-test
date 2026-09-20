"""Kiểm tra bộ lọc GET /login-events (nâng cấp sau Tuần 7)."""

from datetime import datetime, timezone

from app.models import Admin, LoginEvent, User
from app.security import hash_password

ADMIN_PASSWORD = "MatKhauQuanTri123!"


def _admin_headers(client, db_session):
    admin = Admin(username="admin", password_hash=hash_password(ADMIN_PASSWORD))
    db_session.add(admin)
    db_session.commit()
    token = client.post("/admin/login", json={"username": "admin", "password": ADMIN_PASSWORD}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _seed_events(db_session):
    user = User(username="alice", password_hash=hash_password("x"))
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    now = datetime.now(timezone.utc)
    events = [
        LoginEvent(user_id=user.id, attempted_username="alice", success=True, ip_address="1.1.1.1", risk_score=10, is_synthetic=False, created_at=now),
        LoginEvent(user_id=user.id, attempted_username="alice", success=False, ip_address="1.1.1.1", risk_score=50, is_synthetic=False, created_at=now),
        LoginEvent(user_id=None, attempted_username="bob", success=False, ip_address="2.2.2.2", risk_score=80, is_synthetic=False, created_at=now),
        LoginEvent(user_id=user.id, attempted_username="alice", success=True, ip_address="1.1.1.1", risk_score=None, is_synthetic=True, created_at=now),
    ]
    db_session.add_all(events)
    db_session.commit()


def test_filter_by_username(client, db_session):
    headers = _admin_headers(client, db_session)
    _seed_events(db_session)

    response = client.get("/login-events", params={"username": "ali"}, headers=headers)
    body = response.json()
    assert body["total"] == 3
    assert all(item["attempted_username"] == "alice" for item in body["items"])


def test_filter_by_success(client, db_session):
    headers = _admin_headers(client, db_session)
    _seed_events(db_session)

    response = client.get("/login-events", params={"success": False}, headers=headers)
    body = response.json()
    assert body["total"] == 2
    assert all(item["success"] is False for item in body["items"])


def test_filter_by_risk_level(client, db_session):
    headers = _admin_headers(client, db_session)
    _seed_events(db_session)

    low = client.get("/login-events", params={"risk_level": "low"}, headers=headers).json()
    medium = client.get("/login-events", params={"risk_level": "medium"}, headers=headers).json()
    high = client.get("/login-events", params={"risk_level": "high"}, headers=headers).json()

    assert low["total"] == 1  # risk_score=10
    assert medium["total"] == 1  # risk_score=50
    assert high["total"] == 1  # risk_score=80


def test_filter_by_is_synthetic(client, db_session):
    headers = _admin_headers(client, db_session)
    _seed_events(db_session)

    real_only = client.get("/login-events", params={"is_synthetic": False}, headers=headers).json()
    synthetic_only = client.get("/login-events", params={"is_synthetic": True}, headers=headers).json()

    assert real_only["total"] == 3
    assert synthetic_only["total"] == 1


def test_combined_filters(client, db_session):
    headers = _admin_headers(client, db_session)
    _seed_events(db_session)

    response = client.get(
        "/login-events",
        params={"username": "alice", "success": True, "is_synthetic": False},
        headers=headers,
    )
    body = response.json()
    assert body["total"] == 1
