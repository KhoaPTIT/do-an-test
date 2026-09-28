"""MR17 — GET /users/{id}/profile: gộp login_events, alerts, known_devices, known_locations, user_risk_profiles của
MỘT tài khoản thành một hồ sơ xem nhanh cho admin (checklist "hồ sơ rủi ro theo user")."""

from datetime import datetime, timedelta, timezone

from app.models import Admin, Alert, KnownDevice, KnownLocation, LoginEvent, User, UserRiskProfile
from app.security import hash_password

ADMIN_PASSWORD = "MatKhauQuanTri123!"
BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _admin_token(db_session, client):
    db_session.add(Admin(username="admin", password_hash=hash_password(ADMIN_PASSWORD)))
    db_session.commit()
    login = client.post("/admin/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    return login.json()["access_token"]


def test_requires_admin_auth(client):
    assert client.get("/users/1/profile").status_code == 401


def test_unknown_user_id_returns_404(client, db_session):
    token = _admin_token(db_session, client)

    response = client.get("/users/999999/profile", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 404


def test_assembles_timeline_alerts_devices_locations_and_risk_profile(client, db_session):
    token = _admin_token(db_session, client)
    user = User(username="alice", password_hash="x", importance=2.0)
    db_session.add(user)
    db_session.flush()

    event = LoginEvent(user_id=user.id, attempted_username="alice", success=True, ip_address="1.1.1.1", created_at=BASE)
    db_session.add(event)
    db_session.flush()
    db_session.add(Alert(login_event_id=event.id, user_id=user.id, alert_type="hybrid_risk", severity="high", risk_score=80, message="test"))
    db_session.add(KnownDevice(user_id=user.id, device_fingerprint="fp1", user_agent="Chrome", first_seen_at=BASE, last_seen_at=BASE))
    db_session.add(KnownLocation(user_id=user.id, country="VN", city="Hanoi", first_seen_at=BASE, last_seen_at=BASE))
    db_session.add(UserRiskProfile(user_id=user.id, threshold_delta=8.0, feedback_count=3, false_positive_count=2))
    db_session.commit()

    response = client.get(f"/users/{user.id}/profile", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    body = response.json()
    assert body["username"] == "alice" and body["importance"] == 2.0
    assert len(body["timeline"]) == 1 and body["timeline"][0]["id"] == event.id
    assert len(body["alerts"]) == 1 and body["alerts"][0]["severity"] == "high"
    assert len(body["known_devices"]) == 1 and body["known_devices"][0]["device_fingerprint"] == "fp1"
    assert len(body["known_locations"]) == 1 and body["known_locations"][0]["country"] == "VN"
    assert body["risk_profile"] == {"threshold_delta": 8.0, "feedback_count": 3, "false_positive_count": 2}


def test_a_user_with_not_enough_feedback_has_a_null_risk_profile_not_an_error(client, db_session):
    token = _admin_token(db_session, client)
    user = User(username="bob", password_hash="x")
    db_session.add(user)
    db_session.commit()

    response = client.get(f"/users/{user.id}/profile", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    body = response.json()
    assert body["risk_profile"] is None
    assert body["timeline"] == [] and body["alerts"] == [] and body["known_devices"] == [] and body["known_locations"] == []


def test_timeline_is_capped_and_most_recent_first(client, db_session):
    from app.routers.users import TIMELINE_LIMIT

    token = _admin_token(db_session, client)
    user = User(username="carol", password_hash="x")
    db_session.add(user)
    db_session.flush()
    for i in range(TIMELINE_LIMIT + 5):
        db_session.add(LoginEvent(user_id=user.id, attempted_username="carol", success=True, ip_address="1.1.1.1", created_at=BASE + timedelta(minutes=i)))
    db_session.commit()

    response = client.get(f"/users/{user.id}/profile", headers={"Authorization": f"Bearer {token}"})

    body = response.json()
    assert len(body["timeline"]) == TIMELINE_LIMIT
    assert body["timeline"][0]["created_at"] > body["timeline"][1]["created_at"]
