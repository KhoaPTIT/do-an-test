"""MR15 — POST /alerts/{id}/feedback: "Đúng"/"Báo nhầm" ghi vào Alert + nhật ký kiểm toán. CHỈ ghi nhận phản hồi —
KHÔNG chỉnh UserRiskProfile ngay (việc đó là của scripts/retrain_from_feedback.py, xem tests/test_retrain_from_feedback.py)."""

from app.models import Admin, Alert, AuditLog, LoginEvent, User, UserRiskProfile
from app.security import hash_password

ADMIN_PASSWORD = "MatKhauQuanTri123!"


def _admin_token(db_session, client, username="admin"):
    db_session.add(Admin(username=username, password_hash=hash_password(ADMIN_PASSWORD)))
    db_session.commit()
    login = client.post("/admin/login", json={"username": username, "password": ADMIN_PASSWORD})
    return login.json()["access_token"]


def _seed_alert(db_session):
    user = User(username="alice", password_hash="x")
    db_session.add(user)
    db_session.flush()
    event = LoginEvent(user_id=user.id, attempted_username="alice", success=True, ip_address="1.1.1.1")
    db_session.add(event)
    db_session.flush()
    alert = Alert(login_event_id=event.id, user_id=user.id, alert_type="hybrid_risk", severity="high", risk_score=80, message="x", status="open")
    db_session.add(alert)
    db_session.commit()
    return alert


def test_feedback_route_without_token_returns_401(client, db_session):
    alert = _seed_alert(db_session)
    assert client.post(f"/alerts/{alert.id}/feedback", json={"correct": True}).status_code == 401


def test_marking_an_alert_correct_sets_status_resolved_and_writes_an_audit_log(db_session, client):
    token = _admin_token(db_session, client)
    alert = _seed_alert(db_session)

    response = client.post(f"/alerts/{alert.id}/feedback", json={"correct": True, "note": "dung, da xac nhan voi user"}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "resolved"

    db_session.refresh(alert)
    assert alert.status == "resolved" and alert.feedback == "dung, da xac nhan voi user"

    audit = db_session.query(AuditLog).filter(AuditLog.action == "feedback_correct").one()
    assert audit.actor == "admin" and audit.target_type == "alert" and audit.target_id == alert.id


def test_marking_an_alert_false_positive_sets_status_false_positive(db_session, client):
    token = _admin_token(db_session, client)
    alert = _seed_alert(db_session)

    response = client.post(f"/alerts/{alert.id}/feedback", json={"correct": False, "note": "IP van phong that"}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200 and response.json()["status"] == "false_positive"

    audit = db_session.query(AuditLog).filter(AuditLog.action == "feedback_false_positive").one()
    assert audit.detail["note"] == "IP van phong that"


def test_feedback_does_not_touch_user_risk_profile_directly_retrain_script_does_that_separately(db_session, client):
    token = _admin_token(db_session, client)
    alert = _seed_alert(db_session)
    client.post(f"/alerts/{alert.id}/feedback", json={"correct": False}, headers={"Authorization": f"Bearer {token}"})
    assert db_session.query(UserRiskProfile).count() == 0


def test_feedback_can_be_resubmitted_and_each_submission_adds_a_new_audit_log_row(db_session, client):
    token = _admin_token(db_session, client)
    alert = _seed_alert(db_session)

    client.post(f"/alerts/{alert.id}/feedback", json={"correct": False}, headers={"Authorization": f"Bearer {token}"})
    client.post(f"/alerts/{alert.id}/feedback", json={"correct": True, "note": "xem lai, thuc ra dung"}, headers={"Authorization": f"Bearer {token}"})

    db_session.refresh(alert)
    assert alert.status == "resolved" and alert.feedback == "xem lai, thuc ra dung"  # lần sau ghi đè lần trước
    assert db_session.query(AuditLog).filter(AuditLog.target_id == alert.id).count() == 2  # nhưng nhật ký giữ cả hai


def test_feedback_on_an_unknown_alert_returns_404(db_session, client):
    token = _admin_token(db_session, client)
    response = client.post("/alerts/999999/feedback", json={"correct": True}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 404
