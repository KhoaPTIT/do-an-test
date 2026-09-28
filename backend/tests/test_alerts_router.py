"""MR13 — GET /alerts mặc định sắp theo `priority_score` (novelty × độ tin cậy × importance), không còn luôn mới nhất
lên đầu; `sort=recent` giữ lại hành vi cũ (MR12 trở về trước). Test xác thực JWT admin có sẵn ở tests/test_admin.py."""

from datetime import datetime, timedelta, timezone

from app.models import Admin, Alert, LoginEvent, User
from app.security import hash_password

ADMIN_PASSWORD = "MatKhauQuanTri123!"
BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _admin_token(db_session, client):
    db_session.add(Admin(username="admin", password_hash=hash_password(ADMIN_PASSWORD)))
    db_session.commit()
    login = client.post("/admin/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    return login.json()["access_token"]


def _seed_two_alerts(db_session):
    user = User(username="alice", password_hash="x")
    db_session.add(user)
    db_session.flush()
    event = LoginEvent(user_id=user.id, attempted_username="alice", success=True, ip_address="1.1.1.1", created_at=BASE)
    db_session.add(event)
    db_session.flush()

    # "low_priority" tạo TRƯỚC (created_at mặc định = lúc chạy test, nhưng thêm trước -> id nhỏ hơn) nhưng priority_score THẤP hơn.
    low_priority = Alert(login_event_id=event.id, user_id=user.id, alert_type="hybrid_risk", severity="medium", risk_score=40, message="thap", priority_score=0.5)
    db_session.add(low_priority)
    db_session.flush()
    high_priority = Alert(login_event_id=event.id, user_id=user.id, alert_type="hybrid_risk", severity="high", risk_score=90, message="cao", priority_score=3.2)
    db_session.add(high_priority)
    db_session.commit()
    return low_priority, high_priority


def test_default_sort_is_priority_not_created_at(db_session, client):
    token = _admin_token(db_session, client)
    low, high = _seed_two_alerts(db_session)

    response = client.get("/alerts", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    ids = [item["id"] for item in response.json()["items"]]
    assert ids == [high.id, low.id]  # priority_score 3.2 lên trước 0.5, dù low.id được TẠO trước (id nhỏ hơn)


def test_sort_recent_keeps_the_old_newest_first_behaviour(db_session, client):
    token = _admin_token(db_session, client)
    low, high = _seed_two_alerts(db_session)

    response = client.get("/alerts", params={"sort": "recent"}, headers={"Authorization": f"Bearer {token}"})
    ids = [item["id"] for item in response.json()["items"]]
    assert ids == [high.id, low.id]  # high được tạo SAU low (id lớn hơn, created_at cũng sau) -> mới nhất lên trước


def test_alerts_older_than_mr13_without_a_priority_score_sort_to_the_bottom_not_the_top(db_session, client):
    """NULLS LAST: alert cũ (trước MR13, priority_score chưa từng được tính) không được CHEN LÊN ĐẦU vì NULL — phải rơi
    xuống dưới alert mới có priority_score, kể cả priority_score đó rất thấp."""
    token = _admin_token(db_session, client)
    user = User(username="bob", password_hash="x")
    db_session.add(user)
    db_session.flush()
    event = LoginEvent(user_id=user.id, attempted_username="bob", success=True, ip_address="2.2.2.2", created_at=BASE)
    db_session.add(event)
    db_session.flush()
    legacy = Alert(login_event_id=event.id, user_id=user.id, alert_type="brute_force", severity="high", risk_score=80, message="cu", priority_score=None)
    db_session.add(legacy)
    new = Alert(login_event_id=event.id, user_id=user.id, alert_type="hybrid_risk", severity="low", risk_score=10, message="moi", priority_score=0.1)
    db_session.add(new)
    db_session.commit()

    response = client.get("/alerts", headers={"Authorization": f"Bearer {token}"})
    ids = [item["id"] for item in response.json()["items"]]
    assert ids == [new.id, legacy.id]


# ------------------------------------------------------------------------------------------------------- MR17: bộ lọc


def _seed_filterable_alerts(db_session):
    user = User(username="alice", password_hash="x")
    db_session.add(user)
    db_session.flush()
    event = LoginEvent(user_id=user.id, attempted_username="alice", success=True, ip_address="1.1.1.1", created_at=BASE)
    db_session.add(event)
    db_session.flush()

    a = Alert(login_event_id=event.id, user_id=user.id, alert_type="hybrid_risk", severity="high", risk_score=90,
              message="a", attack_family="Đoán và dò mật khẩu", rule_id="brute_force", campaign_id=None, status="open")
    b = Alert(login_event_id=event.id, user_id=user.id, alert_type="hybrid_risk", severity="medium", risk_score=50,
              message="b", attack_family="Danh tiếng hạ tầng", rule_id="blocklist_hit", campaign_id=None, status="resolved")
    db_session.add_all([a, b])
    db_session.commit()
    return a, b


def test_filters_by_attack_family(db_session, client):
    token = _admin_token(db_session, client)
    a, b = _seed_filterable_alerts(db_session)

    response = client.get("/alerts", params={"attack_family": "Đoán và dò mật khẩu"}, headers={"Authorization": f"Bearer {token}"})
    ids = {item["id"] for item in response.json()["items"]}
    assert ids == {a.id}


def test_filters_by_rule_id(db_session, client):
    token = _admin_token(db_session, client)
    a, b = _seed_filterable_alerts(db_session)

    response = client.get("/alerts", params={"rule_id": "blocklist_hit"}, headers={"Authorization": f"Bearer {token}"})
    ids = {item["id"] for item in response.json()["items"]}
    assert ids == {b.id}


def test_filters_by_status(db_session, client):
    token = _admin_token(db_session, client)
    a, b = _seed_filterable_alerts(db_session)

    response = client.get("/alerts", params={"status": "resolved"}, headers={"Authorization": f"Bearer {token}"})
    ids = {item["id"] for item in response.json()["items"]}
    assert ids == {b.id}


def test_filters_by_campaign_id(db_session, client):
    token = _admin_token(db_session, client)
    user = User(username="carol", password_hash="x")
    db_session.add(user)
    db_session.flush()
    event = LoginEvent(user_id=user.id, attempted_username="carol", success=True, ip_address="3.3.3.3", created_at=BASE)
    db_session.add(event)
    db_session.flush()
    from app.models import Campaign

    campaign = Campaign(label="test", alert_count=1, first_seen_at=BASE, last_seen_at=BASE)
    db_session.add(campaign)
    db_session.flush()
    in_campaign = Alert(login_event_id=event.id, user_id=user.id, alert_type="hybrid_risk", severity="high", risk_score=90, message="x", campaign_id=campaign.id)
    outside = Alert(login_event_id=event.id, user_id=user.id, alert_type="hybrid_risk", severity="high", risk_score=90, message="y", campaign_id=None)
    db_session.add_all([in_campaign, outside])
    db_session.commit()

    response = client.get("/alerts", params={"campaign_id": campaign.id}, headers={"Authorization": f"Bearer {token}"})
    ids = {item["id"] for item in response.json()["items"]}
    assert ids == {in_campaign.id}


def test_an_invalid_status_value_returns_422(db_session, client):
    token = _admin_token(db_session, client)

    response = client.get("/alerts", params={"status": "khong_hop_le"}, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 422
