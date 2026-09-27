"""MR14 — GET /campaigns, GET /campaigns/{id}: hợp đồng API, độc lập với việc pipeline gán chiến dịch thế nào (đã
kiểm ở tests/test_pipeline_mr14.py) — ở đây dựng thẳng Campaign/Alert/LoginEvent/User để kiểm API."""

from datetime import datetime, timedelta, timezone

from app.models import Admin, Alert, Campaign, LoginEvent, User
from app.security import hash_password

ADMIN_PASSWORD = "MatKhauQuanTri123!"
BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _admin_token(db_session, client):
    db_session.add(Admin(username="admin", password_hash=hash_password(ADMIN_PASSWORD)))
    db_session.commit()
    login = client.post("/admin/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    return login.json()["access_token"]


def _seed_campaign(db_session):
    alice = User(username="alice", password_hash="x")
    bob = User(username="bob", password_hash="x")
    db_session.add_all([alice, bob])
    db_session.flush()

    ev_alice = LoginEvent(user_id=alice.id, attempted_username="alice", success=True, ip_address="1.2.3.4", asn=999, device_type="desktop", created_at=BASE)
    ev_bob = LoginEvent(user_id=bob.id, attempted_username="bob", success=True, ip_address="5.6.7.8", asn=999, device_type="mobile", created_at=BASE + timedelta(hours=1))
    ev_ghost = LoginEvent(user_id=None, attempted_username="ghost1", success=False, ip_address="1.2.3.4", asn=999, device_type=None, created_at=BASE + timedelta(hours=2))
    db_session.add_all([ev_alice, ev_bob, ev_ghost])
    db_session.flush()

    campaign = Campaign(label="Chiến dịch qua ASN 999", attack_family="Danh tiếng hạ tầng", alert_count=3, first_seen_at=BASE, last_seen_at=BASE + timedelta(hours=2))
    db_session.add(campaign)
    db_session.flush()

    for ev, user, severity in ((ev_alice, alice, "high"), (ev_bob, bob, "high"), (ev_ghost, None, "medium")):
        db_session.add(
            Alert(
                login_event_id=ev.id, user_id=user.id if user else None, alert_type="hybrid_risk", severity=severity, risk_score=90,
                message=f"canh bao cho {ev.attempted_username}", campaign_id=campaign.id, created_at=ev.created_at,
            )
        )
    db_session.commit()
    return campaign


def test_campaigns_route_without_token_returns_401(client, db_session):
    assert client.get("/campaigns").status_code == 401


def test_list_campaigns_returns_the_campaign_with_computed_targeted_accounts(db_session, client):
    token = _admin_token(db_session, client)
    _seed_campaign(db_session)

    response = client.get("/campaigns", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["label"] == "Chiến dịch qua ASN 999" and item["attack_family"] == "Danh tiếng hạ tầng"
    assert item["alert_count"] == 3
    assert item["targeted_accounts"] == 3  # alice + bob + 1 mục gộp cho tên đăng nhập không tồn tại


def test_campaign_detail_has_a_timeline_targeted_usernames_and_a_user_ip_asn_device_graph(db_session, client):
    token = _admin_token(db_session, client)
    campaign = _seed_campaign(db_session)

    response = client.get(f"/campaigns/{campaign.id}", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    body = response.json()

    assert len(body["timeline"]) == 3
    assert [item["username"] for item in body["timeline"]] == ["alice", "bob", None]
    assert sorted(body["targeted_usernames"]) == ["(tên đăng nhập không tồn tại)", "alice", "bob"]

    node_ids = {n["id"] for n in body["graph"]["nodes"]}
    assert {"user:alice", "user:bob", "ip:1.2.3.4", "ip:5.6.7.8", "asn:999", "device:desktop", "device:mobile"} <= node_ids
    edges = {(e["source"], e["target"]) for e in body["graph"]["edges"]}
    assert ("user:alice", "ip:1.2.3.4") in edges and ("user:alice", "asn:999") in edges and ("user:bob", "asn:999") in edges


def test_unknown_campaign_id_returns_404(db_session, client):
    token = _admin_token(db_session, client)
    response = client.get("/campaigns/999999", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 404


def test_status_filter_only_returns_matching_campaigns(db_session, client):
    token = _admin_token(db_session, client)
    campaign = _seed_campaign(db_session)
    campaign.status = "closed"
    db_session.commit()

    open_only = client.get("/campaigns", params={"status": "open"}, headers={"Authorization": f"Bearer {token}"})
    closed_only = client.get("/campaigns", params={"status": "closed"}, headers={"Authorization": f"Bearer {token}"})
    assert open_only.json()["total"] == 0 and closed_only.json()["total"] == 1
