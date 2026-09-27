"""MR16 — GET /blocklist (danh sách khoá tạm/chặn) + DELETE /blocklist/{id} ("nút mở khoá" của checklist). Test xác
thực JWT admin có sẵn ở tests/test_admin.py; logic thực thi lock (tạo/gia hạn mục chặn) đã kiểm ở test_pipeline_mr12.py."""

from datetime import datetime, timedelta, timezone

from app.models import Admin, AuditLog, BlocklistEntry, User
from app.security import hash_password

ADMIN_PASSWORD = "MatKhauQuanTri123!"
PASSWORD = "CorrectHorse123"


def _admin_token(db_session, client):
    db_session.add(Admin(username="admin", password_hash=hash_password(ADMIN_PASSWORD)))
    db_session.commit()
    login = client.post("/admin/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    return login.json()["access_token"]


def test_list_and_delete_require_admin_auth(client, db_session):
    entry = BlocklistEntry(kind="ip", value="203.0.113.66", reason="x", added_by="test")
    db_session.add(entry)
    db_session.commit()

    assert client.get("/blocklist").status_code == 401
    assert client.delete(f"/blocklist/{entry.id}").status_code == 401


def test_list_returns_only_active_entries_by_default(client, db_session):
    token = _admin_token(db_session, client)
    now = datetime.now(timezone.utc)
    active = BlocklistEntry(kind="ip", value="203.0.113.1", reason="active", added_by="test", expires_at=now + timedelta(minutes=30))
    expired = BlocklistEntry(kind="ip", value="203.0.113.2", reason="expired", added_by="test", expires_at=now - timedelta(minutes=1))
    permanent = BlocklistEntry(kind="username", value="ghost", reason="permanent", added_by="admin")
    db_session.add_all([active, expired, permanent])
    db_session.commit()

    response = client.get("/blocklist", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    values = {item["value"] for item in response.json()["items"]}
    assert values == {"203.0.113.1", "ghost"}
    assert response.json()["total"] == 2

    all_response = client.get("/blocklist?active_only=false", headers={"Authorization": f"Bearer {token}"})
    assert all_response.json()["total"] == 3


def test_delete_removes_the_entry_writes_an_audit_log_and_invalidates_the_cache(client, db_session):
    token = _admin_token(db_session, client)
    alice = User(username="alice", password_hash=hash_password(PASSWORD))
    db_session.add(alice)
    db_session.commit()
    db_session.refresh(alice)

    entry = BlocklistEntry(kind="ip", value="203.0.113.66", reason="test unlock", added_by="test")
    db_session.add(entry)
    db_session.commit()
    entry_id = entry.id

    response = client.delete(f"/blocklist/{entry_id}", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 204
    assert db_session.query(BlocklistEntry).filter(BlocklistEntry.id == entry_id).first() is None

    log = db_session.query(AuditLog).filter(AuditLog.action == "unlock").one()
    assert log.actor == "admin" and log.target_type == "blocklist" and log.target_id == entry_id
    assert log.detail["kind"] == "ip" and log.detail["value"] == "203.0.113.66"

    # Mở khoá THẬT: đăng nhập lại từ IP vừa gỡ không còn bị precheck (auth.py, MR16) chặn nữa (cache 15s bị vô hiệu ngay).
    login = client.post("/login", json={"username": "alice", "password": PASSWORD})
    assert login.status_code != 423


def test_delete_a_nonexistent_entry_returns_404(client, db_session):
    token = _admin_token(db_session, client)

    response = client.delete("/blocklist/999999", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 404
