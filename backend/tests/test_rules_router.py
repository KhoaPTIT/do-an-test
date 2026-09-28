"""MR17 — GET /rules (danh sách luật + trạng thái hiệu lực), PUT /rules/{id} (bật/tắt + chỉnh tham số),
DELETE /rules/{id} (khôi phục mặc định). Test xác thực JWT admin có sẵn ở tests/test_admin.py."""

from app.detection.engine.registry import REGISTRY
from app.models import Admin, AuditLog, RuleOverride
from app.security import hash_password

ADMIN_PASSWORD = "MatKhauQuanTri123!"
RULE_ID = "brute_force"  # có ít nhất 1 tham số int (threshold) — đủ để kiểm coerce/validate


def _admin_token(db_session, client):
    db_session.add(Admin(username="admin", password_hash=hash_password(ADMIN_PASSWORD)))
    db_session.commit()
    login = client.post("/admin/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    return login.json()["access_token"]


def test_list_and_update_require_admin_auth(client):
    assert client.get("/rules").status_code == 401
    assert client.put(f"/rules/{RULE_ID}", json={"mode": "off"}).status_code == 401
    assert client.delete(f"/rules/{RULE_ID}").status_code == 401


def test_list_returns_every_registered_rule_at_its_default_mode_when_no_override_exists(client, db_session):
    token = _admin_token(db_session, client)

    response = client.get("/rules", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    items = response.json()
    assert len(items) == len(REGISTRY)
    by_id = {r["id"]: r for r in items}
    assert RULE_ID in by_id
    rule = by_id[RULE_ID]
    assert rule["mode"] == rule["default_mode"] and rule["is_overridden"] is False
    assert rule["updated_by"] is None and rule["updated_at"] is None
    assert any(p["value"] == p["default"] for p in rule["params"])


def test_put_mode_only_creates_an_override_writes_audit_log_and_does_not_touch_params(client, db_session):
    token = _admin_token(db_session, client)
    headers = {"Authorization": f"Bearer {token}"}

    response = client.put(f"/rules/{RULE_ID}", json={"mode": "off"}, headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "off" and body["is_overridden"] is True
    assert body["updated_by"] == "admin"

    row = db_session.get(RuleOverride, RULE_ID)
    assert row is not None and row.mode == "off" and row.params is None

    log = db_session.query(AuditLog).filter(AuditLog.action == "update_rule_config").one()
    assert log.actor == "admin" and log.detail["rule_id"] == RULE_ID and log.detail["mode"] == "off"


def test_put_params_only_leaves_an_existing_mode_override_untouched(client, db_session):
    token = _admin_token(db_session, client)
    headers = {"Authorization": f"Bearer {token}"}
    client.put(f"/rules/{RULE_ID}", json={"mode": "shadow"}, headers=headers)

    spec = REGISTRY[RULE_ID]
    param = spec.params[0]
    new_value = param.default if not isinstance(param.default, (int, float)) or isinstance(param.default, bool) else param.default + 1

    response = client.put(f"/rules/{RULE_ID}", json={"params": {param.name: new_value}}, headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "shadow"  # KHÔNG bị đổi lại default — request này không gửi "mode"
    changed = next(p for p in body["params"] if p["name"] == param.name)
    assert changed["value"] == new_value


def test_put_with_an_unknown_param_name_returns_422(client, db_session):
    token = _admin_token(db_session, client)

    response = client.put(f"/rules/{RULE_ID}", json={"params": {"khong_ton_tai": 1}}, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 422


def test_put_with_an_invalid_mode_returns_422(client, db_session):
    token = _admin_token(db_session, client)

    response = client.put(f"/rules/{RULE_ID}", json={"mode": "khong_hop_le"}, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 422


def test_put_an_unknown_rule_id_returns_404(client, db_session):
    token = _admin_token(db_session, client)

    response = client.put("/rules/khong_ton_tai", json={"mode": "off"}, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 404


def test_delete_removes_the_override_and_reverts_to_the_registry_default(client, db_session):
    token = _admin_token(db_session, client)
    headers = {"Authorization": f"Bearer {token}"}
    client.put(f"/rules/{RULE_ID}", json={"mode": "off"}, headers=headers)
    assert db_session.get(RuleOverride, RULE_ID) is not None

    response = client.delete(f"/rules/{RULE_ID}", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == body["default_mode"] and body["is_overridden"] is False
    assert db_session.get(RuleOverride, RULE_ID) is None
    assert db_session.query(AuditLog).filter(AuditLog.action == "reset_rule_config").count() == 1


def test_live_pipeline_now_respects_a_rule_override_that_used_to_be_ignored(db_session):
    """Trước MR17: build_rule_engine(db) (không truyền config) LUÔN chấm bằng mặc định sổ đăng ký — ghi đè trong DB
    (nếu có cơ chế nào ghi) không hề được đọc. Kiểm TRỰC TIẾP dây nối build_rule_engine -> refresh_rule_config."""
    from app.detection.rule_engine_runtime import build_rule_engine, invalidate_rule_config_cache

    db_session.add(RuleOverride(rule_id=RULE_ID, mode="off", updated_by="test"))
    db_session.commit()
    invalidate_rule_config_cache()

    engine = build_rule_engine(db_session)

    assert engine.config.mode_of(REGISTRY[RULE_ID]) == "off"
