"""MR16 — router-level: precheck chặn tài khoản/IP/ASN đã khoá TRƯỚC KHI xác thực mật khẩu; mật khẩu ĐÚNG nhưng hybrid
risk engine đề xuất step_up/lock cho CHÍNH lần thử này phải THỰC THI (không chỉ recommend) trước khi trả response;
POST /login/verify-otp hoàn tất bước xác thực thêm.

Logic THUẦN (sinh/so khớp OTP, chọn khoá tài khoản hay IP) đã kiểm ở test_response_execution.py; logic THỰC THI lock
BÊN TRONG pipeline (tạo/gia hạn BlocklistEntry, đổi status "executed") đã kiểm ở test_pipeline_mr12.py/mr13.py — file
này chỉ kiểm HÀNH VI HTTP đầu-cuối của app/routers/auth.py (đường đi nào được chọn, response trả gì)."""

from datetime import datetime, timedelta, timezone

from app.detection import hybrid_runtime
from app.detection.hybrid import Contribution, RiskResult
from app.detection.response_execution import OTP_MAX_ATTEMPTS
from app.models import AuditLog, BlocklistEntry, LoginEvent, OtpChallenge, ResponseAction, User
from app.security import hash_password

PASSWORD = "CorrectHorse123"
CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
GOOGLE_DNS = "8.8.8.8"  # ASN 15169 thật (GeoLite2-ASN.mmdb) — đã xác nhận ở test_pipeline_mr12.py
OTP_INVALID_MESSAGE = "Mã xác thực không đúng hoặc đã hết hạn."


def _create_user(db_session, username="alice", password=PASSWORD):
    user = User(username=username, password_hash=hash_password(password))
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _force_action(monkeypatch, action, score=60):
    """Ép hybrid risk engine trả về `action` cố định — như _spy_on_evaluate trong test_pipeline_mr15.py. `step_up`
    không có "cửa" deterministic nào như blocklist_hit (chỉ ép ra được `lock`), nên phải ép thẳng ở đây thay vì dựng
    một kịch bản điểm số mong manh qua toàn bộ rule engine + mô hình thật."""
    engine = hybrid_runtime.get_engine()
    result = RiskResult(
        score=score, action=action, probability=score / 100, ml_probability=None, rule_probability=score / 100,
        reputation_probability=0.0, overridden_by=None,
        contributions=(Contribution(source="test", label="ép hành động cho test", weight=score / 100, group="rule"),),
    )
    monkeypatch.setattr(engine, "evaluate", lambda features, hits, bands=None: result)


# --------------------------------------------------------------------------------- (1) precheck chặn TRƯỚC mật khẩu


def test_a_blocklisted_ip_is_rejected_before_password_is_even_checked(client, db_session, monkeypatch):
    monkeypatch.setattr("app.routers.auth.resolve_client_ip", lambda request: "203.0.113.66")
    _create_user(db_session, "alice")
    db_session.add(BlocklistEntry(kind="ip", value="203.0.113.66", reason="test MR16", added_by="test"))
    db_session.commit()

    response = client.post("/login", json={"username": "alice", "password": PASSWORD}, headers={"user-agent": CHROME_UA})

    assert response.status_code == 423
    assert response.json()["locked"] is True
    # Bị chặn NGAY từ precheck -> không chạy pipeline -> không LoginEvent/ResponseAction nào được tạo cho lần này.
    assert db_session.query(LoginEvent).count() == 0
    assert db_session.query(ResponseAction).count() == 0

    log = db_session.query(AuditLog).filter(AuditLog.action == "reject_blocked_login").one()
    assert log.detail["blocklist_kind"] == "ip" and log.detail["blocklist_value"] == "203.0.113.66"


def test_a_blocklisted_username_is_rejected_even_from_an_unblocked_ip(client, db_session):
    _create_user(db_session, "alice")
    db_session.add(BlocklistEntry(kind="username", value="alice", reason="test MR16", added_by="test"))
    db_session.commit()

    response = client.post("/login", json={"username": "alice", "password": PASSWORD}, headers={"user-agent": CHROME_UA})

    assert response.status_code == 423
    assert response.json()["locked"] is True


def test_wrong_password_against_a_blocklisted_ip_is_also_rejected_by_precheck(client, db_session, monkeypatch):
    """Khoá là khoá — sai mật khẩu hay đúng mật khẩu không quan trọng khi nguồn/tài khoản đã bị khoá."""
    monkeypatch.setattr("app.routers.auth.resolve_client_ip", lambda request: "203.0.113.66")
    _create_user(db_session, "alice")
    db_session.add(BlocklistEntry(kind="ip", value="203.0.113.66", reason="test MR16", added_by="test"))
    db_session.commit()

    response = client.post("/login", json={"username": "alice", "password": "SaiMatKhau"}, headers={"user-agent": CHROME_UA})

    assert response.status_code == 423


def test_an_expired_block_no_longer_rejects_at_precheck(client, db_session, monkeypatch):
    monkeypatch.setattr("app.routers.auth.resolve_client_ip", lambda request: "203.0.113.66")
    _create_user(db_session, "alice")
    db_session.add(BlocklistEntry(
        kind="ip", value="203.0.113.66", reason="test MR16", added_by="test",
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
    ))
    db_session.commit()

    response = client.post("/login", json={"username": "alice", "password": PASSWORD}, headers={"user-agent": CHROME_UA})

    assert response.status_code == 200


# --------------------------------------------------------------------------------- (2) khoá quyết định SAU khi mật khẩu đúng


def test_correct_password_locked_by_an_asn_block_the_precheck_cannot_see_is_still_caught_after_scoring(client, db_session, monkeypatch):
    """Precheck KHÔNG tra ASN (đắt — xem comment trong auth.py) nên một khối chặn theo ASN "lọt" qua precheck — nhưng
    pipeline (chạy sau khi mật khẩu đúng) CÓ tra ASN thật nên vẫn bắt được: không phải lỗ hổng, chỉ chậm hơn đường
    precheck rẻ cho đúng trường hợp hiếm này."""
    monkeypatch.setattr("app.routers.auth.resolve_client_ip", lambda request: GOOGLE_DNS)
    _create_user(db_session, "alice")
    db_session.add(BlocklistEntry(kind="asn", value="15169", reason="test MR16", added_by="test"))
    db_session.commit()

    response = client.post("/login", json={"username": "alice", "password": PASSWORD}, headers={"user-agent": CHROME_UA})

    assert response.status_code == 423
    assert response.json()["locked"] is True
    # CÓ chạy pipeline lần này (khác precheck-reject phía trên) vì mãi tới sau khi chấm điểm mới biết phải khoá.
    event = db_session.query(LoginEvent).one()
    assert event.hybrid_action == "lock"
    assert db_session.query(AuditLog).filter(AuditLog.action == "execute_lock").count() == 1


# --------------------------------------------------------------------------------- (3) step_up (OTP giả lập)


def test_correct_password_with_step_up_action_returns_an_otp_challenge_not_a_successful_login(client, db_session, monkeypatch):
    _create_user(db_session, "alice")
    _force_action(monkeypatch, "step_up")

    response = client.post("/login", json={"username": "alice", "password": PASSWORD}, headers={"user-agent": CHROME_UA})

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is False and body["step_up_required"] is True
    assert body["challenge_id"] is not None
    assert body["demo_otp_code"] is not None and len(body["demo_otp_code"]) == 6 and body["demo_otp_code"].isdigit()

    challenge = db_session.query(OtpChallenge).one()
    assert challenge.user_id is not None and challenge.verified_at is None and challenge.attempts == 0
    assert challenge.code_hash != body["demo_otp_code"]  # không lưu bản rõ

    action = db_session.query(ResponseAction).filter(ResponseAction.action == "step_up").one()
    assert action.status == "executed" and action.executed_at is not None

    log = db_session.query(AuditLog).filter(AuditLog.action == "execute_step_up").one()
    assert log.detail["otp_challenge_id"] == challenge.id


def test_verify_otp_with_the_correct_code_completes_the_login(client, db_session, monkeypatch):
    _create_user(db_session, "alice")
    _force_action(monkeypatch, "step_up")
    login = client.post("/login", json={"username": "alice", "password": PASSWORD}, headers={"user-agent": CHROME_UA}).json()

    response = client.post("/login/verify-otp", json={"challenge_id": login["challenge_id"], "code": login["demo_otp_code"]})

    assert response.status_code == 200
    assert response.json() == {
        "success": True, "message": "Login successful",
        "step_up_required": False, "challenge_id": None, "demo_otp_code": None, "locked": False,
        "role": "user", "access_token": None,
    }
    challenge = db_session.query(OtpChallenge).one()
    assert challenge.verified_at is not None


def test_verify_otp_with_the_wrong_code_fails_with_a_generic_message_and_counts_the_attempt(client, db_session, monkeypatch):
    _create_user(db_session, "alice")
    _force_action(monkeypatch, "step_up")
    login = client.post("/login", json={"username": "alice", "password": PASSWORD}, headers={"user-agent": CHROME_UA}).json()
    wrong_code = "000000" if login["demo_otp_code"] != "000000" else "111111"

    response = client.post("/login/verify-otp", json={"challenge_id": login["challenge_id"], "code": wrong_code})

    assert response.status_code == 200
    assert response.json()["success"] is False
    assert response.json()["message"] == OTP_INVALID_MESSAGE
    challenge = db_session.query(OtpChallenge).one()
    assert challenge.attempts == 1 and challenge.verified_at is None


def test_verify_otp_with_an_unknown_challenge_id_fails_with_the_same_generic_message(client, db_session):
    """Không lộ 'challenge không tồn tại' vs 'sai mã' — cùng triết lý với thông báo sai mật khẩu/tài khoản không tồn tại."""
    _create_user(db_session, "alice")

    response = client.post("/login/verify-otp", json={"challenge_id": 999999, "code": "123456"})

    assert response.status_code == 200
    assert response.json()["message"] == OTP_INVALID_MESSAGE


def test_verify_otp_after_too_many_wrong_attempts_rejects_even_the_correct_code(client, db_session, monkeypatch):
    _create_user(db_session, "alice")
    _force_action(monkeypatch, "step_up")
    login = client.post("/login", json={"username": "alice", "password": PASSWORD}, headers={"user-agent": CHROME_UA}).json()
    wrong_code = "000000" if login["demo_otp_code"] != "000000" else "111111"

    for _ in range(OTP_MAX_ATTEMPTS):
        client.post("/login/verify-otp", json={"challenge_id": login["challenge_id"], "code": wrong_code})

    response = client.post("/login/verify-otp", json={"challenge_id": login["challenge_id"], "code": login["demo_otp_code"]})

    assert response.json()["success"] is False


def test_verify_otp_after_expiry_rejects_even_the_correct_code(client, db_session, monkeypatch):
    _create_user(db_session, "alice")
    _force_action(monkeypatch, "step_up")
    login = client.post("/login", json={"username": "alice", "password": PASSWORD}, headers={"user-agent": CHROME_UA}).json()

    challenge = db_session.query(OtpChallenge).one()
    challenge.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()

    response = client.post("/login/verify-otp", json={"challenge_id": login["challenge_id"], "code": login["demo_otp_code"]})

    assert response.json()["success"] is False


def test_verify_otp_cannot_be_replayed_after_a_successful_verification(client, db_session, monkeypatch):
    _create_user(db_session, "alice")
    _force_action(monkeypatch, "step_up")
    login = client.post("/login", json={"username": "alice", "password": PASSWORD}, headers={"user-agent": CHROME_UA}).json()
    client.post("/login/verify-otp", json={"challenge_id": login["challenge_id"], "code": login["demo_otp_code"]})

    replay = client.post("/login/verify-otp", json={"challenge_id": login["challenge_id"], "code": login["demo_otp_code"]})

    assert replay.json()["success"] is False
