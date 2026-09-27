"""MR12 — tích hợp realtime: parse UA + tra ASN trong pipeline, rule engine v2 (MR9-10) + hybrid risk engine (MR11)
CHẠY SONG SONG tầng 1-2-3 (KHÔNG THAY THẾ), lỗi ở khối MR12 không được làm mất alert tầng 1-2-3.

`client` fixture (conftest.py) khiến `TestClient(app)` chạy sự kiện "startup" của `app/main.py`, TỰ ĐĂNG KÝ và TỰ NẠP
mô hình hybrid thật (artifact có sẵn trên đĩa) vào DB TEST (SQLite, nhờ monkeypatch `app.main.SessionLocal`) — nên mọi
test dùng `client` mặc định CÓ SẴN `hybrid_runtime.get_engine().ml_available is True`, không cần tự đăng ký."""

import asyncio
from datetime import datetime, timezone

from app.detection import hybrid_runtime
from app.detection.hybrid.calibration import ACTIONS
from app.detection.pipeline import run_detection_pipeline
from app.models import Alert, AuditLog, BlocklistEntry, LoginEvent, ResponseAction, User
from app.security import hash_password

PASSWORD = "CorrectHorse123"
CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


def _create_user(db_session, username="alice", password=PASSWORD):
    user = User(username=username, password_hash=hash_password(password))
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def test_login_event_stores_the_parsed_user_agent(client, db_session):
    """TestClient không gửi IP thật (`request.client.host == "testclient"`, không phải địa chỉ hợp lệ) nên tra ASN qua
    HTTP không kiểm được ở đây — xem `test_asn_is_looked_up_for_a_real_public_ip` (gọi thẳng pipeline với IP thật)."""
    _create_user(db_session, "alice")
    response = client.post("/login", json={"username": "alice", "password": PASSWORD}, headers={"user-agent": CHROME_UA})
    assert response.status_code == 200

    event = db_session.query(LoginEvent).one()
    assert event.os_name and event.browser_name and event.device_type == "desktop"


def test_asn_is_looked_up_for_a_real_public_ip(db_session):
    """Gọi thẳng `run_detection_pipeline` (không qua HTTP) với một IP công khai thật (Google, ASN 15169) — dùng file
    GeoLite2-ASN.mmdb THẬT đã cài ở MR12, không phải chế độ mock."""
    user = _create_user(db_session, "alice")
    asyncio.run(
        run_detection_pipeline(username="alice", user_id=user.id, success=True, ip="8.8.8.8", user_agent=CHROME_UA, timestamp=datetime.now(timezone.utc))
    )
    event = db_session.query(LoginEvent).one()
    assert event.asn == 15169


def test_login_computes_a_hybrid_score_and_action_using_the_real_model(client, db_session):
    assert hybrid_runtime.get_engine().ml_available is True  # tự nạp lúc startup của test này (xem docstring module)
    _create_user(db_session, "alice")
    client.post("/login", json={"username": "alice", "password": PASSWORD}, headers={"user-agent": CHROME_UA})

    event = db_session.query(LoginEvent).one()
    assert event.hybrid_risk_score is not None and 0 <= event.hybrid_risk_score <= 100
    assert event.hybrid_action in ACTIONS


def test_a_brute_force_burst_computes_a_valid_score_without_crashing(client, db_session):
    """Không ép buộc phải VƯỢT ngưỡng `alert` — MR11 hiệu chỉnh trọng số `brute_force` khá thấp khi đứng một mình (đo
    được ~10% trên val, xem docs/hybrid-risk-engine.md), nên vài lần sai từ một IP/thiết bị đã quen không nhất thiết đủ
    để báo động (đúng như thiết kế: không phải chỉ cần MỘT luật yếu khớp là báo ngay). Test này chỉ đảm bảo pipeline
    chạy hết, không sập, và điểm luôn hợp lệ — kịch bản CHẮC CHẮN vượt ngưỡng dùng blocklist ở test dưới."""
    _create_user(db_session, "alice")
    for _ in range(8):
        response = client.post("/login", json={"username": "alice", "password": "SaiMatKhau"}, headers={"user-agent": CHROME_UA})
        assert response.status_code == 401

    events = db_session.query(LoginEvent).all()
    assert len(events) == 8 and all(0 <= e.hybrid_risk_score <= 100 for e in events)


def test_a_blocklisted_ip_deterministically_locks_creates_a_response_action_and_an_audit_log_entry(client, db_session, monkeypatch):
    """`blocklist_hit` GHI ĐÈ (MR11: điểm 100, hành động `lock`) bất kể hiệu chỉnh trọng số/ML cụ thể — kịch bản DUY NHẤT
    chắc chắn tái lập được hành động `lock` mà không phụ thuộc số liệu hiệu chỉnh có thể đổi sau này. IP cố định qua
    monkeypatch (không qua X-Forwarded-For — phụ thuộc TRUST_FORWARDED_FOR của `.env`, không chắc bật ở môi trường khác)."""
    monkeypatch.setattr("app.routers.auth.resolve_client_ip", lambda request: "203.0.113.66")
    _create_user(db_session, "alice")
    db_session.add(BlocklistEntry(kind="ip", value="203.0.113.66", reason="test MR12", added_by="test"))
    db_session.commit()

    response = client.post("/login", json={"username": "alice", "password": PASSWORD}, headers={"user-agent": CHROME_UA})
    assert response.status_code == 200  # blocklist chỉ ghi đè ĐIỂM RỦI RO/đề xuất, KHÔNG (chưa) chặn đăng nhập thật (MR16)

    event = db_session.query(LoginEvent).order_by(LoginEvent.id.desc()).first()
    assert event.hybrid_risk_score == 100 and event.hybrid_action == "lock"

    hybrid_alert = db_session.query(Alert).filter(Alert.alert_type == "hybrid_risk").order_by(Alert.id.desc()).first()
    assert hybrid_alert is not None and hybrid_alert.rule_id == "blocklist_hit" and hybrid_alert.status == "open"
    assert hybrid_alert.explanation is not None and any(c["source"] == "blocklist_hit" for c in hybrid_alert.explanation["contributions"])

    action = db_session.query(ResponseAction).order_by(ResponseAction.id.desc()).first()
    assert action is not None and action.action == "lock" and action.status == "recommended" and action.alert_id == hybrid_alert.id

    log = db_session.query(AuditLog).filter(AuditLog.action == "recommend_lock").order_by(AuditLog.id.desc()).first()
    assert log is not None and log.actor == "system" and log.target_type == "login_event" and log.target_id == event.id


def test_a_broken_mr12_block_never_loses_the_tier1_brute_force_alert(client, db_session, monkeypatch):
    """Hỏng có chủ đích ở bước MR12 (rule engine v2 + hybrid) — cảnh báo brute_force của TẦNG 1 (rate_counter.py, có
    trước MR9-12) vẫn phải được tạo bình thường, và request vẫn phải trả lời (không sập luồng)."""

    def boom(*args, **kwargs):
        raise RuntimeError("lỗi giả lập trong khối MR12")

    monkeypatch.setattr("app.detection.pipeline.build_rule_engine", boom)
    _create_user(db_session, "alice")
    for _ in range(6):  # BRUTE_FORCE_THRESHOLD (tầng 1, rules.py) = 5
        response = client.post("/login", json={"username": "alice", "password": "SaiMatKhau"}, headers={"user-agent": CHROME_UA})
        assert response.status_code == 401

    tier1_alerts = db_session.query(Alert).filter(Alert.alert_type == "brute_force").all()
    assert tier1_alerts, "alert tầng 1 (brute_force) phải vẫn được tạo dù khối MR12 luôn raise"
    assert db_session.query(Alert).filter(Alert.alert_type == "hybrid_risk").count() == 0  # MR12 hỏng: không có alert nào từ đó
    last_event = db_session.query(LoginEvent).order_by(LoginEvent.id.desc()).first()
    assert last_event.hybrid_risk_score is None and last_event.hybrid_action is None  # cột MR12 vẫn NULL, không nửa vời


def test_ml_component_degrades_gracefully_when_the_engine_has_no_model_loaded(client, db_session, monkeypatch):
    """Ép hybrid_runtime CHƯA nạp được mô hình (mô phỏng model_registry rỗng/artifact lỗi) — pipeline vẫn phải chạy hết,
    action lúc này chỉ còn dựa vào luật (hồ sơ dự phòng nếu chưa nạp lại profile, hoặc profile thật nhưng ml_probability=None)."""
    engine = hybrid_runtime.get_engine()
    monkeypatch.setattr(engine, "scorer", None)
    _create_user(db_session, "alice")

    response = client.post("/login", json={"username": "alice", "password": PASSWORD}, headers={"user-agent": CHROME_UA})
    assert response.status_code == 200
    event = db_session.query(LoginEvent).one()
    assert event.hybrid_risk_score is not None  # vẫn chấm được (chỉ luật + danh tiếng), không phải None/lỗi


def test_login_from_a_nonexistent_username_still_runs_the_mr12_block_without_a_user_key(client, db_session):
    response = client.post("/login", json={"username": "ghost_user_mr12", "password": "whatever"}, headers={"user-agent": CHROME_UA})
    assert response.status_code == 401
    event = db_session.query(LoginEvent).filter(LoginEvent.attempted_username == "ghost_user_mr12").one()
    assert event.hybrid_risk_score is not None  # user_key=None: engine vẫn chấm được (luật theo IP/UA, không theo tài khoản)
