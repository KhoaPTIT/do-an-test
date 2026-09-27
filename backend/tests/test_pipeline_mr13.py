"""MR13 — "Cảnh báo thông minh v2" tích hợp vào pipeline thật (SQLite test + fakeredis + mô hình hybrid_cp2 thật, cùng
hạ tầng `client`/`db_session` của test_pipeline_mr12.py): chống trùng lặp thực sự GIẢM số hàng `Alert`, novelty/họ tấn
công gợi ý xuất hiện trong message, ưu tiên được tính. Đo trên diện rộng (nhiều kịch bản, độ chính xác gán họ, phần
trăm giảm alert) ở backend/scripts/alert_intelligence_sim.py — file này chỉ kiểm chứng CƠ CHẾ, không phải số đo cuối."""

import asyncio
from datetime import datetime, timedelta, timezone

from app.detection.pipeline import run_detection_pipeline
from app.models import Alert, AuditLog, BlocklistEntry, LoginEvent, ResponseAction, User
from app.security import hash_password
from app.utils.time import ensure_utc

PASSWORD = "CorrectHorse123"
CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
GOOGLE_DNS = "8.8.8.8"  # ASN 15169, GeoIP thật trả country="US" (đã xác nhận ở MR12, docs/geoip-setup.md)


def _create_user(db_session, username="alice", importance=1.0):
    user = User(username=username, password_hash=hash_password(PASSWORD), importance=importance)
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _seed_vn_history(db_session, user, *, count=10):
    """Lịch sử THÀNH CÔNG toàn từ VN — để lần đăng nhập từ US (GOOGLE_DNS) sau đó là novelty thật, so được với lịch sử."""
    for i in range(count):
        db_session.add(
            LoginEvent(
                user_id=user.id, attempted_username=user.username, success=True, ip_address="14.169.1.1", country="VN",
                user_agent=CHROME_UA, is_synthetic=True, created_at=BASE - timedelta(days=30) + timedelta(hours=i),
            )
        )
    db_session.commit()


def _run(*, username, user_id, success, ip, ts, user_agent=CHROME_UA):
    asyncio.run(run_detection_pipeline(username=username, user_id=user_id, success=success, ip=ip, user_agent=user_agent, timestamp=ts))


def test_a_burst_from_a_blocklisted_ip_is_deduped_into_one_alert_not_five(db_session):
    user = _create_user(db_session, "alice")
    db_session.add(BlocklistEntry(kind="ip", value=GOOGLE_DNS, reason="test MR13", added_by="test"))
    db_session.commit()

    for i in range(5):
        _run(username="alice", user_id=user.id, success=True, ip=GOOGLE_DNS, ts=BASE + timedelta(seconds=i * 30))

    events = db_session.query(LoginEvent).order_by(LoginEvent.id).all()
    assert len(events) == 5 and all(e.hybrid_action == "lock" for e in events)  # blocklist_hit ghi đè MỌI lần, không phụ thuộc hiệu chỉnh

    alerts = db_session.query(Alert).filter(Alert.alert_type == "hybrid_risk").all()
    assert len(alerts) == 1, "5 lần cùng khớp blocklist_hit trong 15 phút phải GỘP thành 1 alert, không phải 5 (đúng mục tiêu 'giảm số cảnh báo' của MR13)"

    alert = alerts[0]
    assert alert.occurrence_count == 5
    assert alert.attack_family == "Danh tiếng hạ tầng" and alert.attack_family_confidence is not None
    assert alert.priority_score is not None and alert.priority_score >= 0
    # `created_at` (server_default=func.now(), giờ THẬT lúc chạy test) và `last_seen_at` (= event.created_at, giờ GIẢ
    # BASE của kịch bản) đến từ hai "đồng hồ" khác nhau — so `last_seen_at` với chính mốc thời gian kịch bản, không
    # phải với created_at (cùng bẫy đã ghi nhận ở MR12: "test boundary bug, không phải lỗi module").
    assert ensure_utc(alert.last_seen_at) == BASE + timedelta(seconds=4 * 30)
    assert "Đã lặp lại 5 lần" in alert.message

    # "action" không đổi (lock -> lock không phải leo thang) mỗi lần trùng -> chỉ 1 response_action/audit_log, không phải 5.
    assert db_session.query(ResponseAction).count() == 1
    assert db_session.query(AuditLog).filter(AuditLog.action == "recommend_lock").count() == 1


def test_dedup_still_groups_by_ip_when_the_username_does_not_exist(db_session):
    """Kịch bản dò danh sách tài khoản: nhiều TÊN ĐĂNG NHẬP KHÔNG TỒN TẠI khác nhau, cùng một IP bị blocklist — user_id
    luôn None nên chống trùng lặp phải gộp theo IP, không phải theo user_id (None == None sẽ gộp NHẦM các IP khác nhau
    nếu chỉ lọc user_id, xem app/detection/pipeline.py)."""
    db_session.add(BlocklistEntry(kind="ip", value=GOOGLE_DNS, reason="test MR13", added_by="test"))
    db_session.commit()
    for i, name in enumerate(["ghost1", "ghost2", "ghost3"]):
        _run(username=name, user_id=None, success=False, ip=GOOGLE_DNS, ts=BASE + timedelta(seconds=i * 10))

    alerts = db_session.query(Alert).filter(Alert.alert_type == "hybrid_risk").all()
    assert len(alerts) == 1 and alerts[0].occurrence_count == 3 and alerts[0].user_id is None


def test_a_login_from_a_new_country_mentions_it_by_name_in_the_message_with_the_usual_country_and_count(db_session):
    user = _create_user(db_session, "alice")
    _seed_vn_history(db_session, user, count=10)
    db_session.add(BlocklistEntry(kind="ip", value=GOOGLE_DNS, reason="test MR13", added_by="test"))
    db_session.commit()

    _run(username="alice", user_id=user.id, success=True, ip=GOOGLE_DNS, ts=BASE)

    alert = db_session.query(Alert).filter(Alert.alert_type == "hybrid_risk").one()
    assert "Lần đầu quốc gia này (US), trước đó dùng VN 10 lần." in alert.message


def test_an_ordinary_login_matching_established_history_creates_no_novelty_clause_or_alert(db_session):
    """Kiểm chứng âm tính: lịch sử quen thuộc + đăng nhập bình thường (không blocklist, không sai mật khẩu, cùng nước/
    thiết bị) không được tự bịa ra sự "mới lạ" hay cảnh báo nào — hệ thống không được ồn ào với traffic hợp lệ.

    ⚠️ IP "14.169.1.1" ở đây không tra được GeoIP thật (không phải IP thật đã cấp phát) nên rare_country/rare_asn là
    NaN, không phải "cực hiếm" — test này KHÔNG mâu thuẫn với phát hiện báo nhầm của `alert_intelligence_sim.py` (dùng
    IP Việt Nam THẬT, tra được ASN/quốc gia cực hiếm so với RBA nên ML một mình vượt ngưỡng) — hai điều kiện khác nhau,
    xem diễn giải trong docs/alert-intelligence-v2.md."""
    user = _create_user(db_session, "alice")
    _seed_vn_history(db_session, user, count=10)

    _run(username="alice", user_id=user.id, success=True, ip="14.169.1.1", ts=BASE, user_agent=CHROME_UA)

    assert db_session.query(Alert).filter(Alert.alert_type == "hybrid_risk").count() == 0
