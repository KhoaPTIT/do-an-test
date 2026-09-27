"""MR14 — "Tương quan chiến dịch" tích hợp vào pipeline thật: alert của NHIỀU TÀI KHOẢN KHÁC NHAU chia sẻ hạ tầng
(IP/ASN) trong 24h được gộp vào CÙNG một `Campaign`, khác chống trùng lặp CÙNG một tài khoản của MR13. Đo trên diện
rộng (141 ATO thật của RBA): ml/rba/campaign_correlation_eval.py — file này chỉ kiểm chứng CƠ CHẾ.

⚠️ Tài khoản MỚI (chưa có baseline) có thể tự kích thêm alert `ml_anomaly` (tầng 3 cũ, Tuần 7 — coi tài khoản mới là
bất thường, không liên quan MR14) CÙNG lúc với alert `hybrid_risk` do blocklist sinh ra; alert đó CŨNG được gán vào
cùng chiến dịch (đúng thiết kế: cùng một login_event/hạ tầng thì cùng chiến dịch, không phân biệt tầng nào sinh ra
alert) — vì vậy các test dưới đây lọc theo `alert_type == "hybrid_risk"` khi cần đếm CHÍNH XÁC, thay vì đếm TỔNG số
alert (phụ thuộc hành vi ngẫu nhiên của tầng 3 cũ, không phải trọng tâm của MR14)."""

import asyncio
from datetime import datetime, timedelta, timezone

from app.detection.pipeline import run_detection_pipeline
from app.models import Alert, BlocklistEntry, Campaign, User
from app.security import hash_password

PASSWORD = "CorrectHorse123"
CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
GOOGLE_DNS = "8.8.8.8"  # ASN 15169, dùng chung với test_pipeline_mr13.py


def _create_user(db_session, username):
    user = User(username=username, password_hash=hash_password(PASSWORD))
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _run(*, username, user_id, success, ip, ts, user_agent=CHROME_UA):
    asyncio.run(run_detection_pipeline(username=username, user_id=user_id, success=success, ip=ip, user_agent=user_agent, timestamp=ts))


def _hybrid_alerts(db_session):
    return db_session.query(Alert).filter(Alert.alert_type == "hybrid_risk").order_by(Alert.id).all()


def test_two_different_accounts_hit_from_the_same_ip_join_the_same_campaign(db_session):
    alice = _create_user(db_session, "alice")
    bob = _create_user(db_session, "bob")
    db_session.add(BlocklistEntry(kind="ip", value=GOOGLE_DNS, reason="test MR14", added_by="test"))
    db_session.commit()

    _run(username="alice", user_id=alice.id, success=True, ip=GOOGLE_DNS, ts=BASE)
    _run(username="bob", user_id=bob.id, success=True, ip=GOOGLE_DNS, ts=BASE + timedelta(hours=2))

    alerts = _hybrid_alerts(db_session)
    assert len(alerts) == 2
    assert alerts[0].campaign_id is not None and alerts[0].campaign_id == alerts[1].campaign_id

    campaign = db_session.query(Campaign).one()
    assert campaign.alert_count >= 2 and campaign.attack_family == "Danh tiếng hạ tầng"
    assert "8.8.8.8" not in campaign.label and "ASN 15169" in campaign.label  # ưu tiên nhãn theo ASN hơn IP khi biết cả hai


def test_a_third_different_account_joins_the_existing_campaign_instead_of_creating_a_new_one(db_session):
    alice = _create_user(db_session, "alice")
    bob = _create_user(db_session, "bob")
    carol = _create_user(db_session, "carol")
    db_session.add(BlocklistEntry(kind="ip", value=GOOGLE_DNS, reason="test MR14", added_by="test"))
    db_session.commit()

    _run(username="alice", user_id=alice.id, success=True, ip=GOOGLE_DNS, ts=BASE)
    _run(username="bob", user_id=bob.id, success=True, ip=GOOGLE_DNS, ts=BASE + timedelta(hours=1))
    _run(username="carol", user_id=carol.id, success=True, ip=GOOGLE_DNS, ts=BASE + timedelta(hours=2))

    assert db_session.query(Campaign).count() == 1  # không phải 3 chiến dịch riêng biệt
    campaign_ids = {a.campaign_id for a in _hybrid_alerts(db_session)}
    assert len(campaign_ids) == 1 and None not in campaign_ids


def test_the_same_account_repeating_from_the_same_ip_does_not_start_a_campaign(db_session):
    """Đây là việc của MR13 (chống trùng lặp CÙNG một tài khoản) — MR14 chỉ quan tâm NHIỀU tài khoản khác nhau."""
    alice = _create_user(db_session, "alice")
    db_session.add(BlocklistEntry(kind="ip", value=GOOGLE_DNS, reason="test MR14", added_by="test"))
    db_session.commit()

    # ⚠️ PHẢI trong DEDUP_WINDOW (15 phút, MR13) để MR13 gộp thành 1 alert — dùng timedelta(hours=i) từng cho kết quả
    # ĐÚNG NHƯNG VÌ SAI LÝ DO: bug thật tự phát hiện ở MR15 khiến bộ lọc cửa sổ của MR13 vô hiệu hoàn toàn (so nhầm
    # Alert.created_at thay vì LoginEvent.created_at — xem app/detection/pipeline.py), nên MỌI khoảng cách đều bị coi
    # là "trong cửa sổ". Sau khi vá đúng, timedelta(hours=i) (2 giờ) giờ NGOÀI cửa sổ 15 phút — đúng ra phải tạo 3
    # alert riêng, không phải 1. Đổi sang phút để test CÒN kiểm đúng điều nó nói (chống trùng lặp CÙNG một tài khoản).
    for i in range(3):
        _run(username="alice", user_id=alice.id, success=True, ip=GOOGLE_DNS, ts=BASE + timedelta(minutes=i))

    assert db_session.query(Campaign).count() == 0
    alert = _hybrid_alerts(db_session)[0]  # MR13 gộp 3 lần (trong 15 phút) thành 1 alert hybrid_risk
    assert len(_hybrid_alerts(db_session)) == 1 and alert.campaign_id is None


def test_two_accounts_sharing_infra_far_outside_the_window_do_not_share_a_campaign(db_session):
    alice = _create_user(db_session, "alice")
    bob = _create_user(db_session, "bob")
    db_session.add(BlocklistEntry(kind="ip", value=GOOGLE_DNS, reason="test MR14", added_by="test"))
    db_session.commit()

    _run(username="alice", user_id=alice.id, success=True, ip=GOOGLE_DNS, ts=BASE)
    _run(username="bob", user_id=bob.id, success=True, ip=GOOGLE_DNS, ts=BASE + timedelta(days=10))

    alerts = _hybrid_alerts(db_session)
    assert len(alerts) == 2 and alerts[0].campaign_id is None and alerts[1].campaign_id is None
    assert db_session.query(Campaign).count() == 0


def test_a_single_alert_with_no_matching_infra_does_not_create_a_campaign(db_session):
    alice = _create_user(db_session, "alice")
    db_session.add(BlocklistEntry(kind="ip", value=GOOGLE_DNS, reason="test MR14", added_by="test"))
    db_session.commit()

    _run(username="alice", user_id=alice.id, success=True, ip=GOOGLE_DNS, ts=BASE)

    assert db_session.query(Campaign).count() == 0
    assert _hybrid_alerts(db_session)[0].campaign_id is None
