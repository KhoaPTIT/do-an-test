"""MR15 — pipeline.py đọc UserRiskProfile.threshold_delta và truyền BANDS ĐÃ NỚI LỎNG riêng cho tài khoản đó vào
hybrid_runtime.evaluate(). Việc "nới lỏng bands thật sự đổi hành động" đã kiểm ở tests/test_hybrid_runtime.py — ở đây
chỉ kiểm ĐÚNG DÂY NỐI (pipeline có đọc UserRiskProfile và truyền đúng bands hay không), dùng spy thay vì cố dựng một
kịch bản điểm số chính xác qua toàn bộ rule engine + mô hình thật (mong manh, phụ thuộc hiệu chỉnh có thể đổi sau)."""

import asyncio
from datetime import datetime, timezone

from app.detection import hybrid_runtime
from app.detection.pipeline import run_detection_pipeline
from app.models import User, UserRiskProfile
from app.security import hash_password

PASSWORD = "CorrectHorse123"
CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _create_user(db_session, username):
    user = User(username=username, password_hash=hash_password(PASSWORD))
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _run(*, username, user_id, ip="8.8.8.8"):
    asyncio.run(run_detection_pipeline(username=username, user_id=user_id, success=True, ip=ip, user_agent=CHROME_UA, timestamp=BASE))


def _spy_on_evaluate(monkeypatch):
    engine = hybrid_runtime.get_engine()
    original = engine.evaluate
    captured = {}

    def spy(ml_prediction, hits, *, bands=None):  # Phase 4.1: đối số đầu là MLPrediction (trước đây đặc trưng RBA)
        captured["bands"] = bands
        return original(ml_prediction, hits, bands=bands)

    monkeypatch.setattr(engine, "evaluate", spy)
    return captured


def test_a_user_with_a_positive_delta_gets_the_bands_shifted_by_exactly_that_amount(db_session, client, monkeypatch):
    alice = _create_user(db_session, "alice")
    db_session.add(UserRiskProfile(user_id=alice.id, threshold_delta=12.0, feedback_count=5, false_positive_count=4))
    db_session.commit()
    captured = _spy_on_evaluate(monkeypatch)

    _run(username="alice", user_id=alice.id)

    base = hybrid_runtime.get_engine().profile.bands
    assert captured["bands"] is not None
    assert (captured["bands"].alert_at, captured["bands"].step_up_at, captured["bands"].lock_at) == (base.alert_at + 12, base.step_up_at + 12, base.lock_at + 12)


def test_a_user_without_a_risk_profile_gets_no_override_the_group_default_is_used(db_session, client, monkeypatch):
    alice = _create_user(db_session, "alice")
    captured = _spy_on_evaluate(monkeypatch)

    _run(username="alice", user_id=alice.id)

    assert captured["bands"] is None  # HybridEngine.evaluate() tự dùng self.profile.bands khi bands=None


def test_a_risk_profile_with_zero_delta_also_gets_no_override(db_session, client, monkeypatch):
    """feedback_count đủ mẫu nhưng phản hồi "đúng"/"báo nhầm" cân bằng nhau -> delta=0 -> KHÔNG có lý do gì tạo một
    ActionBands mới giống hệt bands nhóm — pipeline.py chỉ áp override khi threshold_delta > 0."""
    alice = _create_user(db_session, "alice")
    db_session.add(UserRiskProfile(user_id=alice.id, threshold_delta=0.0, feedback_count=6, false_positive_count=3))
    db_session.commit()
    captured = _spy_on_evaluate(monkeypatch)

    _run(username="alice", user_id=alice.id)

    assert captured["bands"] is None


def test_a_login_with_no_matching_username_never_looks_up_a_risk_profile(db_session, client, monkeypatch):
    captured = _spy_on_evaluate(monkeypatch)
    _run(username="ghost_user_does_not_exist", user_id=None)
    assert captured["bands"] is None


def test_one_users_delta_never_affects_a_different_users_bands(db_session, client, monkeypatch):
    alice = _create_user(db_session, "alice")
    bob = _create_user(db_session, "bob")
    db_session.add(UserRiskProfile(user_id=alice.id, threshold_delta=15.0, feedback_count=5, false_positive_count=5))
    db_session.commit()
    captured = _spy_on_evaluate(monkeypatch)

    _run(username="bob", user_id=bob.id)

    assert captured["bands"] is None  # bob khong co UserRiskProfile rieng, du alice co
