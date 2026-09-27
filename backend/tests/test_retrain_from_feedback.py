"""MR15 — scripts/retrain_from_feedback.py: đọc Alert.status đã có phản hồi, tính lại UserRiskProfile.threshold_delta."""

from datetime import datetime, timezone

from app.detection.adaptive_threshold import LEARNING_RATE, MIN_FEEDBACK_FOR_PERSONAL_THRESHOLD
from app.models import Alert, AuditLog, LoginEvent, User, UserRiskProfile
from scripts.retrain_from_feedback import retrain, tally_feedback

BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _user(db, username):
    user = User(username=username, password_hash="x")
    db.add(user)
    db.flush()
    return user


def _alert(db, user, status, *, minutes=0):
    ev = LoginEvent(user_id=user.id if user else None, attempted_username=user.username if user else "ghost", success=True, ip_address="1.1.1.1", created_at=BASE)
    db.add(ev)
    db.flush()
    a = Alert(login_event_id=ev.id, user_id=user.id if user else None, alert_type="hybrid_risk", severity="high", risk_score=80, message="x", status=status, created_at=BASE)
    db.add(a)
    db.flush()
    return a


def test_tally_feedback_counts_only_alerts_with_a_real_account_and_a_feedback_status(db_session):
    alice = _user(db_session, "alice")
    _alert(db_session, alice, "false_positive")
    _alert(db_session, alice, "resolved")
    _alert(db_session, alice, "open")  # chưa có phản hồi -> không tính
    _alert(db_session, None, "false_positive")  # tên đăng nhập không tồn tại -> không tính
    db_session.commit()

    tallies = tally_feedback(db_session)
    assert tallies == {alice.id: (2, 1)}


def test_retrain_skips_users_below_the_minimum_feedback_count(db_session):
    alice = _user(db_session, "alice")
    for _ in range(MIN_FEEDBACK_FOR_PERSONAL_THRESHOLD - 1):
        _alert(db_session, alice, "false_positive")
    db_session.commit()

    changes = retrain(db_session)
    assert changes == []
    assert db_session.get(UserRiskProfile, alice.id) is None


def test_retrain_creates_a_profile_with_the_correct_delta_for_a_user_with_mostly_false_positive_feedback(db_session):
    alice = _user(db_session, "alice")
    for _ in range(4):
        _alert(db_session, alice, "false_positive")
    _alert(db_session, alice, "resolved")
    db_session.commit()  # 5 phan hoi, 4 bao nham, 1 dung -> rong = 3

    changes = retrain(db_session)
    assert len(changes) == 1 and changes[0]["user_id"] == alice.id and changes[0]["new_delta"] == 3 * LEARNING_RATE

    profile = db_session.get(UserRiskProfile, alice.id)
    assert profile is not None and profile.threshold_delta == 3 * LEARNING_RATE and profile.feedback_count == 5 and profile.false_positive_count == 4

    audit = db_session.query(AuditLog).filter(AuditLog.action == "retrain_thresholds").one()
    assert audit.actor == "system" and audit.detail["n_users_adjusted"] == 1


def test_dry_run_computes_but_does_not_write_to_the_database(db_session):
    alice = _user(db_session, "alice")
    for _ in range(5):
        _alert(db_session, alice, "false_positive")
    db_session.commit()

    changes = retrain(db_session, dry_run=True)
    assert len(changes) == 1 and changes[0]["new_delta"] > 0
    assert db_session.get(UserRiskProfile, alice.id) is None
    assert db_session.query(AuditLog).filter(AuditLog.action == "retrain_thresholds").count() == 0


def test_rerunning_retrain_recomputes_from_scratch_and_can_lower_the_delta_back_down(db_session):
    """Không cộng dồn theo số lần chạy — chạy lại sau khi có thêm phản hồi "đúng" phải tính LẠI từ đầu trên toàn bộ
    lịch sử hiện có, delta có thể giảm (kể cả về 0), không bị kẹt ở mức đã tăng từ lần chạy trước."""
    alice = _user(db_session, "alice")
    for _ in range(5):
        _alert(db_session, alice, "false_positive")
    db_session.commit()
    retrain(db_session)
    assert db_session.get(UserRiskProfile, alice.id).threshold_delta == 5 * LEARNING_RATE

    for _ in range(5):
        _alert(db_session, alice, "resolved")
    db_session.commit()  # giờ 10 phan hoi, 5 bao nham, 5 dung -> rong = 0

    retrain(db_session)
    assert db_session.get(UserRiskProfile, alice.id).threshold_delta == 0.0


def test_a_user_with_mostly_correct_feedback_never_gets_a_positive_delta(db_session):
    alice = _user(db_session, "alice")
    for _ in range(5):
        _alert(db_session, alice, "resolved")
    db_session.commit()

    changes = retrain(db_session)
    assert changes[0]["new_delta"] == 0.0
