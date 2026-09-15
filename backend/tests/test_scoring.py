"""Kiểm tra nhiệm vụ 4.2 — chấm điểm risk score tầng 2."""

from datetime import datetime, timedelta, timezone

from app.detection.scoring import (
    CONSECUTIVE_FAIL_WEIGHT,
    LOW_RISK_MAX,
    MEDIUM_RISK_MAX,
    SUCCESS_AFTER_FAIL_STREAK_WEIGHT,
    UNKNOWN_LOCATION_WEIGHT,
    UNUSUAL_HOUR_WEIGHT,
    classify_severity,
    compute_risk_score,
    is_unusual_hour,
)
from app.models import UserBaseline

# Baseline "trưởng thành" (đã qua chế độ học) dùng chung cho các test.
_MATURE_BASELINE = UserBaseline(
    user_id=1,
    successful_login_count=50,
    avg_login_hour=9.0,
    stddev_login_hour=1.0,
    first_login_at=datetime.now(timezone.utc) - timedelta(days=30),
)


def test_classify_severity_boundaries():
    assert classify_severity(0) == "low"
    assert classify_severity(LOW_RISK_MAX - 1) == "low"
    assert classify_severity(LOW_RISK_MAX) == "medium"
    assert classify_severity(MEDIUM_RISK_MAX) == "medium"
    assert classify_severity(MEDIUM_RISK_MAX + 1) == "high"
    assert classify_severity(100) == "high"


def test_score_known_exact_case_unusual_hour_plus_unknown_location():
    # Test case biết trước: đăng nhập lệch giờ + IP lạ -> điểm phải đúng
    # bằng tổng theo công thức (checklist mục 4.2 — kiểm tra sau khi hoàn thành).
    score, factors = compute_risk_score(
        baseline=_MATURE_BASELINE,
        login_hour=20.0,  # cách avg_login_hour=9.0 rất xa -> unusual_hour=True
        is_new_location=True,
        consecutive_fail=False,
        success_after_fail_streak=False,
    )
    assert factors.unusual_hour is True
    assert factors.unknown_location is True
    assert score == UNUSUAL_HOUR_WEIGHT + UNKNOWN_LOCATION_WEIGHT == 50
    assert classify_severity(score) == "medium"


def test_score_success_after_fail_streak_reaches_high_immediately():
    score, factors = compute_risk_score(
        baseline=_MATURE_BASELINE,
        login_hour=9.0,  # đúng giờ quen thuộc -> không unusual
        is_new_location=False,
        consecutive_fail=False,
        success_after_fail_streak=True,
    )
    assert factors.success_after_fail_streak is True
    assert score == SUCCESS_AFTER_FAIL_STREAK_WEIGHT == 50
    # Một mình yếu tố này chưa chắc > 70 -> vẫn "medium"; kết hợp thêm sẽ lên "high".
    score2, _ = compute_risk_score(
        baseline=_MATURE_BASELINE,
        login_hour=9.0,
        is_new_location=True,
        consecutive_fail=False,
        success_after_fail_streak=True,
    )
    assert score2 == SUCCESS_AFTER_FAIL_STREAK_WEIGHT + UNKNOWN_LOCATION_WEIGHT == 80
    assert classify_severity(score2) == "high"


def test_score_normal_login_is_low_no_false_alert():
    # Đăng nhập hoàn toàn bình thường -> điểm thấp, không tạo alert nhầm.
    score, factors = compute_risk_score(
        baseline=_MATURE_BASELINE,
        login_hour=9.1,  # rất gần avg_login_hour
        is_new_location=False,
        consecutive_fail=False,
        success_after_fail_streak=False,
    )
    assert score == 0
    assert classify_severity(score) == "low"


def test_score_consecutive_fail_weight():
    score, factors = compute_risk_score(
        baseline=None,
        login_hour=9.0,
        is_new_location=False,
        consecutive_fail=True,
        success_after_fail_streak=False,
    )
    assert factors.consecutive_fail is True
    assert score == CONSECUTIVE_FAIL_WEIGHT == 40


def test_learning_mode_never_flags_unusual_hour_or_location():
    new_user_baseline = UserBaseline(
        user_id=2,
        successful_login_count=2,  # < 10 -> chế độ học
        avg_login_hour=9.0,
        stddev_login_hour=0.5,
        first_login_at=datetime.now(timezone.utc),
    )
    score, factors = compute_risk_score(
        baseline=new_user_baseline,
        login_hour=22.0,  # lệch giờ rất xa nhưng vẫn đang học -> không tính
        is_new_location=True,
        consecutive_fail=False,
        success_after_fail_streak=False,
    )
    assert factors.unusual_hour is False
    assert factors.unknown_location is False
    assert score == 0


def test_is_unusual_hour_handles_circular_wraparound():
    # avg=23h, hiện tại=1h -> chỉ cách 2h thật sự (không phải 22h) -> KHÔNG bất thường
    baseline = UserBaseline(
        user_id=3,
        successful_login_count=50,
        avg_login_hour=23.0,
        stddev_login_hour=1.0,
        first_login_at=datetime.now(timezone.utc) - timedelta(days=30),
    )
    assert is_unusual_hour(baseline, 1.0) is False
    assert is_unusual_hour(baseline, 12.0) is True  # cách nửa ngày -> chắc chắn bất thường
