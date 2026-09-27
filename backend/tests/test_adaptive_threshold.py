"""MR15 — app/detection/adaptive_threshold.py: công thức nới lỏng ngưỡng theo phản hồi (thuần, không DB)."""

import pytest

from app.detection.adaptive_threshold import LEARNING_RATE, MAX_DELTA, MIN_FEEDBACK_FOR_PERSONAL_THRESHOLD, apply_delta, compute_delta
from app.detection.hybrid.calibration import ActionBands


def test_below_minimum_feedback_count_never_adjusts_regardless_of_content():
    assert compute_delta(feedback_count=MIN_FEEDBACK_FOR_PERSONAL_THRESHOLD - 1, false_positive_count=MIN_FEEDBACK_FOR_PERSONAL_THRESHOLD - 1) == 0.0


def test_all_correct_feedback_never_lowers_the_threshold_below_the_group_default():
    assert compute_delta(feedback_count=10, false_positive_count=0) == 0.0


def test_equal_correct_and_false_positive_feedback_does_not_adjust():
    assert compute_delta(feedback_count=6, false_positive_count=3) == 0.0  # 3 báo nhầm, 3 đúng -> ròng = 0


def test_net_false_positives_scale_the_delta_linearly_with_the_learning_rate():
    # 5 báo nhầm, 0 đúng -> ròng = 5
    assert compute_delta(feedback_count=5, false_positive_count=5) == pytest.approx(5 * LEARNING_RATE)
    # 5 báo nhầm, 2 đúng (7 tổng) -> ròng = 3
    assert compute_delta(feedback_count=7, false_positive_count=5) == pytest.approx(3 * LEARNING_RATE)


def test_delta_is_capped_at_max_delta_even_with_many_false_positives():
    assert compute_delta(feedback_count=100, false_positive_count=100) == MAX_DELTA


def test_apply_delta_shifts_all_three_bands_by_the_same_amount_preserving_order():
    bands = ActionBands(alert_at=32, step_up_at=58, lock_at=70)
    shifted = apply_delta(bands, 10.0)
    assert (shifted.alert_at, shifted.step_up_at, shifted.lock_at) == (42, 68, 80)
    assert shifted.alert_at < shifted.step_up_at < shifted.lock_at  # ActionBands.__post_init__ đã tự kiểm, đây kiểm lại tường minh


def test_apply_delta_with_zero_or_negative_returns_the_same_bands_object():
    bands = ActionBands(alert_at=32, step_up_at=58, lock_at=70)
    assert apply_delta(bands, 0.0) is bands
    assert apply_delta(bands, -5.0) is bands


def test_apply_delta_never_produces_an_invalid_action_bands_even_near_the_ceiling():
    """lock_at đã gần 100 — dịch đều mà kẹp SAU (thay vì kẹp delta TRƯỚC) sẽ làm 2 mốc trùng nhau ở 100 và
    ActionBands tự raise; ở đây không được raise, phải tự kẹp delta lại cho vừa đủ (hoặc không dịch gì cả)."""
    bands = ActionBands(alert_at=90, step_up_at=95, lock_at=98)
    shifted = apply_delta(bands, MAX_DELTA)  # muốn dịch 20 nhưng chỉ còn đúng 2 điểm chỗ trống trước khi lock_at chạm 100
    assert shifted.lock_at <= 100
    assert shifted.alert_at < shifted.step_up_at < shifted.lock_at  # không raise HybridConfigError

    no_room_left = ActionBands(alert_at=98, step_up_at=99, lock_at=100)
    assert apply_delta(no_room_left, MAX_DELTA) is no_room_left  # lock_at đã ở trần 100 -> không còn chỗ, không dịch, không raise
