"""Kiểm tra nhiệm vụ 3.3 — rule-based detection tầng 1."""

from datetime import datetime, timedelta, timezone

from app.detection.rules import (
    BRUTE_FORCE_THRESHOLD,
    CREDENTIAL_STUFFING_FAIL_THRESHOLD,
    CREDENTIAL_STUFFING_MIN_DISTINCT_USERNAMES,
    GeoPoint,
    haversine_distance,
    is_brute_force,
    is_credential_stuffing,
    is_impossible_travel,
    register_login_failure,
)


def test_haversine_distance_known_value():
    # 1 độ kinh độ tại xích đạo ~ 111.19 km (bán kính Trái Đất 6371km).
    distance = haversine_distance(0, 0, 0, 1)
    assert abs(distance - 111.19) < 0.5


def test_haversine_distance_same_point_is_zero():
    assert haversine_distance(21.03, 105.85, 21.03, 105.85) == 0


def test_impossible_travel_true_for_far_apart_short_time():
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    # Hà Nội -> New York trong 10 phút là bất khả thi.
    previous = GeoPoint(21.03, 105.85, now - timedelta(minutes=10))
    current = GeoPoint(40.71, -74.01, now)
    assert is_impossible_travel(previous, current) is True


def test_impossible_travel_false_for_nearby_points():
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    previous = GeoPoint(21.03, 105.85, now - timedelta(minutes=10))
    current = GeoPoint(21.05, 105.83, now)  # cách vài km, cùng thành phố
    assert is_impossible_travel(previous, current) is False


def test_impossible_travel_false_when_missing_geoip():
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    previous = GeoPoint(None, None, now - timedelta(minutes=10))
    current = GeoPoint(40.71, -74.01, now)
    assert is_impossible_travel(previous, current) is False


def test_impossible_travel_false_without_previous_login():
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    current = GeoPoint(40.71, -74.01, now)
    assert is_impossible_travel(None, current) is False


def test_impossible_travel_tolerates_a_naive_previous_timestamp():
    """Bug thật phát hiện ở MR13 (test_pipeline_mr13.py, hai lần đăng nhập thành công thật qua pipeline trên SQLite):
    `previous.timestamp` đọc lại từ SQLite mất tzinfo (naive) trong khi `current.timestamp` (vừa gán trong Python) vẫn
    aware — trừ hai loại datetime khác nhau từng raise TypeError thay vì so sánh được. Không xảy ra trên Postgres thật
    (TIMESTAMP WITH TIME ZONE luôn trả aware) nhưng vẫn là ổ gà cần vá tận gốc — xem ensure_utc() trong hàm."""
    aware_now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    naive_previous = datetime(2026, 1, 1, 11, 50)  # mô phỏng đúng những gì SQLAlchemy/SQLite trả về
    previous = GeoPoint(21.03, 105.85, naive_previous)
    current = GeoPoint(40.71, -74.01, aware_now)
    assert is_impossible_travel(previous, current) is True  # Hà Nội -> New York trong 10 phút vẫn phải bắt được, không raise


def test_is_brute_force_true_after_threshold_fails(fake_redis):
    for _ in range(BRUTE_FORCE_THRESHOLD):
        register_login_failure("victim", "1.2.3.4")
    assert is_brute_force("victim") is True


def test_is_brute_force_false_below_threshold(fake_redis):
    for _ in range(BRUTE_FORCE_THRESHOLD - 1):
        register_login_failure("victim2", "1.2.3.4")
    assert is_brute_force("victim2") is False


def test_is_credential_stuffing_true_for_many_usernames_same_ip(fake_redis):
    attacker_ip = "9.9.9.9"
    for i in range(max(CREDENTIAL_STUFFING_FAIL_THRESHOLD, CREDENTIAL_STUFFING_MIN_DISTINCT_USERNAMES)):
        register_login_failure(f"user{i}", attacker_ip)
    assert is_credential_stuffing(attacker_ip) is True


def test_is_credential_stuffing_false_for_single_username(fake_redis):
    ip = "9.9.9.8"
    for _ in range(CREDENTIAL_STUFFING_FAIL_THRESHOLD):
        register_login_failure("only-one-user", ip)  # nhiều fail nhưng CÙNG 1 username
    assert is_credential_stuffing(ip) is False


# ------------------------------------------------------------------------------------- MR18: now= (giờ SỰ KIỆN, không phải giờ thật)


def test_register_login_failure_without_now_uses_real_time_and_is_unaffected_by_a_simulated_past(fake_redis):
    """Hành vi CŨ (không truyền now=) phải giữ nguyên — chỉ THÊM tham số, không đổi mặc định."""
    for _ in range(BRUTE_FORCE_THRESHOLD):
        register_login_failure("victim_default", "1.2.3.4")
    assert is_brute_force("victim_default") is True


def test_credential_stuffing_respects_simulated_time_not_wall_clock_when_now_is_given(fake_redis):
    """Bug thật tự phát hiện ở MR18 (ml/attack_scenarios.py — kịch bản 'rải mật khẩu chậm'): trước khi register_
    login_failure/is_credential_stuffing nhận now=, MỌI lần gọi (dù truyền timestamp mô phỏng cách nhau hàng giờ vào
    run_detection_pipeline) đều đếm theo time.time() THẬT — 10 lần gọi trong một test chạy vài mili-giây luôn rơi
    vào CÙNG một cửa sổ 300 giây thật, dù các timestamp mô phỏng cách nhau rất xa. Giả: 10 lần thử, mỗi lần cách nhau
    25 PHÚT theo now= mô phỏng (>> 300 giây cửa sổ) — dù cả 10 lệnh gọi Python chạy gần như tức thời — PHẢI KHÔNG bị
    coi là credential stuffing, vì mỗi cửa sổ 300s mô phỏng chỉ từng chứa ĐÚNG 1 lần thử."""
    ip = "9.9.9.7"
    base = 1_700_000_000.0
    for i in range(10):
        register_login_failure(f"victim_spray_{i}", ip, now=base + i * 25 * 60)
    assert is_credential_stuffing(ip, now=base + 9 * 25 * 60) is False


def test_credential_stuffing_still_fires_when_the_simulated_attempts_are_genuinely_close_together(fake_redis):
    """Đối chứng cho test trên — cùng số lần thử, nhưng now= mô phỏng cách nhau VÀI GIÂY (thật sự nhanh) vẫn phải bị bắt."""
    ip = "9.9.9.6"
    base = 1_700_000_000.0
    for i in range(10):
        register_login_failure(f"victim_fast_{i}", ip, now=base + i * 10)
    assert is_credential_stuffing(ip, now=base + 9 * 10) is True


def test_brute_force_window_slides_on_simulated_time_not_call_order(fake_redis):
    """10 lần sai cách nhau 1 GIỜ mô phỏng (>> cửa sổ 300s) không được cộng dồn thành brute force, dù gọi liên tiếp
    trong cùng một tiến trình test."""
    base = 1_700_000_000.0
    for i in range(10):
        register_login_failure("victim_slow_bf", "1.2.3.4", now=base + i * 3600)
    assert is_brute_force("victim_slow_bf", now=base + 9 * 3600) is False
