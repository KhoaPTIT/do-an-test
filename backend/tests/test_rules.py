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
