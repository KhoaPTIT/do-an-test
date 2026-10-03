"""impossible_travel — hai lần đăng nhập THÀNH CÔNG liên tiếp cách nhau quá xa so với thời gian (> `max_speed_kmh`=900).

Phase 3 (quyết định #2): chỉ tính THÀNH CÔNG → THÀNH CÔNG ở CẢ tầng 1 gốc lẫn rule engine v2."""

from datetime import timedelta

from app.detection.engine.registry import REGISTRY
from app.detection.rules import haversine_distance
from tests.behavior_detection.conftest import HAIPHONG_IP, HOME_IP, JP_IP, T0, US_IP, seed_user
from verification.fixtures import fixture_lookup_ip

RULE = "impossible_travel"
MAX_SPEED = next(p.default for p in REGISTRY[RULE].params if p.name == "max_speed_kmh")


def _km(ip_a, ip_b):
    a, b = fixture_lookup_ip(ip_a), fixture_lookup_ip(ip_b)
    return haversine_distance(a.latitude, a.longitude, b.latitude, b.longitude)


def _trip(env, second_ip, after, *, second_success=True):
    env.login("victim", success=True, ip=HOME_IP, ts=T0)
    env.login("victim", success=second_success, ip=second_ip, ts=T0 + after)


def test_positive_hanoi_then_new_york_ten_minutes_later(env):
    seed_user(env, "victim")
    _trip(env, US_IP, timedelta(minutes=10))

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    exp = alerts[0].explanation
    assert exp["primary_detector"] == RULE and exp["behavior"] == "impossible_travel"
    assert exp["evidence"]["speed_kmh"] > MAX_SPEED
    assert any(a.alert_type == "impossible_travel" for a in env.alerts())  # tầng 1 gốc vẫn báo (bản đồ dashboard dùng alert này)


def test_negative_hanoi_then_hai_phong_half_an_hour_later(env):
    seed_user(env, "victim")
    _trip(env, HAIPHONG_IP, timedelta(minutes=30))
    assert env.detector_alerts(RULE) == []
    assert not any(a.alert_type == "impossible_travel" for a in env.alerts())


def test_negative_failed_attempts_from_far_away_are_not_travel(env):
    seed_user(env, "victim")
    env.login("victim", success=True, ip=HOME_IP, ts=T0)
    for i in range(3):
        env.login("victim", success=False, ip=US_IP, ts=T0 + timedelta(minutes=5 + i))
    assert env.detector_alerts(RULE) == []
    assert not any(a.alert_type == "impossible_travel" for a in env.alerts())


def test_negative_failed_far_attempt_does_not_become_the_reference_point(env):
    # Sai từ Mỹ rồi chủ tài khoản đăng nhập ĐÚNG ở Hà Nội vài phút sau: so với lần THÀNH CÔNG trước (Hà Nội) — không di chuyển.
    seed_user(env, "victim")
    env.login("victim", success=False, ip=US_IP, ts=T0)
    env.login("victim", success=True, ip=HOME_IP, ts=T0 + timedelta(minutes=3))
    assert env.detector_alerts(RULE) == []


def test_boundary_speed_just_below_and_just_above_the_limit(env):
    km = _km(HOME_IP, JP_IP)
    slow_hours, fast_hours = km / (MAX_SPEED * 0.95), km / (MAX_SPEED * 1.05)
    seed_user(env, "victim")
    _trip(env, JP_IP, timedelta(hours=slow_hours))
    assert env.detector_alerts(RULE) == []

    env.login("victim", success=True, ip=HOME_IP, ts=T0 + timedelta(days=2))
    env.login("victim", success=True, ip=JP_IP, ts=T0 + timedelta(days=2, hours=fast_hours))
    assert len(env.detector_alerts(RULE)) == 1


def test_attribution_multi_country_rule_also_matching_keeps_travel_primary(env):
    seed_user(env, "victim")
    _trip(env, US_IP, timedelta(minutes=5))
    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1 and "multi_context_simultaneous" in alerts[0].explanation["matched_rules"]
    assert env.detector_alerts("multi_context_simultaneous") == []
