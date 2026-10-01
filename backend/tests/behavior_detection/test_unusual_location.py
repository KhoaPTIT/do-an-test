"""unusual_location — tài khoản trưởng thành (≥10 lần thành công, ≥7 ngày) đăng nhập THÀNH CÔNG từ quốc gia chưa từng
xuất hiện trong hồ sơ vị trí (học CHỈ từ lần thành công). Thành phố mới trong nước đã quen, chuyến đi đã có trong lịch sử,
lần thử thất bại, thiếu GeoIP: không cảnh báo."""

from datetime import timedelta

import pytest

from app.detection.engine.registry import REGISTRY
from tests.behavior_detection.conftest import FR_IP, HCM_IP, HOME_IP, JP_IP, T0, US_IP, seed_user
from verification.harness import CHROME_UA, SAFARI_UA

RULE = "unusual_location"
PARAMS = {p.name: p.default for p in REGISTRY[RULE].params}
NO_GEO_IP = "100.64.7.10"  # không có trong GeoIP fixture


@pytest.fixture(autouse=True)
def _candidate(as_candidate):
    as_candidate(RULE)


def test_positive_mature_hanoi_profile_then_a_never_seen_country(env):
    seed_user(env, "alice", days=20)
    env.login("alice", success=True, ip=JP_IP, ts=T0 + timedelta(days=1))  # 2 ngày sau lần cuối ở Hà Nội: không phải impossible travel

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.alert_type == "behavior_anomaly" and a.severity == "medium"
    exp = a.explanation
    assert exp["primary_detector"] == RULE and exp["behavior"] == "unusual_location" and exp["action"] == "allow"
    ev = exp["evidence"]
    assert ev["current_country"] == "JP" and ev["current_city"] == "Tokyo"
    assert ev["known_countries"] == ["VN"] and ev["known_locations"][0]["location"] == "VN|Hanoi" and ev["known_locations"][0]["count"] == 20
    assert ev["successful_login_count"] == 20 and ev["profile_age_days"] >= 20 and ev["first_seen_location"] == "VN|Hanoi"
    assert env.detector_alerts("impossible_travel") == []


def test_negative_familiar_location(env):
    seed_user(env, "alice", days=20)
    env.login("alice", success=True, ip=HOME_IP, ts=T0 + timedelta(hours=2))
    assert env.detector_alerts(RULE) == []


def test_negative_new_city_inside_a_familiar_country(env):
    seed_user(env, "alice", days=20)  # chỉ Hà Nội
    env.login("alice", success=True, ip=HCM_IP, ts=T0 + timedelta(days=1))  # TP.HCM, vẫn Việt Nam
    assert env.detector_alerts(RULE) == []


def test_negative_new_account_is_not_evaluated(env):
    seed_user(env, "newbie", days=4)
    env.login("newbie", success=True, ip=JP_IP, ts=T0 + timedelta(days=1))
    assert env.detector_alerts(RULE) == []


def test_negative_trip_already_in_history(env):
    seed_user(env, "alice", days=20)
    for k in range(3):  # đã từng công tác Nhật 90 ngày trước
        env.add_history("alice", ip=JP_IP, ts=T0 - timedelta(days=90 - k))
    env.login("alice", success=True, ip=JP_IP, ts=T0 + timedelta(days=1))
    assert env.detector_alerts(RULE) == []


def test_negative_missing_geoip_is_skipped_not_guessed(env):
    seed_user(env, "alice", days=20)
    env.login("alice", success=True, ip=NO_GEO_IP, ts=T0 + timedelta(days=1))
    assert env.detector_alerts(RULE) == []
    assert all(RULE not in v.matched_rules for v in env.verdicts)


def test_negative_failed_login_from_a_new_country(env):
    seed_user(env, "alice", days=20)
    env.login("alice", success=False, ip=FR_IP, ts=T0 + timedelta(days=1))
    assert env.detector_alerts(RULE) == []


def test_profile_poisoning_failed_logins_never_add_a_location(env):
    """Một loạt lần THẤT BẠI từ Pháp không được làm hồ sơ 'quen' Pháp: lần THÀNH CÔNG từ Pháp sau đó vẫn là vị trí lạ."""
    from app.detection.rule_engine_runtime import DbAccountHistory

    seed_user(env, "alice", days=20)
    for k in range(6):
        env.login("alice", success=False, ip=FR_IP, ts=T0 + timedelta(hours=k))
    db = env.session_factory()
    try:
        history = DbAccountHistory(db, T0 + timedelta(days=1)).get(str(env.user_id("alice")))
    finally:
        db.close()
    assert history.known_countries == ("VN",) and all(not loc.startswith("FR|") for loc in history.known_locations)
    env.login("alice", success=True, ip=FR_IP, ts=T0 + timedelta(days=1))
    assert len(env.detector_alerts(RULE)) == 1


def test_boundary_success_count_and_profile_age(env):
    seed_user(env, "nine", days=PARAMS["min_successes"] - 1)
    seed_user(env, "ten", days=PARAMS["min_successes"])
    env.add_user("young")
    for k in range(14):  # 14 lần trong 6 ngày: đủ số lần, chưa đủ tuổi
        env.add_history("young", ip=HOME_IP, ts=T0 - timedelta(days=6) + timedelta(days=6 * k / 14))
    for name in ("nine", "ten"):
        env.login(name, success=True, ip=JP_IP, ts=T0 + timedelta(days=1))
    env.login("young", success=True, ip=JP_IP, ts=T0 + timedelta(hours=1))  # tuổi hồ sơ lúc này ≈ 6,04 ngày (< 7)
    assert [a.user_id for a in env.detector_alerts(RULE)] == [env.user_id("ten")]


def test_attribution_impossible_travel_is_primary_and_location_is_secondary(env):
    seed_user(env, "alice", days=20)
    env.login("alice", success=True, ip=HOME_IP, ts=T0)
    env.login("alice", success=True, ip=US_IP, ts=T0 + timedelta(minutes=5))
    alerts = env.detection_alerts()
    assert [a.rule_id for a in alerts] == ["impossible_travel"]
    assert "unusual_location" in alerts[0].explanation["secondary_signals"]


def test_attribution_location_and_device_keep_both_reasons(env):
    seed_user(env, "alice", days=20, user_agent=CHROME_UA)
    env.login("alice", success=True, ip=JP_IP, ts=T0 + timedelta(days=1), user_agent=SAFARI_UA)
    alerts = env.detection_alerts()
    assert [a.rule_id for a in alerts] == [RULE]
    assert "unusual_device" in alerts[0].explanation["secondary_signals"]
