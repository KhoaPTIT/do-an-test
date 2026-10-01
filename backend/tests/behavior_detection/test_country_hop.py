"""country_hop — một tài khoản bị thử SAI từ nhiều quốc gia trong một khoảng thời gian (ngưỡng mặc định:
`min_countries`=3 quốc gia có lần thất bại trong `window_s`=24h).

Không được để impossible_travel "bắt hộ": impossible travel chỉ so hai lần THÀNH CÔNG (Milestone A, quyết định #2)."""

from datetime import timedelta

from app.detection.engine.registry import REGISTRY
from tests.behavior_detection.conftest import BR_IP, FR_IP, HOME_IP, JP_IP, T0, US_IP, seed_user
from verification.harness import CHROME_UA

import pytest

RULE = "country_hop"
PARAMS = {p.name: p.default for p in REGISTRY[RULE].params}


@pytest.fixture(autouse=True)
def _candidate(as_candidate):
    as_candidate(RULE)


def _fails(env, ips, *, gap_h=3.0, user_agent=CHROME_UA, start=T0):
    for i, ip in enumerate(ips):
        env.login("victim", success=False, ip=ip, ts=start + timedelta(hours=i * gap_h), user_agent=user_agent)


def test_positive_failures_from_three_countries_within_a_day(env):
    seed_user(env, "victim")
    _fails(env, [US_IP, JP_IP, FR_IP])

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    exp = alerts[0].explanation
    assert exp["primary_detector"] == RULE and exp["behavior"] == "country_hopping"
    assert exp["evidence"]["countries"] == ["FR", "JP", "US"] and exp["evidence"]["distinct_countries"] >= PARAMS["min_countries"]
    assert exp["action"] == "allow"
    # thất bại không phải bằng chứng di chuyển: không có impossible_travel ở tầng nào
    assert env.detector_alerts("impossible_travel") == [] and not any(a.alert_type == "impossible_travel" for a in env.alerts())


def test_negative_two_countries_is_within_normal_bounds(env):
    seed_user(env, "victim")
    _fails(env, [HOME_IP, JP_IP, HOME_IP, JP_IP])
    assert env.detector_alerts(RULE) == []


def test_negative_traveller_logging_in_successfully_in_three_countries(env):
    seed_user(env, "victim")
    env.login("victim", success=True, ip=HOME_IP, ts=T0)
    env.login("victim", success=True, ip=JP_IP, ts=T0 + timedelta(hours=7))
    env.login("victim", success=False, ip=FR_IP, ts=T0 + timedelta(hours=22))  # gõ sai một lần ở nước thứ ba
    env.login("victim", success=True, ip=FR_IP, ts=T0 + timedelta(hours=22, minutes=1))
    assert env.detector_alerts(RULE) == []


def test_boundary_threshold_minus_one_countries_then_threshold(env):
    seed_user(env, "victim")
    _fails(env, [US_IP, JP_IP])
    assert env.detector_alerts(RULE) == []
    env.login("victim", success=False, ip=BR_IP, ts=T0 + timedelta(hours=6))
    assert len(env.detector_alerts(RULE)) == 1


def test_boundary_third_country_outside_the_window(env):
    seed_user(env, "victim")
    _fails(env, [US_IP, JP_IP, FR_IP], gap_h=12.5)  # nước thứ 3 ở giờ 25: nước đầu đã ra khỏi cửa sổ 24h
    assert env.detector_alerts(RULE) == []


def test_attribution_country_hop_is_primary_and_bot_marker_is_secondary(env):
    seed_user(env, "victim")
    _fails(env, [US_IP, JP_IP, FR_IP], user_agent="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1 and "bot_user_agent" in alerts[0].explanation["secondary_signals"]
