"""multi_context_simultaneous — CÙNG một tài khoản có đăng nhập THÀNH CÔNG từ ≥ `min_countries`=2 quốc gia trong
`window_s`=600s. Thiết kế Phase 2: chỉ tính là hành vi riêng ở phần impossible_travel KHÔNG làm được — GeoIP chỉ biết quốc
gia, không có toạ độ (FIXTURE 198.18.0.0/24). Khi cả hai bên có toạ độ, impossible_travel làm detector chính."""

from datetime import timedelta

import pytest

from app.detection.engine.registry import REGISTRY
from tests.behavior_detection.conftest import HOME_IP, JP_IP, T0, seed_user
from verification.harness import CURL_UA, MOBILE_UA

RULE = "multi_context_simultaneous"
WINDOW = next(p.default for p in REGISTRY[RULE].params if p.name == "window_s")
SG_ONLY, US_ONLY, VN_ONLY, KR_ONLY = "198.18.0.10", "198.18.0.70", "198.18.0.130", "198.18.0.200"  # FIXTURE: chỉ quốc gia


@pytest.fixture(autouse=True)
def _candidate(as_candidate):
    as_candidate(RULE)


def _login(env, ip, seconds, name="alice", success=True, ua=None):
    kwargs = {} if ua is None else {"user_agent": ua}
    env.login(name, success=success, ip=ip, ts=T0 + timedelta(seconds=seconds), **kwargs)


def test_positive_home_then_country_only_abroad(env):
    seed_user(env, "alice")
    _login(env, HOME_IP, 0)
    _login(env, SG_ONLY, 300)

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    exp = alerts[0].explanation
    assert exp["primary_detector"] == RULE and exp["action"] == "allow" and alerts[0].severity == "high"
    assert exp["evidence"]["countries"] == ["SG", "VN"] and exp["evidence"]["window_s"] == WINDOW
    assert env.detector_alerts("impossible_travel") == []  # không có toạ độ ⇒ không tính được tốc độ


def test_positive_country_only_mobile_then_abroad_with_coordinates(env):
    seed_user(env, "alice")
    _login(env, VN_ONLY, 0, ua=MOBILE_UA)
    _login(env, JP_IP, 240)  # lần thành công trước KHÔNG có toạ độ ⇒ impossible_travel không áp dụng
    assert len(env.detector_alerts(RULE)) == 1 and env.detector_alerts("impossible_travel") == []


def test_positive_three_countries(env):
    seed_user(env, "alice")
    for k, ip in enumerate((HOME_IP, US_ONLY, KR_ONLY)):
        _login(env, ip, k * 100)
    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1 and alerts[0].occurrence_count == 2
    assert alerts[0].explanation["evidence"]["countries"] == ["KR", "US", "VN"]


@pytest.mark.parametrize(("gap", "expected"), [(WINDOW - 5, 1), (WINDOW + 5, 0)])
def test_boundary_window(env, gap, expected):
    seed_user(env, "alice")
    _login(env, HOME_IP, 0)
    _login(env, US_ONLY, gap)
    assert len(env.detector_alerts(RULE)) == expected


def test_negative_same_country_two_contexts(env):
    seed_user(env, "alice")
    _login(env, HOME_IP, 0)
    _login(env, VN_ONLY, 120, ua=MOBILE_UA)
    assert env.detector_alerts(RULE) == []


def test_negative_failed_attempts_abroad_do_not_count(env):
    seed_user(env, "alice")
    for k in range(3):
        _login(env, SG_ONLY, k * 20, success=False, ua=CURL_UA)
    _login(env, HOME_IP, 200)
    assert env.detector_alerts(RULE) == []


def test_negative_unknown_country_is_ignored(env):
    seed_user(env, "alice")
    _login(env, HOME_IP, 0)
    _login(env, "100.64.7.7", 120)  # ngoài GeoIP: quốc gia '?'
    assert env.detector_alerts(RULE) == []


def test_negative_two_accounts_in_two_countries(env):
    seed_user(env, "alice")
    seed_user(env, "bob")
    _login(env, HOME_IP, 0)
    _login(env, SG_ONLY, 60, name="bob")
    assert env.detector_alerts(RULE) == []


def test_negative_same_foreign_country_two_ips(env):
    seed_user(env, "alice")
    _login(env, KR_ONLY, 0)
    _login(env, "198.18.0.201", 90, ua=MOBILE_UA)
    assert env.detector_alerts(RULE) == []


def test_attribution_with_coordinates_impossible_travel_is_primary(env):
    seed_user(env, "alice")
    _login(env, HOME_IP, 0)
    _login(env, JP_IP, 300)  # Hà Nội → Tokyo trong 5 phút: cả hai có toạ độ
    alerts = env.detection_alerts()
    assert [a.rule_id for a in alerts] == ["impossible_travel"]
    assert RULE in alerts[0].explanation["secondary_signals"]
