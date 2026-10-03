"""unusual_device — đăng nhập THÀNH CÔNG từ họ thiết bị chưa từng thấy, khi hồ sơ tài khoản đã trưởng thành (mặc định:
≥ 10 lần thành công VÀ ≥ 7 ngày từ lần thành công đầu tiên). Thiết bị chuẩn hoá theo họ (loại | HĐH | trình duyệt): Chrome
120 → 121 KHÔNG phải thiết bị mới. Cảnh báo `behavior_anomaly`, mức low, không tự step_up/lock."""

from datetime import timedelta

import pytest

from app.detection.engine.registry import REGISTRY
from tests.behavior_detection.conftest import HOME_IP, MOBILE_IP, T0, US_IP, seed_user
from verification.harness import CHROME_UA, EDGE_UA, FIREFOX_UA, MOBILE_UA, SAFARI_UA
from verification.scenarios import chrome_version_ua

RULE = "unusual_device"
PARAMS = {p.name: p.default for p in REGISTRY[RULE].params}


@pytest.fixture(autouse=True)
def _candidate(as_candidate):
    as_candidate(RULE)


def test_positive_stable_profile_then_a_never_seen_device(env):
    seed_user(env, "alice", days=20, user_agent=CHROME_UA)
    env.login("alice", success=True, ip=HOME_IP, ts=T0, user_agent=SAFARI_UA)

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.alert_type == "behavior_anomaly" and a.severity == "low"
    exp = a.explanation
    assert exp["primary_detector"] == RULE and exp["behavior"] == "unusual_device" and exp["action"] == "allow"
    ev = exp["evidence"]
    assert ev["current_device"] == "desktop|Mac OS X|Safari"
    assert ev["known_devices"] == ["desktop|Windows|Chrome"] and ev["known_device_count"] == 1
    assert ev["successful_login_count"] == 20 and ev["profile_age_days"] >= 20
    assert ev["profile_first_seen"] and ev["current_context"]["ip"] == HOME_IP


def test_negative_same_device_and_browser_version_update(env):
    seed_user(env, "alice", days=20, user_agent=chrome_version_ua(120))
    env.login("alice", success=True, ip=HOME_IP, ts=T0, user_agent=chrome_version_ua(120))
    env.login("alice", success=True, ip=HOME_IP, ts=T0 + timedelta(days=1), user_agent=chrome_version_ua(125))  # Chrome tự cập nhật
    assert env.detector_alerts(RULE) == []


def test_negative_new_account_is_not_evaluated(env):
    seed_user(env, "newbie", days=3, user_agent=CHROME_UA)
    env.login("newbie", success=True, ip=HOME_IP, ts=T0, user_agent=SAFARI_UA)
    assert env.detector_alerts(RULE) == []


def test_negative_laptop_and_phone_already_in_history(env):
    env.add_user("alice")
    for d in range(20, 0, -1):
        env.add_history("alice", ip=MOBILE_IP if d % 3 == 0 else HOME_IP, ts=T0 - timedelta(days=d), user_agent=MOBILE_UA if d % 3 == 0 else CHROME_UA)
    env.login("alice", success=True, ip=MOBILE_IP, ts=T0, user_agent=MOBILE_UA)
    assert env.detector_alerts(RULE) == []


def test_negative_several_familiar_browsers(env):
    env.add_user("alice")
    for d in range(21, 0, -1):
        env.add_history("alice", ip=HOME_IP, ts=T0 - timedelta(days=d), user_agent=(CHROME_UA, FIREFOX_UA, EDGE_UA)[d % 3])
    env.login("alice", success=True, ip=HOME_IP, ts=T0, user_agent=FIREFOX_UA)
    assert env.detector_alerts(RULE) == []


def test_negative_failed_attempt_from_a_new_device_is_not_a_device_login(env):
    seed_user(env, "alice", days=20)
    env.login("alice", success=False, ip=US_IP, ts=T0, user_agent=SAFARI_UA)
    assert env.detector_alerts(RULE) == []


def test_boundary_success_count_maturity(env):
    seed_user(env, "nine", days=PARAMS["min_successes"] - 1)
    env.login("nine", success=True, ip=HOME_IP, ts=T0, user_agent=SAFARI_UA)
    assert env.detector_alerts(RULE) == []
    seed_user(env, "ten", days=PARAMS["min_successes"])
    env.login("ten", success=True, ip=HOME_IP, ts=T0, user_agent=SAFARI_UA)
    assert [a.user_id for a in env.detector_alerts(RULE)] == [env.user_id("ten")]


def test_boundary_profile_age_maturity(env):
    # 14 lần thành công nhưng dồn trong 6 ngày (hồ sơ chưa đủ tuổi), rồi đúng 7 ngày.
    for name, span_days in (("young", PARAMS["min_profile_days"] - 1), ("aged", PARAMS["min_profile_days"])):
        env.add_user(name)
        for k in range(14):
            env.add_history(name, ip=HOME_IP, ts=T0 - timedelta(days=span_days) + timedelta(days=span_days * k / 14), user_agent=CHROME_UA)
        env.login(name, success=True, ip=HOME_IP, ts=T0, user_agent=SAFARI_UA)
    assert [a.user_id for a in env.detector_alerts(RULE)] == [env.user_id("aged")]


def test_attribution_impossible_travel_is_primary_and_new_device_is_supporting_evidence(env):
    seed_user(env, "alice", days=20, user_agent=CHROME_UA)
    env.login("alice", success=True, ip=HOME_IP, ts=T0, user_agent=CHROME_UA)
    env.login("alice", success=True, ip=US_IP, ts=T0 + timedelta(minutes=10), user_agent=SAFARI_UA)
    alerts = env.detection_alerts()
    assert [a.rule_id for a in alerts] == ["impossible_travel"]
    assert "unusual_device" in alerts[0].explanation["secondary_signals"]
