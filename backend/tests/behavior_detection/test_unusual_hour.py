"""unusual_hour — tài khoản trưởng thành đăng nhập THÀNH CÔNG vào giờ lệch xa khỏi giờ trung tâm (trung bình vòng tròn)
của chính nó: lệch > max(3σ vòng tròn, 4 giờ), hồ sơ đủ tập trung (R ≥ 0,5). Không giờ nào "luôn nguy hiểm"."""

from datetime import timedelta

import pytest

from app.detection.engine.profile import circular_hour_distance
from tests.behavior_detection.conftest import HOME_IP, T0
from verification.harness import CHROME_UA, SAFARI_UA

RULE = "unusual_hour"
MIDNIGHT = T0 - timedelta(hours=9)  # T0 = 09:00 UTC


@pytest.fixture(autouse=True)
def _candidate(as_candidate):
    as_candidate(RULE)


def _profile(env, name, hours, days=20, ua=CHROME_UA):
    env.add_user(name)
    for d in range(days, 0, -1):
        for h in hours[d % len(hours)] if isinstance(hours[0], (list, tuple)) else [hours[d % len(hours)]]:
            env.add_history(name, ip=HOME_IP, ts=MIDNIGHT - timedelta(days=d) + timedelta(hours=h), user_agent=ua)


def _login_at(env, name, hour, success=True, day=0, ua=CHROME_UA):
    env.login(name, success=success, ip=HOME_IP, ts=MIDNIGHT + timedelta(days=day, hours=hour), user_agent=ua)


def test_positive_office_hours_profile_then_3am(env):
    _profile(env, "alice", [8, 10, 12, 14, 16, 18, 9, 11, 13, 15, 17])  # 08:00–18:00
    _login_at(env, "alice", 3.0)

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.alert_type == "behavior_anomaly" and a.severity == "low"
    exp = a.explanation
    assert exp["primary_detector"] == RULE and exp["behavior"] == "unusual_hour" and exp["action"] == "allow"
    ev = exp["evidence"]
    assert abs(ev["usual_hour_center"] - 13.0) < 0.5 and ev["current_hour"] == 3.0
    assert ev["hour_deviation"] > ev["threshold_hours"] and ev["sample_count"] == 20 and ev["profile_age_days"] >= 19


def test_negative_night_user_logging_in_at_night(env):
    _profile(env, "owl", [22, 23, 0, 1, 2, 23.5])
    _login_at(env, "owl", 1.5)
    assert env.detector_alerts(RULE) == []


def test_negative_one_hour_off(env):
    _profile(env, "alice", [9, 9.5, 10, 10.5])
    _login_at(env, "alice", 11.5)
    assert env.detector_alerts(RULE) == []


def test_negative_new_account_is_not_evaluated(env):
    _profile(env, "newbie", [9, 10], days=5)
    _login_at(env, "newbie", 21.0)
    assert env.detector_alerts(RULE) == []


def test_negative_failed_login_at_an_odd_hour(env):
    _profile(env, "alice", [9, 10, 11])
    _login_at(env, "alice", 22.0, success=False)
    assert env.detector_alerts(RULE) == []


@pytest.mark.parametrize("hour", [23.75, 0.25, 1.5, 22.5])
def test_negative_profile_around_midnight_is_circular(env, hour):
    # hồ sơ 23:00–01:00: trung tâm ≈ 00:00 (không phải 12:00 như trung bình số học)
    _profile(env, "alice", [23.0, 23.5, 0.0, 0.5, 1.0])
    _login_at(env, "alice", hour)
    assert env.detector_alerts(RULE) == []


def test_positive_around_midnight_profile_then_noon(env):
    _profile(env, "alice", [23.0, 23.5, 0.0, 0.5, 1.0])
    _login_at(env, "alice", 12.0)
    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    ev = alerts[0].explanation["evidence"]
    assert circular_hour_distance(ev["usual_hour_center"], 0.0) < 0.5 and ev["hour_deviation"] > 11


def test_negative_dispersed_bimodal_profile_is_not_scored(env):
    _profile(env, "alice", [8, 20])  # sáng + tối: R ≈ 0, không có "giờ quen" rõ ràng
    _login_at(env, "alice", 14.0)
    assert env.detector_alerts(RULE) == []
    assert all(RULE not in v.matched_rules for v in env.verdicts)


def test_boundary_minimum_deviation_hours(env):
    _profile(env, "a", [10.0])  # cực đều: σ ≈ 0 → ngưỡng = 4 giờ tối thiểu
    _profile(env, "b", [10.0])
    _login_at(env, "a", 13.9)  # lệch 3,9h
    _login_at(env, "b", 14.1)  # lệch 4,1h
    assert [x.user_id for x in env.detector_alerts(RULE)] == [env.user_id("b")]


def test_profile_poisoning_failed_logins_at_3am_do_not_shift_the_profile(env):
    from app.detection.engine.profile import hour_profile
    from app.detection.rule_engine_runtime import DbAccountHistory

    _profile(env, "alice", [9, 10, 11])
    for k in range(10):
        _login_at(env, "alice", 3.0 + k * 0.05, success=False)
    db = env.session_factory()
    try:
        hp = hour_profile(DbAccountHistory(db, MIDNIGHT + timedelta(days=1)).get(str(env.user_id("alice"))))
    finally:
        db.close()
    assert abs(hp.center - 10.0) < 0.5 and hp.sample_count == 20
    _login_at(env, "alice", 3.0, day=1)
    assert len(env.detector_alerts(RULE)) == 1


def test_attribution_hour_and_device_keep_both_reasons(env):
    _profile(env, "alice", [9, 10, 11], ua=CHROME_UA)
    _login_at(env, "alice", 22.0, ua=SAFARI_UA)
    alerts = env.detection_alerts()
    assert [a.rule_id for a in alerts] == [RULE]
    assert "unusual_device" in alerts[0].explanation["secondary_signals"]
