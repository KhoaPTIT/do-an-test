"""login_velocity_spike — NHIỀU lần đăng nhập THÀNH CÔNG vào cùng tài khoản trong 10 phút: ≥ 8 lần VÀ ≥ 2 lần đỉnh lịch
sử của chính tài khoản trong cùng độ dài cửa sổ (đỉnh chỉ học từ lần thành công). Khác brute_force (lần THẤT BẠI)."""

from datetime import timedelta

import pytest

from app.detection.engine.registry import REGISTRY
from tests.behavior_detection.conftest import HOME_IP, T0, US_IP, seed_user
from verification.harness import CHROME_UA, PY_REQUESTS_UA

RULE = "login_velocity_spike"
PARAMS = {p.name: p.default for p in REGISTRY[RULE].params}


@pytest.fixture(autouse=True)
def _candidate(as_candidate):
    as_candidate(RULE)


def _burst(env, name, n, *, gap_s=45, start=T0, success=True, ua=CHROME_UA, ip=HOME_IP):
    for k in range(n):
        env.login(name, success=success, ip=ip, ts=start + timedelta(seconds=k * gap_s), user_agent=ua)


def _service_profile(env, name, burst_size, days=15):
    """Tài khoản dùng chung có lịch sử đăng nhập theo đợt `burst_size` lần trong vài phút."""
    env.add_user(name)
    for d in range(days, 0, -1):
        for k in range(burst_size):
            env.add_history(name, ip=HOME_IP, ts=T0 - timedelta(days=d) + timedelta(seconds=k * 40))


def test_positive_normal_user_then_twelve_successes_in_ten_minutes(env):
    seed_user(env, "alice", days=20)  # 1 lần/ngày
    _burst(env, "alice", 12)

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.alert_type == "behavior_anomaly" and a.severity == "medium"
    exp = a.explanation
    assert exp["primary_detector"] == RULE and exp["behavior"] == "login_velocity_spike" and exp["action"] == "allow"
    ev = exp["evidence"]
    assert ev["recent_success_count"] >= PARAMS["min_successes_in_window"] and ev["window_minutes"] == 10
    assert ev["baseline_peak_in_window"] == 1 and ev["velocity_ratio"] >= PARAMS["min_velocity_ratio"]
    # evidence của cảnh báo chiến dịch là của lần thử MỚI NHẤT: số lần thành công đã gồm các lần trước đó trong đợt
    assert ev["successful_login_count"] >= 20 and ev["profile_age_days"] >= 20 and ev["baseline_rate_per_day"] > 0
    assert a.occurrence_count == 12 - PARAMS["min_successes_in_window"] + 1  # một cảnh báo chiến dịch


def test_negative_two_or_three_logins_in_ten_minutes(env):
    seed_user(env, "alice", days=20)
    _burst(env, "alice", 3, gap_s=120)
    assert env.detector_alerts(RULE) == []


def test_negative_new_account_is_not_evaluated(env):
    seed_user(env, "newbie", days=3)
    _burst(env, "newbie", 12)
    assert env.detector_alerts(RULE) == []


def test_negative_rapid_failures_are_brute_force_not_velocity(env):
    seed_user(env, "victim", days=20)
    _burst(env, "victim", 10, gap_s=20, success=False, ip=US_IP)
    env.login("victim", success=True, ip=US_IP, ts=T0 + timedelta(seconds=210))
    assert env.detector_alerts(RULE) == []
    assert all(RULE not in v.matched_rules for v in env.verdicts)


def test_negative_service_account_with_a_high_baseline(env):
    _service_profile(env, "kiosk", burst_size=12)
    _burst(env, "kiosk", 12, gap_s=40)
    assert env.detector_alerts(RULE) == []


def test_boundary_success_count(env):
    seed_user(env, "a", days=20)
    seed_user(env, "b", days=20)
    _burst(env, "a", PARAMS["min_successes_in_window"] - 1)
    _burst(env, "b", PARAMS["min_successes_in_window"])
    assert [x.user_id for x in env.detector_alerts(RULE)] == [env.user_id("b")]


def test_boundary_velocity_ratio_against_the_historical_peak(env):
    _service_profile(env, "p5a", burst_size=5)
    _service_profile(env, "p5b", burst_size=5)
    _burst(env, "p5a", 9, gap_s=40)  # 9 / 5 = 1,8 < 2
    _burst(env, "p5b", 10, gap_s=40)  # 10 / 5 = 2,0
    assert [x.user_id for x in env.detector_alerts(RULE)] == [env.user_id("p5b")]


def test_profile_poisoning_rapid_failures_do_not_raise_the_success_baseline(env):
    from app.detection.rule_engine_runtime import DbAccountHistory

    seed_user(env, "alice", days=20)
    _burst(env, "alice", 15, gap_s=10, success=False, ip=US_IP)
    db = env.session_factory()
    try:
        history = DbAccountHistory(db, T0 + timedelta(days=1)).get(str(env.user_id("alice")))
    finally:
        db.close()
    assert history.baseline_peak((T0 + timedelta(days=1)).timestamp()) == 1 and history.n_success == 20
    _burst(env, "alice", 10, start=T0 + timedelta(days=1))
    assert len(env.detector_alerts(RULE)) == 1


def test_attribution_velocity_is_primary_and_scripted_client_is_secondary(env):
    seed_user(env, "alice", days=20)
    _burst(env, "alice", 12, ua=PY_REQUESTS_UA)
    alerts = env.detection_alerts()
    assert [a.rule_id for a in alerts] == [RULE]
    assert "scripted_client" in alerts[0].explanation["secondary_signals"]
