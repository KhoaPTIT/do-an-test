"""credential_stuffing — một IP thử nhiều tên đăng nhập khác nhau với nhiều lần sai trong thời gian ngắn (ngưỡng mặc định:
`min_fails`=10 lần sai và `min_users`=5 tên trong `window_s`=300s; bỏ qua khi tỉ lệ thành công của IP > 0,5)."""

from datetime import timedelta

from app.detection.engine.registry import REGISTRY
from tests.behavior_detection.conftest import OFFICE_NAT_IP, T0, US_IP, seed_user
from verification.harness import CURL_UA

RULE = "credential_stuffing"
PARAMS = {p.name: p.default for p in REGISTRY[RULE].params}


def _accounts(env, n):
    names = [f"kh_{i:02d}" for i in range(n)]
    for name in names:
        seed_user(env, name, days=3)
    return names


def _stuff(env, names, n_fails, *, ip=US_IP, gap_s=20, user_agent=None):
    kwargs = {} if user_agent is None else {"user_agent": user_agent}
    for i in range(n_fails):
        env.login(names[i % len(names)], success=False, ip=ip, ts=T0 + timedelta(seconds=i * gap_s), **kwargs)


def test_positive_one_ip_many_accounts_many_failures(env):
    _stuff(env, _accounts(env, 6), 12)

    alerts = env.detector_alerts(RULE)
    assert alerts
    exp = alerts[0].explanation
    assert exp["primary_detector"] == RULE and exp["behavior"] == "credential_stuffing"
    assert exp["evidence"]["distinct_users"] >= PARAMS["min_users"] and exp["evidence"]["fails"] >= PARAMS["min_fails"]
    assert any(a.alert_type == "credential_stuffing" for a in env.alerts())  # alert tầng 1 gốc vẫn còn


def test_negative_office_nat_with_mostly_successful_logins(env):
    names = _accounts(env, 10)
    for i, name in enumerate(names):
        env.login(name, success=True, ip=OFFICE_NAT_IP, ts=T0 + timedelta(seconds=i * 20))
        if i < 6:  # 6 người gõ sai một lần
            env.login(name, success=False, ip=OFFICE_NAT_IP, ts=T0 + timedelta(seconds=i * 20 + 5))
    assert env.detector_alerts(RULE) == []


def test_boundary_fail_count_threshold_minus_one_then_threshold(env):
    names = _accounts(env, 5)
    _stuff(env, names, PARAMS["min_fails"] - 1)
    assert env.detector_alerts(RULE) == []
    env.login(names[0], success=False, ip=US_IP, ts=T0 + timedelta(seconds=(PARAMS["min_fails"] - 1) * 20))
    assert len(env.detector_alerts(RULE)) >= 1


def test_boundary_enough_failures_but_too_few_accounts(env):
    _stuff(env, _accounts(env, PARAMS["min_users"] - 1), PARAMS["min_fails"])
    assert env.detector_alerts(RULE) == []


def test_attribution_unknown_usernames_and_curl_keep_stuffing_as_primary(env):
    # Nhanh (10 lần/200s) trên tên KHÔNG tồn tại: username_enumeration cũng khớp từ lần thứ 8, nhưng hành vi (mức cao hơn,
    # đặc hiệu hơn khi đủ ngưỡng nhồi) là credential_stuffing.
    for i in range(10):
        env.login(f"leaked_{i}", success=False, ip=US_IP, ts=T0 + timedelta(seconds=i * 20), user_agent=CURL_UA)

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    assert {"username_enumeration", "scripted_client"} <= set(alerts[0].explanation["matched_rules"])
