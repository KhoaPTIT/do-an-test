"""password_spray_slow — một IP thử NHIỀU tài khoản, mỗi tài khoản rất ít lần sai, trải dài hàng giờ (ngưỡng mặc định:
`min_users`=15 tài khoản/24h, trung bình ≤ `max_fails_per_user`=3 lần sai/tài khoản, ≤ 120 lần sai/giờ).

Pipeline KHÔNG nhận mật khẩu: "cùng một mật khẩu" được nhận diện theo HÀNH VI (rải mỏng trên nhiều tài khoản), không so
mật khẩu — không có mật khẩu nào được lưu hay băm để phát hiện."""

from datetime import timedelta

from app.detection.engine.registry import REGISTRY
from tests.behavior_detection.conftest import OFFICE_NAT_IP, T0, US_IP, seed_user
from verification.harness import CHROME_UA, PY_REQUESTS_UA

RULE = "password_spray_slow"
MIN_USERS = next(p.default for p in REGISTRY[RULE].params if p.name == "min_users")


def _victims(env, n, prefix="nv"):
    names = [f"{prefix}_{i:02d}" for i in range(n)]
    for name in names:
        seed_user(env, name, days=3)
    return names


def _spray(env, names, *, gap_min=25, ip=US_IP, user_agent=CHROME_UA):
    for i, name in enumerate(names):
        env.login(name, success=False, ip=ip, ts=T0 + timedelta(minutes=i * gap_min), user_agent=user_agent)


def test_positive_one_ip_one_failure_on_each_of_18_accounts_over_hours(env):
    _spray(env, _victims(env, 18))

    alerts = env.detector_alerts(RULE)
    assert alerts, "không có alert password_spray_slow"
    for alert in alerts:
        exp = alert.explanation
        assert exp["primary_detector"] == RULE and exp["behavior"] == "password_spraying"
        assert exp["alert_reason"] == "rule_enforced"
        assert exp["evidence"]["distinct_users"] >= MIN_USERS
        assert exp["action"] == "allow"
    # không bị quy nhầm sang dò nhanh: tốc độ 25 phút/lần không chạm ngưỡng credential_stuffing/brute_force
    assert env.detector_alerts("credential_stuffing") == [] and env.detector_alerts("brute_force") == []


def test_negative_office_nat_where_several_employees_mistype_once(env):
    names = _victims(env, 6)
    for i, name in enumerate(names):
        env.login(name, success=False, ip=OFFICE_NAT_IP, ts=T0 + timedelta(minutes=i * 7))
        env.login(name, success=True, ip=OFFICE_NAT_IP, ts=T0 + timedelta(minutes=i * 7, seconds=30))

    assert env.detector_alerts(RULE) == []


def test_negative_many_failures_per_account_is_not_a_thin_spray(env):
    # 15 tài khoản nhưng dồn 4 lần sai vào TỪNG tài khoản rồi mới sang tài khoản kế (trung bình luôn > 3 lần/tài khoản
    # khi đủ 15 tài khoản): đoán mật khẩu tuần tự, không phải "rải mỏng". (Rải 1 lần/tài khoản qua cả 15 tài khoản
    # TRƯỚC rồi mới lặp lại thì vòng đầu CHÍNH LÀ rải mật khẩu — detector báo là đúng.)
    t = 0
    for name in _victims(env, 15):
        for _ in range(4):
            env.login(name, success=False, ip=US_IP, ts=T0 + timedelta(minutes=t))
            t += 5
    assert env.detector_alerts(RULE) == []


def test_boundary_threshold_minus_one_accounts_then_threshold(env):
    names = _victims(env, MIN_USERS)
    _spray(env, names[:-1])
    assert env.detector_alerts(RULE) == []

    env.login(names[-1], success=False, ip=US_IP, ts=T0 + timedelta(minutes=25 * MIN_USERS))
    assert len(env.detector_alerts(RULE)) >= 1


def test_boundary_same_accounts_spread_over_more_than_24_hours(env):
    # 15 tài khoản, cách nhau 110 phút => lần thứ 15 ở phút 1540 > 1440: cửa sổ 24h chỉ chứa 14.
    _spray(env, _victims(env, MIN_USERS), gap_min=110)
    assert env.detector_alerts(RULE) == []


def test_attribution_scripted_client_also_matching_keeps_spray_as_primary(env):
    _spray(env, _victims(env, 16), user_agent=PY_REQUESTS_UA)

    alerts = env.detector_alerts(RULE)
    assert alerts
    assert all("scripted_client" in a.explanation["matched_rules"] and a.explanation["primary_detector"] == RULE for a in alerts)
