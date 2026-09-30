"""brute_force — nhiều lần sai vào CÙNG một tên đăng nhập trong thời gian ngắn (ngưỡng mặc định: `threshold`=5 lần sai
trong `window_s`=300s). Regression cho một trong 4 hành vi VERIFIED sẵn có, nay đo theo quy kết."""

from datetime import timedelta

from app.detection.engine.registry import REGISTRY
from tests.behavior_detection.conftest import HOME_IP, T0, TOR_IP, US_IP, seed_user
from verification.harness import CURL_UA

RULE = "brute_force"
PARAMS = {p.name: p.default for p in REGISTRY[RULE].params}


def _fails(env, n, *, ip=US_IP, gap_s=20, user_agent=None):
    kwargs = {} if user_agent is None else {"user_agent": user_agent}
    for i in range(n):
        env.login("victim", success=False, ip=ip, ts=T0 + timedelta(seconds=i * gap_s), **kwargs)


def test_positive_repeated_failures_on_one_account(env):
    seed_user(env, "victim")
    _fails(env, 7)

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    exp = alerts[0].explanation
    assert exp["primary_detector"] == RULE and exp["behavior"] == "brute_force"
    assert exp["evidence"]["fails"] >= PARAMS["threshold"]
    assert alerts[0].occurrence_count == 7 - PARAMS["threshold"] + 1
    assert any(a.alert_type == "brute_force" for a in env.alerts())  # alert tầng 1 gốc vẫn còn (không phá dashboard cũ)


def test_negative_owner_mistyping_twice_then_succeeding(env):
    seed_user(env, "victim")
    _fails(env, 2, ip=HOME_IP)
    env.login("victim", success=True, ip=HOME_IP, ts=T0 + timedelta(seconds=60))
    assert env.detector_alerts(RULE) == []


def test_boundary_threshold_minus_one_then_threshold(env):
    seed_user(env, "victim")
    _fails(env, PARAMS["threshold"] - 1)
    assert env.detector_alerts(RULE) == []
    env.login("victim", success=False, ip=US_IP, ts=T0 + timedelta(seconds=PARAMS["threshold"] * 20))
    assert len(env.detector_alerts(RULE)) == 1


def test_boundary_same_count_spread_beyond_the_window(env):
    seed_user(env, "victim")
    _fails(env, PARAMS["threshold"], gap_s=80)  # lần thứ 5 ở giây 320: cửa sổ 300s chỉ chứa 4
    assert env.detector_alerts(RULE) == []


def test_attribution_markers_do_not_steal_the_primary(env):
    seed_user(env, "victim")
    _fails(env, 6, ip=TOR_IP, user_agent=CURL_UA)

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    assert {"tor_exit", "scripted_client"} <= set(alerts[0].explanation["matched_rules"])


def test_attribution_attacker_far_away_is_not_reported_as_impossible_travel(env):
    """Lỗi quy kết đo được ở audit Phase 1: brute force từ IP ở xa sinh thêm alert impossible_travel. Sau Phase 3
    (impossible travel chỉ tính THÀNH CÔNG → THÀNH CÔNG) các lần thử sai chỉ quy kết cho brute_force."""
    seed_user(env, "victim")  # nhà ở Hà Nội
    _fails(env, 6, ip=US_IP)

    assert len(env.detector_alerts(RULE)) == 1
    assert env.detector_alerts("impossible_travel") == []
    assert not any(a.alert_type == "impossible_travel" for a in env.alerts())
