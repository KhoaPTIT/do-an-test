"""success_after_failures — đăng nhập THÀNH CÔNG ngay sau chuỗi lần sai gần đây vào cùng tài khoản (ngưỡng mặc định:
`min_fails`=5 lần sai trong `window_s`=600s trước đó).

Trước Phase 3 hành vi này chỉ lộ ra qua alert `high_risk_score` của tầng 2 cũ (+50 điểm khi ≥3 lần sai) — không quy kết
được cho luật, và luật v2 có trọng số hybrid 0,0. Alert tầng 2 cũ VẪN giữ nguyên (không bị xoá) — test chỉ đếm alert
quy kết đúng detector."""

from datetime import timedelta

from app.detection.engine.registry import REGISTRY
from tests.behavior_detection.conftest import HOME_IP, T0, US_IP, seed_user
from verification.harness import PY_REQUESTS_UA

RULE = "success_after_failures"
PARAMS = {p.name: p.default for p in REGISTRY[RULE].params}


def _fails_then_success(env, n_fails, *, ip=US_IP, gap_s=30, success_at_s=None, user_agent=None, success=True):
    kwargs = {} if user_agent is None else {"user_agent": user_agent}
    for i in range(n_fails):
        env.login("victim", success=False, ip=ip, ts=T0 + timedelta(seconds=i * gap_s), **kwargs)
    if success:
        at = success_at_s if success_at_s is not None else n_fails * gap_s + 20
        env.login("victim", success=True, ip=ip, ts=T0 + timedelta(seconds=at), **kwargs)


def test_positive_success_right_after_a_failure_streak_is_attributed(env):
    seed_user(env, "victim")
    _fails_then_success(env, 6)

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    exp = alerts[0].explanation
    assert exp["primary_detector"] == RULE and exp["behavior"] == "success_after_failures"
    assert exp["evidence"]["fails_before"] >= PARAMS["min_fails"]
    assert alerts[0].severity == "high"
    # Milestone B (B0.3): chuỗi sai (brute_force) rồi thành công là MỘT chiến dịch vào cùng tài khoản — cảnh báo
    # brute_force đang mở được nâng cấp thành success_after_failures (kẻ tấn công đã vào được), không thành hai cảnh báo.
    assert env.detector_alerts("brute_force") == []
    assert exp["superseded_detectors"] == ["brute_force"]
    success_event = env.events()[-1]
    assert success_event.success is True
    # chỉ lần THÀNH CÔNG khớp success_after_failures (verdict thật của pipeline)
    assert [v.primary_detector for v in env.verdicts if RULE in v.matched_rules] == [RULE]


def test_negative_owner_typing_wrong_password_twice(env):
    seed_user(env, "victim")
    _fails_then_success(env, 2, ip=HOME_IP)
    assert env.detector_alerts(RULE) == []


def test_negative_failure_streak_without_success(env):
    seed_user(env, "victim")
    _fails_then_success(env, 6, success=False)
    assert env.detector_alerts(RULE) == []


def test_boundary_threshold_minus_one_failures_then_threshold(env):
    seed_user(env, "victim")
    _fails_then_success(env, PARAMS["min_fails"] - 1)
    assert env.detector_alerts(RULE) == []
    # tầng 2 cũ (≥3 lần sai) vẫn có thể báo high_risk_score — KHÔNG được tính là success_after_failures
    assert all(a.rule_id != RULE for a in env.alerts())


def test_boundary_threshold_failures_trigger(env):
    seed_user(env, "victim")
    _fails_then_success(env, PARAMS["min_fails"])
    assert len(env.detector_alerts(RULE)) == 1


def test_boundary_failures_older_than_the_window(env):
    # 5 lần sai trong 2 phút đầu, thành công ở giây 800: cửa sổ 600s không còn lần sai nào.
    seed_user(env, "victim")
    _fails_then_success(env, PARAMS["min_fails"], success_at_s=800)
    assert env.detector_alerts(RULE) == []


def test_attribution_scripted_client_on_the_success_keeps_primary(env):
    seed_user(env, "victim")
    _fails_then_success(env, 6, user_agent=PY_REQUESTS_UA)

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    assert "scripted_client" in alerts[0].explanation["matched_rules"]
    assert alerts[0].explanation["primary_detector"] == RULE


def test_negative_shared_account_with_typos_among_many_successful_logins(env):
    """Milestone C — báo nhầm thật lộ ra từ lưu lượng bình thường v3 (tài khoản dùng chung kiểu kiosk): 5 lần gõ sai XEN
    GIỮA 6 lần đăng nhập đúng trong 10 phút không phải 'đoán trúng mật khẩu'."""
    seed_user(env, "kiosk")
    t = 0
    for ok in (True, False, True, False, True, False, True, False, True, False, True):
        env.login("kiosk", success=ok, ip=HOME_IP, ts=T0 + timedelta(seconds=t))
        t += 50
    env.login("kiosk", success=True, ip=HOME_IP, ts=T0 + timedelta(seconds=t))
    assert env.detector_alerts(RULE) == []


def test_boundary_one_prior_success_among_many_failures_still_alerts(env):
    # 6 lần sai + 1 lần đúng xen giữa (tỉ lệ 1/7 ≈ 0,14 ≤ 0,2) rồi thành công: vẫn là đoán trúng
    seed_user(env, "victim")
    for k, ok in enumerate((False, False, False, True, False, False, False)):
        env.login("victim", success=ok, ip=US_IP, ts=T0 + timedelta(seconds=k * 30))
    env.login("victim", success=True, ip=US_IP, ts=T0 + timedelta(seconds=250))
    assert len(env.detector_alerts(RULE)) == 1
