"""dormant_account_login — tài khoản không đăng nhập thành công nhiều tháng bỗng đăng nhập lại KÈM ngữ cảnh mới (ngưỡng
mặc định: `dormant_days`=90 ngày; `require_change`=true: phải có quốc gia HOẶC thiết bị chưa từng thấy).

Lịch sử tài khoản (fixture) chỉ là các lần đăng nhập thật trong quá khứ — detector tự dựng lại từ bảng login_events."""

from datetime import timedelta

from app.detection.engine.registry import REGISTRY
from tests.behavior_detection.conftest import HOME_IP, JP_IP, T0, TOR_IP, seed_user
from verification.harness import CHROME_UA, SAFARI_UA

RULE = "dormant_account_login"
DORMANT_DAYS = next(p.default for p in REGISTRY[RULE].params if p.name == "dormant_days")


def _dormant_user(env, idle_days, username="sleeper"):
    """5 lần đăng nhập thành công (Chrome, Hà Nội) — lần cuối cách T0 đúng `idle_days` ngày."""
    return seed_user(env, username, days=5, end=T0 - timedelta(days=idle_days) + timedelta(days=1))


def test_positive_return_after_120_days_on_a_new_device(env):
    _dormant_user(env, 120)
    env.login("sleeper", success=True, ip=HOME_IP, ts=T0, user_agent=SAFARI_UA)

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    exp = alerts[0].explanation
    assert exp["primary_detector"] == RULE and exp["behavior"] == "dormant_account_reactivation"
    assert exp["evidence"]["idle_days"] >= DORMANT_DAYS and exp["evidence"]["new_device"] is True
    assert exp["action"] == "allow"


def test_positive_return_after_200_days_from_a_new_country(env):
    _dormant_user(env, 200)
    env.login("sleeper", success=True, ip=JP_IP, ts=T0, user_agent=CHROME_UA)

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    assert alerts[0].explanation["evidence"]["new_country"] is True


def test_negative_return_after_120_days_with_the_same_device_and_country(env):
    _dormant_user(env, 120)
    env.login("sleeper", success=True, ip=HOME_IP, ts=T0, user_agent=CHROME_UA)
    assert env.detector_alerts(RULE) == []


def test_negative_active_user_on_a_new_device(env):
    seed_user(env, "active", days=20)
    env.login("active", success=True, ip=HOME_IP, ts=T0, user_agent=SAFARI_UA)
    assert env.detector_alerts(RULE) == []


def test_boundary_idle_just_below_and_at_the_threshold(env):
    _dormant_user(env, DORMANT_DAYS - 1, username="almost")
    env.login("almost", success=True, ip=HOME_IP, ts=T0, user_agent=SAFARI_UA)
    assert env.detector_alerts(RULE) == []

    _dormant_user(env, DORMANT_DAYS, username="exactly")
    env.login("exactly", success=True, ip=HOME_IP, ts=T0 + timedelta(minutes=1), user_agent=SAFARI_UA)
    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1 and alerts[0].user_id == env.user_id("exactly")


def test_negative_failed_attempt_on_a_dormant_account_is_not_a_reactivation(env):
    _dormant_user(env, 150)
    env.login("sleeper", success=False, ip=JP_IP, ts=T0, user_agent=SAFARI_UA)
    assert env.detector_alerts(RULE) == []


def test_attribution_dormant_return_through_tor_keeps_dormant_as_primary(env):
    # tor_exit (dấu hiệu hạ tầng) cũng khớp; hành vi chính vẫn là tài khoản ngủ đông bị kích hoạt lại.
    _dormant_user(env, 150)
    env.login("sleeper", success=True, ip=TOR_IP, ts=T0, user_agent=SAFARI_UA)

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    assert "tor_exit" in alerts[0].explanation["matched_rules"]
    assert env.detector_alerts("tor_exit") == []
