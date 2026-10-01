"""bot_user_agent — yêu cầu đăng nhập mang User-Agent của crawler/bot đã biết (Googlebot, Bingbot...). Tín hiệu YẾU: mức
low, không bao giờ tự step_up/lock (UA giả mạo được). Khi một hành vi tấn công cụ thể cùng khớp, hành vi đó làm detector chính."""

from datetime import timedelta

import pytest

from tests.behavior_detection.conftest import HOME_IP, T0, US_IP, seed_user
from verification.harness import CHROME_UA, EDGE_UA, FIREFOX_UA, MOBILE_UA, SAFARI_UA
from verification.scenarios import BOT_UAS

RULE = "bot_user_agent"


@pytest.fixture(autouse=True)
def _candidate(as_candidate):
    as_candidate(RULE)


@pytest.mark.parametrize("ua", BOT_UAS[:4])
def test_positive_crawler_user_agent_on_the_login_endpoint(env, ua):
    seed_user(env, "alice")
    env.login("alice", success=False, ip=US_IP, ts=T0, user_agent=ua)
    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    exp = alerts[0].explanation
    assert exp["primary_detector"] == RULE and exp["behavior"] == "bot_user_agent"
    assert alerts[0].severity == "low"
    assert exp["action"] == "allow"  # không step_up/lock chỉ vì UA bot


@pytest.mark.parametrize("ua", [CHROME_UA, FIREFOX_UA, EDGE_UA, SAFARI_UA, MOBILE_UA, "curl/8.7.1", "okhttp/4.12.0", None])
def test_negative_regular_clients(env, ua):
    seed_user(env, "alice")
    env.login("alice", success=True, ip=HOME_IP, ts=T0, user_agent=ua)
    assert env.detector_alerts(RULE) == []


def test_boundary_browser_ua_mentioning_bot_in_a_path_is_not_a_bot(env):
    seed_user(env, "alice")
    env.login("alice", success=True, ip=HOME_IP, ts=T0, user_agent=CHROME_UA + " (homepage http://example.com/robots)")
    assert env.detector_alerts(RULE) == []
    env.login("alice", success=False, ip=US_IP, ts=T0 + timedelta(hours=1), user_agent=BOT_UAS[0])
    assert len(env.detector_alerts(RULE)) == 1


def test_bot_alone_never_triggers_step_up_or_lock(env):
    from app.models import ResponseAction

    seed_user(env, "alice")
    env.login("alice", success=True, ip=US_IP, ts=T0, user_agent=BOT_UAS[0])
    db = env.session_factory()
    try:
        assert db.query(ResponseAction).count() == 0
    finally:
        db.close()
    assert all(e.hybrid_action == "allow" for e in env.events())


def test_attribution_bot_doing_brute_force_is_attributed_to_brute_force(env):
    seed_user(env, "victim")
    for j in range(6):
        env.login("victim", success=False, ip=US_IP, ts=T0 + timedelta(seconds=j * 20), user_agent=BOT_UAS[1])
    alerts = env.detection_alerts()
    assert [a.rule_id for a in alerts] == ["brute_force"]
    assert "bot_user_agent" in alerts[0].explanation["secondary_signals"]
