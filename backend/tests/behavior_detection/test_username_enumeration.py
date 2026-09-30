"""username_enumeration — một IP thử nhiều tên đăng nhập KHÔNG tồn tại (ngưỡng `min_usernames`=8 trong `window_s`=600s).

Mọi test đi qua `run_detection_pipeline` thật → rule engine → attribution → bảng `alerts`."""

from datetime import timedelta

from app.detection.engine.registry import REGISTRY
from tests.behavior_detection.conftest import HOME_IP, OFFICE_NAT_IP, T0, US_IP, seed_user
from verification.harness import CHROME_UA, CURL_UA

RULE = "username_enumeration"
THRESHOLD = next(p.default for p in REGISTRY[RULE].params if p.name == "min_usernames")


def _enumerate(env, n, *, ip=US_IP, gap_s=45, user_agent=CHROME_UA, prefix="khong_ton_tai"):
    for i in range(n):
        env.login(f"{prefix}_{i:02d}", success=False, ip=ip, ts=T0 + timedelta(seconds=i * gap_s), user_agent=user_agent)


def test_positive_ip_trying_many_unknown_usernames_creates_an_attributed_alert(env):
    _enumerate(env, 10)

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1  # gộp trùng lặp: cùng IP + cùng detector trong 15 phút -> một hàng, đếm số lần
    alert = alerts[0]
    exp = alert.explanation
    assert exp["primary_detector"] == RULE
    assert exp["behavior"] == "username_enumeration"
    assert RULE in exp["matched_rules"]
    assert exp["alert_reason"] == "rule_enforced"
    assert exp["evidence"]["distinct_unknown_usernames"] >= THRESHOLD
    assert alert.occurrence_count == 10 - THRESHOLD + 1
    assert exp["action"] == "allow"  # CHỈ cảnh báo — không step_up/lock


def test_negative_user_mistyping_their_username_a_few_times_does_not_alert(env):
    seed_user(env, "alice")
    for i, typo in enumerate(("alcie", "alise", "alicee")):
        env.login(typo, success=False, ip=HOME_IP, ts=T0 + timedelta(seconds=i * 20))
    env.login("alice", success=True, ip=HOME_IP, ts=T0 + timedelta(seconds=80))

    assert env.detector_alerts(RULE) == []


def test_negative_many_people_behind_one_nat_each_mistyping_once_does_not_alert(env):
    # 7 tên sai khác nhau từ cùng NAT văn phòng trong 10 phút: dưới ngưỡng 8.
    _enumerate(env, THRESHOLD - 1, ip=OFFICE_NAT_IP, gap_s=80, prefix="nhan_vien_go_sai")
    assert env.detector_alerts(RULE) == []


def test_boundary_threshold_minus_one_does_not_alert_threshold_does(env):
    _enumerate(env, THRESHOLD - 1)
    assert env.detector_alerts(RULE) == []

    env.login("khong_ton_tai_99", success=False, ip=US_IP, ts=T0 + timedelta(seconds=THRESHOLD * 45))
    assert len(env.detector_alerts(RULE)) == 1


def test_boundary_same_count_spread_beyond_the_window_does_not_alert(env):
    # 8 tên nhưng cách nhau 90s: cửa sổ 600s chỉ chứa tối đa 7.
    _enumerate(env, THRESHOLD, gap_s=90)
    assert env.detector_alerts(RULE) == []


def test_attribution_scripted_client_also_matching_keeps_enumeration_as_primary(env):
    _enumerate(env, 10, user_agent=CURL_UA)

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    assert "scripted_client" in alerts[0].explanation["matched_rules"]
    assert alerts[0].explanation["primary_detector"] == RULE
    # Trước khi đạt ngưỡng chỉ có scripted_client khớp -> các lần đó quy kết cho scripted_client; alert enumeration bắt
    # đầu ĐÚNG ở lần thử thứ THRESHOLD (không sớm hơn).
    events = env.events()
    scripted = env.detector_alerts("scripted_client")
    assert len(scripted) == 1 and scripted[0].login_event_id == events[0].id
    assert alerts[0].login_event_id == events[THRESHOLD - 1].id


def test_integration_through_the_http_login_endpoint(client, db_session, fake_redis, monkeypatch):
    """POST /login → BackgroundTasks → run_detection_pipeline → alert (tên không tồn tại luôn đi đường nền)."""
    from app.models import Alert
    from verification.harness import install_fixture_telemetry

    install_fixture_telemetry(monkeypatch.setattr, fake_redis)
    for i in range(THRESHOLD):
        response = client.post("/login", json={"username": f"ghost_{i}", "password": "x"}, headers={"user-agent": CHROME_UA})
        assert response.status_code == 401

    alerts = db_session.query(Alert).filter(Alert.alert_type == "hybrid_risk", Alert.rule_id == RULE).all()
    assert len(alerts) == 1
    assert alerts[0].explanation["primary_detector"] == RULE
