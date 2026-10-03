"""regular_rhythm — các lần đăng nhập SAI gần nhất từ MỘT IP cách nhau đều đặn và dày: `samples`=10 lần sai gần nhất có
khoảng cách trung bình ≤ `max_mean_interval_s`=30s và hệ số biến thiên ≤ `max_cv`=0,15. Là tín hiệu ĐÁNH DẤU (cách tấn
công): khi hành vi đặc hiệu hơn (brute force, nhồi thông tin...) cũng khớp thì hành vi đó làm detector chính."""

from datetime import timedelta

import pytest

from app.detection.engine.registry import REGISTRY
from tests.behavior_detection.conftest import HOME_IP, MOBILE_IP, OFFICE_NAT_IP, T0, TOR_IP, US_IP, seed_user
from verification.harness import CURL_UA, MOBILE_UA, PY_REQUESTS_UA

RULE = "regular_rhythm"
PARAMS = {p.name: p.default for p in REGISTRY[RULE].params}


@pytest.fixture(autouse=True)
def _candidate(as_candidate):
    as_candidate(RULE)


def _rhythm(env, names, n, gap, *, ip=US_IP, ua=CURL_UA, start=T0, jitter=()):
    for j in range(n):
        offset = j * gap + (jitter[j] if j < len(jitter) else 0.0)
        env.login(names[j % len(names)], success=False, ip=ip, ts=start + timedelta(seconds=offset), user_agent=ua)


def test_positive_machine_rhythm_over_three_accounts(env):
    for n in ("a1", "a2", "a3"):
        seed_user(env, n)
    _rhythm(env, ["a1", "a2", "a3"], 11, 25.0)  # Phase 2: 3 tài khoản, 11 lần sai cách đều 25 giây

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1  # các lần khớp sau gộp vào cùng một cảnh báo chiến dịch
    exp = alerts[0].explanation
    assert exp["primary_detector"] == RULE and exp["action"] == "allow"
    ev = exp["evidence"]
    assert ev["ip"] == US_IP and ev["samples"] == PARAMS["samples"] and ev["mean_interval_s"] == 25.0 and ev["cv"] == 0.0
    # curl ⇒ scripted_client khớp từ lần 1; tới lần 10 regular_rhythm (đặc hiệu hơn) tiếp quản CHÍNH cảnh báo đó
    assert alerts[0].occurrence_count == 11 and exp["superseded_detectors"] == ["scripted_client"]
    assert env.detector_alerts("brute_force") == [] and env.detector_alerts("credential_stuffing") == []


def test_positive_small_jitter_still_regular(env):
    jitter = [0, 1.5, -1.2, 0.8, -1.9, 1.1, -0.4, 1.7, -1.5, 0.6]  # ±2s trên 20s ⇒ CV ≈ 0,06
    _rhythm(env, ["g1", "g2", "g3", "g4"], 10, 20.0, ua=PY_REQUESTS_UA, jitter=jitter)
    assert len(env.detector_alerts(RULE)) == 1


def test_negative_human_irregular_intervals(env):
    gaps = [4, 31, 9, 22, 3, 40, 12, 7, 28, 15, 5]  # TB ≈ 16s nhưng CV ≈ 0,7
    t = 0.0
    for j, g in enumerate(gaps):
        env.login(f"u{j % 3}", success=False, ip=US_IP, ts=T0 + timedelta(seconds=t))
        t += g
    assert env.detector_alerts(RULE) == []


def test_boundary_samples_minus_one_then_samples(env):
    _rhythm(env, ["x1", "x2", "x3"], PARAMS["samples"] - 1, 15.0)
    assert env.detector_alerts(RULE) == []
    env.login("x1", success=False, ip=US_IP, ts=T0 + timedelta(seconds=(PARAMS["samples"] - 1) * 15.0), user_agent=CURL_UA)
    assert len(env.detector_alerts(RULE)) == 1


def test_boundary_mean_interval_just_above_and_below(env):
    _rhythm(env, ["s1", "s2", "s3"], 10, PARAMS["max_mean_interval_s"] + 1, ip="198.51.100.201")
    assert env.detector_alerts(RULE) == []
    _rhythm(env, ["f1", "f2", "f3"], 10, PARAMS["max_mean_interval_s"] - 1, ip="198.51.100.202", start=T0 + timedelta(hours=2))
    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1 and alerts[0].explanation["evidence"]["ip"] == "198.51.100.202"


def test_boundary_cv_just_above_the_limit(env):
    # khoảng cách xen kẽ 20s·(1 ± 0,17) ⇒ CV ≈ 0,17 > 0,15
    gaps = [23.4, 16.6] * 5
    t = 0.0
    for j in range(10):
        env.login(f"c{j % 3}", success=False, ip=US_IP, ts=T0 + timedelta(seconds=t))
        t += gaps[j]
    assert env.detector_alerts(RULE) == []


def test_negative_office_nat_scattered_typos(env):
    for k in range(10):
        seed_user(env, f"nv{k}", ip=OFFICE_NAT_IP)
    t = 0.0
    for k, pause in enumerate([25, 70, 40, 85, 33, 60, 22, 90, 45, 30]):
        env.login(f"nv{k}", success=False, ip=OFFICE_NAT_IP, ts=T0 + timedelta(seconds=t))
        env.login(f"nv{k}", success=True, ip=OFFICE_NAT_IP, ts=T0 + timedelta(seconds=t + 8))
        t += pause
    assert env.detector_alerts(RULE) == []


def test_negative_app_retrying_with_exponential_backoff(env):
    seed_user(env, "owner")
    t, wait = 0.0, 1.0
    for _ in range(10):
        env.login("owner", success=False, ip=MOBILE_IP, ts=T0 + timedelta(seconds=t), user_agent=MOBILE_UA)
        t += wait
        wait *= 2
    assert env.detector_alerts(RULE) == []


def test_negative_successes_do_not_count(env):
    seed_user(env, "svc", ip=HOME_IP)
    for j in range(12):
        env.login("svc", success=True, ip=HOME_IP, ts=T0 + timedelta(seconds=j * 10))
    assert env.detector_alerts(RULE) == []


def test_attribution_brute_force_stays_primary(env):
    seed_user(env, "victim")
    _rhythm(env, ["victim"], 11, 20.0)  # 11 lần sai đều vào MỘT tài khoản: hành vi là brute force, nhịp máy chỉ là chi tiết
    alerts = env.detection_alerts()
    assert [a.rule_id for a in alerts] == ["brute_force"]
    assert RULE in alerts[0].explanation["secondary_signals"]


def test_attribution_rhythm_primary_over_scripted_client(env):
    _rhythm(env, ["k1", "k2", "k3"], 10, 12.0, ua=PY_REQUESTS_UA)
    alerts = env.detection_alerts()
    assert [a.rule_id for a in alerts] == [RULE]
    assert "scripted_client" in alerts[0].explanation["secondary_signals"]


def test_attribution_tor_stays_primary(env):
    _rhythm(env, ["t1", "t2", "t3"], 10, 12.0, ip=TOR_IP)
    alerts = env.detection_alerts()
    assert [a.rule_id for a in alerts] == ["tor_exit"]
    assert RULE in alerts[0].explanation["secondary_signals"]
