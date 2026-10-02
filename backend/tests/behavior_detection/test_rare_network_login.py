"""rare_network_login — đăng nhập THÀNH CÔNG từ nhà mạng (ASN) hiếm, theo mức trưởng thành của dữ liệu (thiết kế C7, Phase 2):
COLD_START (< `warm_min_total`=500 lượt thành công toàn hệ thống) không chấm; WARM: ASN chưa từng có trong lịch sử thành công
của CHÍNH tài khoản (hồ sơ trưởng thành: ≥10 lần, ≥7 ngày) VÀ chiếm ≤ `warm_max_share`=1% lượt thành công toàn hệ thống;
MATURE (≥ 20.000 lượt): luật gốc theo tỉ lệ ≤ 2e-5 (kiểm ở tests/test_rule_engine_rules.py)."""

from datetime import timedelta

import pytest

from app.detection.engine.registry import REGISTRY
from tests.behavior_detection.conftest import HCM_IP, HOME_IP, JP_IP, T0, seed_user
from verification.harness import CHROME_UA

RULE = "rare_network_login"
PARAMS = {p.name: p.default for p in REGISTRY[RULE].params}
DANANG_IP = "192.0.2.200"  # FIXTURE: VN/Da Nang, ASN 64515 — không người dùng nền nào dùng
HCM_POOL_IPS = [f"192.0.2.{i}" for i in range(130, 150)]


@pytest.fixture(autouse=True)
def _candidate(as_candidate):
    as_candidate(RULE)


def _population(env, total, *, ips=(HOME_IP,), extra=()):
    """Người dùng nền: `total` lần thành công trong 30 ngày qua từ `ips` xoay vòng, cộng `extra` = [(ip, n)]."""
    names = [f"bg{k:02d}" for k in range(max(10, total // 40))]
    for name in names:
        env.add_user(name)
    rows = [ip for ip, n in extra for _ in range(n)]
    rows += [ips[j % len(ips)] for j in range(total - len(rows))]
    for j, ip in enumerate(rows):
        env.add_history(names[j % len(names)], ip=ip, ts=T0 - timedelta(days=1 + (j % 29), minutes=j % 600))


def test_positive_same_country_rare_isp_in_warm_state(env):
    _population(env, 600)
    seed_user(env, "alice", days=20)
    env.login("alice", success=True, ip=DANANG_IP, ts=T0 + timedelta(hours=2))

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    exp = alerts[0].explanation
    assert exp["primary_detector"] == RULE and exp["action"] == "allow"
    ev = exp["evidence"]
    assert ev["data_state"] == "WARM" and ev["asn"] == 64515 and ev["new_for_account"] is True
    assert ev["known_asns"] == [64512] and ev["share"] <= PARAMS["warm_max_share"] and ev["total_successes"] >= PARAMS["warm_min_total"]
    assert ev["successful_login_count"] == 20 and ev["profile_age_days"] >= 7
    assert env.detector_alerts("unusual_location") == []  # cùng quốc gia: chỉ nhà mạng là lạ


def test_negative_rare_isp_already_used_by_the_account(env):
    _population(env, 600)
    seed_user(env, "alice", days=20)
    env.add_history("alice", ip=DANANG_IP, ts=T0 - timedelta(days=60))
    env.login("alice", success=True, ip=DANANG_IP, ts=T0 + timedelta(hours=2))
    assert env.detector_alerts(RULE) == []


def test_negative_new_for_the_account_but_common_isp(env):
    _population(env, 600, ips=(HOME_IP, HCM_IP))  # một nửa người dùng nền ở HCM
    seed_user(env, "alice", days=20)
    env.login("alice", success=True, ip=HCM_POOL_IPS[3], ts=T0 + timedelta(hours=2))
    assert env.detector_alerts(RULE) == []


@pytest.mark.parametrize(("extra", "expected"), [(5, 1), (9, 0)])
def test_boundary_global_share_around_one_percent(env, extra, expected):
    # 600 lượt nền + 20 của alice + lần đăng nhập này ⇒ ~621: 5+1 lượt ≈ 0,97% (≤ 1%), 9+1 lượt ≈ 1,6% (> 1%)
    _population(env, 600, extra=[(DANANG_IP, extra)])
    seed_user(env, "alice", days=20)
    env.login("alice", success=True, ip=DANANG_IP, ts=T0 + timedelta(hours=2))
    assert len(env.detector_alerts(RULE)) == expected


def test_negative_cold_start_system_has_too_little_data(env):
    _population(env, 300)
    seed_user(env, "alice", days=20)
    env.login("alice", success=True, ip=DANANG_IP, ts=T0 + timedelta(hours=2))
    assert env.detector_alerts(RULE) == []
    assert all(RULE not in v.matched_rules for v in env.verdicts)


@pytest.mark.parametrize("days", [5, 9])
def test_negative_immature_account(env, days):
    _population(env, 600)
    seed_user(env, "newbie", days=days)  # 5 ngày (< 7) hoặc 9 lần (< 10)
    env.login("newbie", success=True, ip=DANANG_IP, ts=T0 + timedelta(hours=2))
    assert env.detector_alerts(RULE) == []


def test_negative_failed_logins_from_a_rare_isp(env):
    _population(env, 600)
    seed_user(env, "alice", days=20)
    for k in range(3):
        env.login("alice", success=False, ip=DANANG_IP, ts=T0 + timedelta(minutes=k))
    assert env.detector_alerts(RULE) == []


def test_profile_poisoning_failures_do_not_make_an_isp_known(env):
    _population(env, 600)
    seed_user(env, "alice", days=20)
    for k in range(5):
        env.login("alice", success=False, ip=DANANG_IP, ts=T0 + timedelta(minutes=k))
    env.login("alice", success=True, ip=DANANG_IP, ts=T0 + timedelta(minutes=10))
    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1 and alerts[0].explanation["evidence"]["known_asns"] == [64512]


def test_missing_asn_is_a_telemetry_gap_not_an_alert(env):
    _population(env, 600)
    seed_user(env, "alice", days=20)
    env.login("alice", success=True, ip="100.64.3.10", ts=T0 + timedelta(hours=2))
    assert env.detector_alerts(RULE) == []
    assert all(RULE not in v.matched_rules for v in env.verdicts)


def test_attribution_foreign_rare_isp_keeps_rare_network_primary(env):
    _population(env, 600)
    seed_user(env, "alice", days=20, user_agent=CHROME_UA)
    env.login("alice", success=True, ip=JP_IP, ts=T0 + timedelta(hours=2))  # nhà mạng hiếm VÀ quốc gia chưa từng thấy
    alerts = env.detection_alerts()
    assert [a.rule_id for a in alerts] == [RULE]
    assert "unusual_location" in alerts[0].explanation["secondary_signals"]
