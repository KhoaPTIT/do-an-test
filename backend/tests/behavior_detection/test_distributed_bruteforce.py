"""distributed_bruteforce — MỘT tài khoản bị đoán mật khẩu từ NHIỀU IP (ngưỡng mặc định: `min_fails`=8 lần sai từ
`min_ips`=5 IP khác nhau trong `window_s`=3600s).

Trọng số hybrid của luật này = 0,0 (hiệu chỉnh trên RBA chỉ có 2 mẫu, docs/behavior-coverage-matrix.md) — KHÔNG sửa
trọng số: phát hiện ở đây là theo NGƯỠNG XÁC ĐỊNH của chính luật (enforce), điểm hybrid vẫn giữ nguyên như đã đo.

Kịch bản dương tính cố ý dùng botnet CÙNG khu vực địa lý với nạn nhân (Hà Nội) — biến thể MR18 đã nghi là lọt vì trước
đây chỉ bắt được "tình cờ" qua impossible_travel khi IP ở xa."""

from datetime import timedelta

from app.detection.engine.registry import REGISTRY
from tests.behavior_detection.conftest import HOME_IP, MOBILE_IP, T0, seed_user
from verification.fixtures import ips_in

RULE = "distributed_bruteforce"
PARAMS = {p.name: p.default for p in REGISTRY[RULE].params}
SAME_REGION_IPS = [ip for ip in ips_in("192.0.2.0/26") if ip != HOME_IP][10:40]  # FIXTURE: cùng Hà Nội, cùng ASN nhà mạng


def _attack(env, victim, n_fails, ips, *, gap_s=360):
    for i in range(n_fails):
        env.login(victim, success=False, ip=ips[i % len(ips)], ts=T0 + timedelta(seconds=i * gap_s))


def test_positive_same_region_botnet_one_failure_per_ip(env):
    seed_user(env, "victim")
    _attack(env, "victim", 10, SAME_REGION_IPS)

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    exp = alerts[0].explanation
    assert exp["primary_detector"] == RULE and exp["behavior"] == "distributed_brute_force"
    assert exp["alert_reason"] == "rule_enforced"
    assert exp["evidence"]["distinct_ips"] >= PARAMS["min_ips"] and exp["evidence"]["fails"] >= PARAMS["min_fails"]
    assert exp["action"] == "allow"
    # 6 phút/lần: không chạm brute_force (5 lần/5 phút), cùng khu vực: không có impossible_travel
    assert env.detector_alerts("brute_force") == [] and env.detector_alerts("impossible_travel") == []


def test_positive_still_alerts_with_the_calibrated_zero_weight(env, monkeypatch):
    """Với hồ sơ hybrid ĐÃ HIỆU CHỈNH (trọng số distributed_bruteforce = 0,0): luật KHỚP nhưng KHÔNG góp điểm — cảnh
    báo vẫn được tạo vì ngưỡng riêng của luật đã thoả (enforce), không phải vì ai đó nâng trọng số."""
    from app.detection import hybrid_runtime
    from app.detection.hybrid import HybridProfile
    from app.detection.hybrid_runtime import CALIBRATED_PROFILE_PATH as _PROFILE_PATH  # Phase 4.1: hằng số chuyển chỗ

    calibrated = HybridProfile.from_file(_PROFILE_PATH)
    assert calibrated.weights.weight_of(RULE) == 0.0
    monkeypatch.setattr(hybrid_runtime.get_engine(), "profile", calibrated)

    seed_user(env, "victim")
    _attack(env, "victim", 10, SAME_REGION_IPS)

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    exp = alerts[0].explanation
    assert RULE in exp["matched_rules"]
    assert all(c["rule"] != RULE for c in exp["contributing_rules"])
    assert exp["risk_score"] < calibrated.bands.alert_at  # điểm vẫn dưới ngưỡng toàn cục — ngưỡng không bị hạ


def test_negative_owner_mistyping_from_home_and_mobile(env):
    seed_user(env, "alice")
    for i, ip in enumerate((HOME_IP, MOBILE_IP, HOME_IP)):
        env.login("alice", success=False, ip=ip, ts=T0 + timedelta(minutes=i * 3))
    env.login("alice", success=True, ip=HOME_IP, ts=T0 + timedelta(minutes=10))

    assert env.detector_alerts(RULE) == []


def test_boundary_fail_count_threshold_minus_one_then_threshold(env):
    seed_user(env, "victim")
    _attack(env, "victim", PARAMS["min_fails"] - 1, SAME_REGION_IPS)
    assert env.detector_alerts(RULE) == []

    env.login("victim", success=False, ip=SAME_REGION_IPS[20], ts=T0 + timedelta(seconds=(PARAMS["min_fails"] - 1) * 360))
    assert len(env.detector_alerts(RULE)) == 1


def test_boundary_enough_failures_but_too_few_distinct_ips(env):
    seed_user(env, "victim")
    _attack(env, "victim", PARAMS["min_fails"] + 2, SAME_REGION_IPS[: PARAMS["min_ips"] - 1])
    assert env.detector_alerts(RULE) == []


def test_boundary_failures_spread_beyond_the_window(env):
    # 8 lần sai từ 8 IP nhưng cách nhau 17 phút (2 giờ): cửa sổ 1 giờ chỉ chứa tối đa 4.
    seed_user(env, "victim")
    _attack(env, "victim", PARAMS["min_fails"], SAME_REGION_IPS, gap_s=17 * 60)
    assert env.detector_alerts(RULE) == []


def test_attribution_fast_distributed_attack_also_matching_brute_force(env):
    # Nhanh (30s/lần) nên brute_force khớp từ lần thứ 5; từ lần thứ 8 (đủ 8 IP) detector chính phải là dò PHÂN TÁN.
    seed_user(env, "victim")
    _attack(env, "victim", 10, SAME_REGION_IPS, gap_s=30)

    # Milestone B (B0.3): cùng một chuỗi sự kiện vào cùng tài khoản -> MỘT cảnh báo chiến dịch. Các lần 5–7 mở cảnh
    # báo brute_force; từ lần thứ 8 dò PHÂN TÁN (đặc hiệu hơn) tiếp quản chính cảnh báo đó thay vì tạo cảnh báo thứ hai.
    distributed = env.detector_alerts(RULE)
    assert len(distributed) == 1 and env.detector_alerts("brute_force") == []
    exp = distributed[0].explanation
    assert exp["primary_detector"] == RULE
    assert exp["superseded_detectors"] == ["brute_force"] and "brute_force" in exp["secondary_signals"]
    # verdict THẬT từng lần thử: đủ điều kiện dò phân tán thì detector chính luôn là distributed_bruteforce
    assert all(v.primary_detector == RULE for v in env.verdicts if RULE in v.matched_rules)
