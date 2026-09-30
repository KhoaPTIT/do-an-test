"""blocklist_hit — nguồn (IP, CIDR, ASN, tên đăng nhập) nằm trong blocklist quản trị viên đặt, còn hiệu lực. Luật GHI ĐÈ
(điểm 100, hành động lock — hành vi MR16 sẵn có, Phase 3 không đổi).

⚠️ Qua HTTP `POST /login`, mục chặn loại ip/cidr/username bị TỪ CHỐI NGAY (HTTP 423 + audit log) trước khi vào pipeline
(`app/routers/auth.py`, tiền kiểm) — nên alert `blocklist_hit` trong vận hành thật chủ yếu đến từ mục chặn loại ASN (tiền
kiểm không tra ASN) hoặc mục vừa được thêm trong lúc request đang chạy. Các test dưới gọi pipeline trực tiếp (đường "event")."""

from datetime import timedelta

from tests.behavior_detection.conftest import HOME_IP, T0, US_IP, seed_user

RULE = "blocklist_hit"


def test_positive_blocked_ip_is_attributed_with_override_and_lock(env):
    seed_user(env, "victim")
    env.add_block("ip", US_IP)
    env.login("victim", success=False, ip=US_IP, ts=T0)

    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1
    exp = alerts[0].explanation
    assert exp["primary_detector"] == RULE and exp["behavior"] == "blocklisted_source"
    assert exp["alert_reason"] == "override" and exp["risk_score"] == 100 and exp["action"] == "lock"


def test_positive_each_block_kind(env):
    for i, (kind, value, ip, user) in enumerate([
        ("cidr", "198.51.100.192/26", "198.51.100.201", "u_cidr"),
        ("asn", "64530", "203.0.113.20", "u_asn"),  # FIXTURE: 203.0.113.0/26 thuộc ASN 64530
        ("username", "u_name", HOME_IP, "u_name"),
    ]):
        seed_user(env, user)
        env.add_block(kind, value)
        env.login(user, success=True, ip=ip, ts=T0 + timedelta(hours=i))
    assert sorted(a.user_id for a in env.detector_alerts(RULE)) == sorted(env.user_id(u) for u in ("u_cidr", "u_asn", "u_name"))


def test_negative_unrelated_source_and_expired_entry(env):
    seed_user(env, "victim")
    env.add_block("ip", "198.51.100.250")
    env.add_block("ip", US_IP, expires_at=T0 - timedelta(minutes=1))
    env.login("victim", success=True, ip=US_IP, ts=T0)
    assert env.detector_alerts(RULE) == []


def test_boundary_expiry_just_after_and_just_before_the_event(env):
    seed_user(env, "a")
    seed_user(env, "b")
    env.add_block("username", "a", expires_at=T0 + timedelta(seconds=1))
    env.add_block("username", "b", expires_at=T0)  # hết hạn ĐÚNG lúc sự kiện: không còn hiệu lực
    env.login("a", success=True, ip=HOME_IP, ts=T0)
    env.login("b", success=True, ip=HOME_IP, ts=T0)
    assert [a.user_id for a in env.detector_alerts(RULE)] == [env.user_id("a")]


def test_attribution_blocked_source_doing_brute_force_is_attributed_to_the_block(env):
    seed_user(env, "victim")
    env.add_block("ip", US_IP)
    for i in range(6):
        env.login("victim", success=False, ip=US_IP, ts=T0 + timedelta(seconds=i * 20))
    alerts = env.detector_alerts(RULE)
    assert len(alerts) == 1 and "brute_force" in alerts[0].explanation["matched_rules"]
    assert env.detector_alerts("brute_force") == []
