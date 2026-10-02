"""Ma trận cross-behavior (Milestone B — B8): khi NHIỀU detector cùng khớp một chuỗi sự kiện, cảnh báo phải quy cho
detector cụ thể nhất (thứ tự `attribution.PRIORITY`), các detector còn lại vẫn có mặt trong `secondary_signals` (không mất
bằng chứng), và cả chuỗi là MỘT cảnh báo chiến dịch.

Dùng chung bởi `tests/behavior_detection/test_cross_behavior.py` và `scripts/behavior_verification.py --cross`."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Callable

from verification.harness import CHROME_UA, PY_REQUESTS_UA, SAFARI_UA, VerificationEnv
from verification.scenarios import BOT_UAS, ROTATION_UAS, T0

HOME_IP, US_IP = "192.0.2.10", "198.51.100.200"  # FIXTURE: VN/Hà Nội, US/New York
SAME_REGION = [f"192.0.2.{i}" for i in range(20, 40)]


def _seed(env: VerificationEnv, name: str, days: int = 10, ua: str = CHROME_UA) -> None:
    env.add_user(name)
    for d in range(days, 0, -1):
        env.add_history(name, ip=HOME_IP, ts=T0 - timedelta(days=d), user_agent=ua)


def distributed_with_brute_force_and_scripted_ua(env):
    _seed(env, "victim")
    for i in range(10):  # nhanh (30s/lần) nên brute_force khớp từ lần 5; từ lần 8 đủ 5+ IP
        env.login("victim", success=False, ip=SAME_REGION[i], ts=T0 + timedelta(seconds=i * 30), user_agent=PY_REQUESTS_UA)


def stuffing_with_enumeration(env):
    for i in range(12):
        env.login(f"leaked_{i}", success=False, ip=US_IP, ts=T0 + timedelta(seconds=i * 20))


def spray_with_scripted_client(env):
    names = [f"sp_{i:02d}" for i in range(18)]
    for n in names:
        _seed(env, n, days=3)
    for i, n in enumerate(names):
        env.login(n, success=False, ip=US_IP, ts=T0 + timedelta(minutes=i * 25), user_agent=PY_REQUESTS_UA)


def brute_force_with_bot_ua(env):
    _seed(env, "victim")
    for i in range(6):
        env.login("victim", success=False, ip=US_IP, ts=T0 + timedelta(seconds=i * 20), user_agent=BOT_UAS[0])


def ua_rotation_with_stuffing(env):
    names = [f"kh{i}" for i in range(6)]
    for n in names:
        _seed(env, n, days=2)
    for i in range(12):
        env.login(names[i % 6], success=False, ip=US_IP, ts=T0 + timedelta(seconds=i * 15), user_agent=ROTATION_UAS[i % 6])


def unusual_device_with_impossible_travel(env):
    _seed(env, "alice", days=20, ua=CHROME_UA)  # hồ sơ trưởng thành
    env.login("alice", success=True, ip=HOME_IP, ts=T0, user_agent=CHROME_UA)
    env.login("alice", success=True, ip=US_IP, ts=T0 + timedelta(minutes=10), user_agent=SAFARI_UA)


def unusual_device_with_scripted_client(env):
    _seed(env, "alice", days=20, ua=CHROME_UA)  # hồ sơ trưởng thành, rồi đăng nhập đúng bằng công cụ kịch bản
    env.login("alice", success=True, ip=HOME_IP, ts=T0, user_agent=PY_REQUESTS_UA)


JP_IP = "203.0.113.10"  # FIXTURE: JP/Tokyo
MIDNIGHT = T0 - timedelta(hours=T0.hour)


def unusual_location_with_impossible_travel(env):
    _seed(env, "alice", days=20)
    env.login("alice", success=True, ip=HOME_IP, ts=T0)
    env.login("alice", success=True, ip=US_IP, ts=T0 + timedelta(minutes=5))  # nước chưa từng thấy VÀ không thể bay tới kịp


def unusual_location_with_unusual_device(env):
    _seed(env, "alice", days=20, ua=CHROME_UA)
    env.login("alice", success=True, ip=JP_IP, ts=T0 + timedelta(days=2), user_agent=SAFARI_UA)


def unusual_hour_with_unusual_device(env):
    env.add_user("alice")
    for d in range(20, 0, -1):
        env.add_history("alice", ip=HOME_IP, ts=MIDNIGHT - timedelta(days=d) + timedelta(hours=9 + d % 3), user_agent=CHROME_UA)
    env.login("alice", success=True, ip=HOME_IP, ts=MIDNIGHT + timedelta(hours=22), user_agent=SAFARI_UA)


def unusual_hour_with_unusual_location(env):
    env.add_user("alice")
    for d in range(20, 0, -1):
        env.add_history("alice", ip=HOME_IP, ts=MIDNIGHT - timedelta(days=d) + timedelta(hours=9 + d % 3), user_agent=CHROME_UA)
    env.login("alice", success=True, ip=JP_IP, ts=MIDNIGHT + timedelta(hours=22), user_agent=CHROME_UA)


def velocity_with_scripted_client(env):
    _seed(env, "alice", days=20)
    for k in range(12):
        env.login("alice", success=True, ip=HOME_IP, ts=T0 + timedelta(seconds=k * 45), user_agent=PY_REQUESTS_UA)


def rapid_failures_are_brute_force_not_velocity(env):
    _seed(env, "alice", days=20)
    for k in range(12):
        env.login("alice", success=False, ip=US_IP, ts=T0 + timedelta(seconds=k * 20))


# --- Milestone C+

def rhythm_with_scripted_client(env):
    for k in range(10):  # 10 lần sai cách đều 12s vào 3 tài khoản bằng python-requests: dưới ngưỡng brute force/nhồi thông tin
        env.login(f"rr{k % 3}", success=False, ip=US_IP, ts=T0 + timedelta(seconds=k * 12), user_agent=PY_REQUESTS_UA)


def brute_force_with_regular_rhythm(env):
    _seed(env, "victim")
    for k in range(11):  # nhịp máy vào MỘT tài khoản: hành vi là brute force, nhịp là chi tiết
        env.login("victim", success=False, ip=US_IP, ts=T0 + timedelta(seconds=k * 20))


def _background(env, total=600):
    names = [f"bg{k:02d}" for k in range(15)]
    for name in names:
        env.add_user(name)
    for j in range(total):
        env.add_history(names[j % 15], ip=HOME_IP, ts=T0 - timedelta(days=1 + j % 29, minutes=j % 600))


def rare_network_with_unusual_location(env):
    _background(env)
    _seed(env, "alice", days=20)
    env.login("alice", success=True, ip=JP_IP, ts=T0 + timedelta(hours=2))  # nhà mạng hiếm VÀ quốc gia mới


def rare_network_with_unusual_device(env):
    _background(env)
    _seed(env, "alice", days=20, ua=CHROME_UA)
    env.login("alice", success=True, ip="192.0.2.200", ts=T0 + timedelta(hours=2), user_agent=SAFARI_UA)  # VN/Đà Nẵng, ASN 64515


SG_ONLY = "198.18.0.10"  # FIXTURE: GeoIP chỉ biết quốc gia SG, không toạ độ


def multi_context_with_impossible_travel(env):
    _seed(env, "alice", days=20)
    env.login("alice", success=True, ip=HOME_IP, ts=T0)
    env.login("alice", success=True, ip=JP_IP, ts=T0 + timedelta(minutes=5))  # cả hai có toạ độ: tính được tốc độ


def multi_context_with_unusual_location(env):
    _seed(env, "alice", days=20)
    env.login("alice", success=True, ip=HOME_IP, ts=T0)
    env.login("alice", success=True, ip=SG_ONLY, ts=T0 + timedelta(minutes=5))  # nước mới, KHÔNG toạ độ


@dataclass(frozen=True)
class CrossCase:
    name: str
    build: Callable[[VerificationEnv], None]
    expected_primary: str
    expected_secondary: tuple[str, ...]
    forbidden_matches: tuple[str, ...] = ()  # detector KHÔNG được khớp ở bất kỳ lần thử nào của ca này


CASES: tuple[CrossCase, ...] = (
    CrossCase("distributed_bruteforce + brute_force + scripted_client", distributed_with_brute_force_and_scripted_ua, "distributed_bruteforce", ("brute_force", "scripted_client")),
    CrossCase("credential_stuffing + username_enumeration", stuffing_with_enumeration, "credential_stuffing", ("username_enumeration",)),
    CrossCase("password_spray_slow + scripted_client", spray_with_scripted_client, "password_spray_slow", ("scripted_client",)),
    CrossCase("brute_force + bot_user_agent", brute_force_with_bot_ua, "brute_force", ("bot_user_agent",)),
    CrossCase("ua_rotation + credential_stuffing", ua_rotation_with_stuffing, "credential_stuffing", ("ua_rotation",)),
    CrossCase("unusual_device + impossible_travel", unusual_device_with_impossible_travel, "impossible_travel", ("unusual_device",)),
    # lộ ra ở regression Milestone B: "công cụ kịch bản" giải thích thiết bị lạ cụ thể hơn "thiết bị lần đầu thấy"
    CrossCase("unusual_device + scripted_client", unusual_device_with_scripted_client, "scripted_client", ("unusual_device",)),
    # --- Milestone C (C8)
    CrossCase("unusual_location + impossible_travel", unusual_location_with_impossible_travel, "impossible_travel", ("unusual_location",)),
    CrossCase("unusual_location + unusual_device", unusual_location_with_unusual_device, "unusual_location", ("unusual_device",)),
    # unusual_hour chưa VERIFIED (PARTIAL, experimental) nên không tự dẫn cảnh báo — vẫn phải có mặt trong tín hiệu phụ
    CrossCase("unusual_hour + unusual_device", unusual_hour_with_unusual_device, "unusual_device", ("unusual_hour",)),
    # --- Milestone C.1: unusual_hour vẫn PARTIAL (experimental) -> địa điểm làm detector chính, giờ phải còn trong tín hiệu phụ
    CrossCase("unusual_hour + unusual_location", unusual_hour_with_unusual_location, "unusual_location", ("unusual_hour",)),
    CrossCase("login_velocity_spike + scripted_client", velocity_with_scripted_client, "login_velocity_spike", ("scripted_client",)),
    CrossCase("rapid failed logins -> brute_force, not login_velocity_spike", rapid_failures_are_brute_force_not_velocity, "brute_force", (), ("login_velocity_spike",)),
    # --- Milestone C+
    CrossCase("regular_rhythm + scripted_client", rhythm_with_scripted_client, "regular_rhythm", ("scripted_client",)),
    CrossCase("brute_force + regular_rhythm", brute_force_with_regular_rhythm, "brute_force", ("regular_rhythm",)),
    CrossCase("rare_network_login + unusual_location", rare_network_with_unusual_location, "rare_network_login", ("unusual_location",)),
    CrossCase("rare_network_login + unusual_device", rare_network_with_unusual_device, "rare_network_login", ("unusual_device",)),
    CrossCase("impossible_travel + multi_context_simultaneous", multi_context_with_impossible_travel, "impossible_travel", ("multi_context_simultaneous",)),
    CrossCase("multi_context_simultaneous + unusual_location (thiếu toạ độ)", multi_context_with_unusual_location, "multi_context_simultaneous", ("unusual_location",)),
)


def evaluate(case: CrossCase, env: VerificationEnv) -> dict:
    case.build(env)
    alerts = env.detection_alerts()
    primary = [a for a in alerts if a.rule_id == case.expected_primary]
    # bằng chứng của detector kia KHÔNG mất: nằm trong tín hiệu phụ, hoặc trong `superseded_detectors` khi nó khớp TRƯỚC rồi bị
    # detector đặc hiệu hơn tiếp quản chính cảnh báo đó (gộp chiến dịch — consolidation.py)
    exp = (primary[0].explanation or {}) if primary else {}
    secondary = set(exp.get("secondary_signals", [])) | set(exp.get("superseded_detectors", []))
    missing = [s for s in case.expected_secondary if s not in secondary]
    forbidden = sorted({r for v in env.verdicts for r in v.matched_rules if r in case.forbidden_matches})
    return {
        "case": case.name, "expected_primary": case.expected_primary, "expected_secondary": list(case.expected_secondary),
        "detection_alerts": [a.rule_id for a in alerts], "secondary_signals": sorted(exp.get("secondary_signals", [])), "missing_secondary": missing,
        "superseded_detectors": exp.get("superseded_detectors", []),
        "forbidden_matched": forbidden,
        "passed": len(alerts) == 1 and bool(primary) and not missing and not forbidden,
    }
