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


@dataclass(frozen=True)
class CrossCase:
    name: str
    build: Callable[[VerificationEnv], None]
    expected_primary: str
    expected_secondary: tuple[str, ...]


CASES: tuple[CrossCase, ...] = (
    CrossCase("distributed_bruteforce + brute_force + scripted_client", distributed_with_brute_force_and_scripted_ua, "distributed_bruteforce", ("brute_force", "scripted_client")),
    CrossCase("credential_stuffing + username_enumeration", stuffing_with_enumeration, "credential_stuffing", ("username_enumeration",)),
    CrossCase("password_spray_slow + scripted_client", spray_with_scripted_client, "password_spray_slow", ("scripted_client",)),
    CrossCase("brute_force + bot_user_agent", brute_force_with_bot_ua, "brute_force", ("bot_user_agent",)),
    CrossCase("ua_rotation + credential_stuffing", ua_rotation_with_stuffing, "credential_stuffing", ("ua_rotation",)),
    CrossCase("unusual_device + impossible_travel", unusual_device_with_impossible_travel, "impossible_travel", ("unusual_device",)),
    # lộ ra ở regression Milestone B: "công cụ kịch bản" giải thích thiết bị lạ cụ thể hơn "thiết bị lần đầu thấy"
    CrossCase("unusual_device + scripted_client", unusual_device_with_scripted_client, "scripted_client", ("unusual_device",)),
)


def evaluate(case: CrossCase, env: VerificationEnv) -> dict:
    case.build(env)
    alerts = env.detection_alerts()
    primary = [a for a in alerts if a.rule_id == case.expected_primary]
    secondary = set((primary[0].explanation or {}).get("secondary_signals", [])) if primary else set()
    missing = [s for s in case.expected_secondary if s not in secondary]
    return {
        "case": case.name, "expected_primary": case.expected_primary, "expected_secondary": list(case.expected_secondary),
        "detection_alerts": [a.rule_id for a in alerts], "secondary_signals": sorted(secondary), "missing_secondary": missing,
        "superseded_detectors": (primary[0].explanation or {}).get("superseded_detectors", []) if primary else [],
        "passed": len(alerts) == 1 and bool(primary) and not missing,
    }
