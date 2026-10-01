"""Fixture của bộ test hành vi (Phase 3): mỗi test một `VerificationEnv` riêng (SQLite in-memory + fakeredis + GeoIP/
threat intel TEST FIXTURE), vá trạng thái module qua `monkeypatch` nên tự hoàn tác sau test.

Fixture chỉ cung cấp TELEMETRY (vị trí, ASN, danh sách danh tiếng, lịch sử đăng nhập) — không truyền nhãn tấn công nào
cho detector."""

from datetime import datetime, timedelta, timezone

import pytest

from verification.harness import CHROME_UA, VerificationEnv

T0 = datetime(2026, 3, 2, 9, 0, 0, tzinfo=timezone.utc)  # mốc "bây giờ" của mọi kịch bản test
HOME_IP = "192.0.2.10"  # FIXTURE: VN/Hanoi, ASN 64512 (nhà)
MOBILE_IP = "192.0.2.70"  # FIXTURE: VN/Hanoi, ASN 64513 (di động)
HCM_IP = "192.0.2.140"  # FIXTURE: VN/Ho Chi Minh City
HAIPHONG_IP = "192.0.2.170"  # FIXTURE: VN/Hai Phong (~100km từ Hà Nội)
OFFICE_NAT_IP = "192.0.2.230"  # FIXTURE: VN/Hanoi, NAT văn phòng
US_IP = "198.51.100.200"  # FIXTURE: US/New York
JP_IP = "203.0.113.10"  # FIXTURE: JP/Tokyo
FR_IP = "203.0.113.70"  # FIXTURE: FR/Paris
BR_IP = "203.0.113.140"  # FIXTURE: BR/Sao Paulo
TOR_IP = "198.51.100.7"  # FIXTURE: nằm trong tor_exit_ips.txt của fixture
TOR_NEIGHBOUR_IP = "198.51.100.50"  # FIXTURE: CÙNG ASN/dải với exit node nhưng KHÔNG nằm trong danh sách


@pytest.fixture()
def env(monkeypatch):
    return VerificationEnv(setattr_fn=monkeypatch.setattr)


def seed_user(env: VerificationEnv, username: str, *, days: int = 10, ip: str = HOME_IP, user_agent: str = CHROME_UA, end: datetime = T0) -> int:
    """Tạo tài khoản + `days` lần đăng nhập THÀNH CÔNG bình thường (mỗi ngày một lần, 9h) kết thúc trước `end`."""
    user_id = env.add_user(username)
    for d in range(days, 0, -1):
        env.add_history(username, ip=ip, ts=end - timedelta(days=d), user_agent=user_agent)
    return user_id


@pytest.fixture()
def as_candidate(monkeypatch):
    """Chạy một detector ỨNG VIÊN ở trạng thái như SAU khi được nâng cấp (enforce + verified) — cùng cơ chế
    `scripts/behavior_verification.py --candidates`, chỉ trong test (monkeypatch tự hoàn tác). Với luật đã `verified`
    trong registry thì không đổi gì."""
    import dataclasses

    from app.detection.engine.registry import REGISTRY

    def promote(*rule_ids: str) -> None:
        for rule_id in rule_ids:
            monkeypatch.setitem(REGISTRY, rule_id, dataclasses.replace(REGISTRY[rule_id], verification="verified", default_mode="enforce"))

    return promote
