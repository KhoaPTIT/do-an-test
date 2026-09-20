"""Fingerprint thiết bị đơn giản (dùng ở nhiệm vụ 4.1) + phân tích User-Agent
(giai đoạn mở rộng MR1).

⚠️ Giả định — checklist không nói rõ cách tính fingerprint. Dự án không
triển khai fingerprint phía client (canvas/WebGL...) vì web app mẫu không
yêu cầu, nên dùng hash của User-Agent làm fingerprint xấp xỉ. Đủ để phân
biệt "thiết bị/trình duyệt mới" ở mức cơ bản — không chính xác bằng
fingerprint thật (2 người dùng cùng loại máy + cùng trình duyệt sẽ trùng
fingerprint).

parse_user_agent() tách UA thành trình duyệt / hệ điều hành / loại thiết bị
với cùng bộ giá trị loại thiết bị như bộ dữ liệu RBA (mobile, desktop,
tablet, bot, unknown) — để đặc trưng huấn luyện trên RBA và đặc trưng tính
từ luồng đăng nhập thật có cùng ý nghĩa.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from functools import lru_cache

from user_agents import parse as _parse_ua


def compute_device_fingerprint(user_agent: str | None) -> str | None:
    if not user_agent:
        return None
    return hashlib.sha256(user_agent.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class ParsedUserAgent:
    browser: str | None
    browser_version: str | None
    os: str | None
    os_version: str | None
    device_type: str  # mobile | desktop | tablet | bot | unknown


_UNKNOWN_UA = ParsedUserAgent(None, None, None, None, "unknown")


def _clean(value: str | None) -> str | None:
    if not value or value == "Other":
        return None
    return value


@lru_cache(maxsize=4096)
def parse_user_agent(user_agent: str | None) -> ParsedUserAgent:
    if not user_agent:
        return _UNKNOWN_UA

    ua = _parse_ua(user_agent)
    if ua.is_bot:
        device_type = "bot"
    elif ua.is_tablet:
        device_type = "tablet"
    elif ua.is_mobile:
        device_type = "mobile"
    elif ua.is_pc:
        device_type = "desktop"
    else:
        device_type = "unknown"

    return ParsedUserAgent(
        browser=_clean(ua.browser.family),
        browser_version=ua.browser.version_string or None,
        os=_clean(ua.os.family),
        os_version=ua.os.version_string or None,
        device_type=device_type,
    )
