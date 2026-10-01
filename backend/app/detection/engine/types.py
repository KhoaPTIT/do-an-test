"""Kiểu dữ liệu dùng chung của rule engine v2 (MR9).

Mọi luật chỉ nhìn thấy `LoginAttempt` (một lần thử đăng nhập đã chuẩn hoá) và `AccountHistory` (quá khứ của tài khoản); không luật nào
biết dữ liệu đến từ luồng /login thật, từ log lịch sử hay từ bộ dữ liệu RBA. Nhờ đó cùng một bộ luật chạy được ở cả ba nơi (bộ replay
ở replay.py) và test bằng dữ liệu tổng hợp nhỏ.

THỜI GIAN LÀ THỜI GIAN CỦA SỰ KIỆN (`LoginAttempt.ts`), không phải giờ hệ thống: replay log năm 2020 phải cho kết quả như lúc log được ghi.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from functools import cached_property
from typing import Any, Mapping

SEVERITIES = ("low", "medium", "high")
MODES = ("enforce", "shadow", "off")
DEVICE_TYPES = ("mobile", "desktop", "tablet", "bot", "unknown")


def ua_hash(user_agent: str | None) -> str:
    """Dấu vân tay ngắn (12 ký tự hex) của một chuỗi User-Agent, rỗng nếu thiếu — hàm dùng chung để `LoginAttempt.ua_hash`
    và mã dựng lịch sử tài khoản từ DB (MR12: `app/detection/rule_engine_runtime.py`) luôn tính RA CÙNG GIÁ TRỊ cho cùng
    một UA (so khớp `AccountHistory.known_devices` được, dù một bên tính từ `LoginAttempt`, một bên từ hàng DB thô)."""
    return hashlib.sha1(user_agent.encode("utf-8")).hexdigest()[:12] if user_agent else ""


def device_family_of(user_agent: str | None, device_type: str | None, os: str | None, browser: str | None) -> str:
    """Khoá họ thiết bị dùng chung cho `LoginAttempt` và lịch sử dựng từ DB (cùng `parse_user_agent`). Không nhận ra cả HĐH
    lẫn trình duyệt thì không chuẩn hoá được: dùng chính chuỗi UA (băm) làm họ riêng. Rỗng nếu không có UA."""
    if not user_agent:
        return ""
    if not os and not browser:
        return f"raw:{ua_hash(user_agent)}"
    return f"{device_type or 'unknown'}|{os or '?'}|{browser or '?'}"


@dataclass(frozen=True)
class LoginAttempt:
    """MỘT lần thử đăng nhập — đầu vào duy nhất của mọi luật."""

    ts: float  # epoch giây của SỰ KIỆN
    username: str  # tên đăng nhập người dùng gõ (kể cả tên không tồn tại)
    success: bool
    ip: str
    user_key: str | None = None  # định danh tài khoản khi tài khoản TỒN TẠI; None nếu tên không tồn tại
    asn: int | None = None
    country: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    user_agent: str | None = None
    browser: str | None = None
    os: str | None = None
    device_type: str | None = None  # mobile | desktop | tablet | bot | unknown
    # Nhãn chỉ có ở replay (ví dụ RBA: is_attack_ip, is_ato). KHÔNG được luật nào đọc — tests/test_rule_engine.py kiểm tra bằng cách đổi nhãn.
    labels: Mapping[str, bool] = field(default_factory=dict, compare=False, repr=False)

    @property
    def user_exists(self) -> bool:
        return self.user_key is not None

    @cached_property
    def ua_hash(self) -> str:
        """Dấu vân tay ngắn của chuỗi User-Agent (rỗng nếu thiếu UA) — dùng để đếm UA khác nhau. Tính một lần cho mỗi lần thử."""
        return ua_hash(self.user_agent)

    @property
    def device_family(self) -> str:
        """Định danh thiết bị CHUẨN HOÁ (loại thiết bị | hệ điều hành | trình duyệt), BỎ phiên bản: Chrome 120 và Chrome 121
        trên cùng Windows là CÙNG một họ. Rỗng nếu không có User-Agent (xem `device_family_of`)."""
        return device_family_of(self.user_agent, self.device_type, self.os, self.browser)

    @property
    def has_geo(self) -> bool:
        return self.latitude is not None and self.longitude is not None

    @classmethod
    def from_request(
        cls,
        *,
        username: str,
        user_id: int | None,
        success: bool,
        ip: str,
        user_agent: str | None,
        timestamp: datetime,
        geo: Any = None,
        asn: int | None = None,
        labels: Mapping[str, bool] | None = None,
    ) -> "LoginAttempt":
        """Dựng từ dữ liệu của luồng /login (cùng tham số `run_detection_pipeline`); `geo` là `GeoResult` hoặc None. Phân tích UA bằng
        `parse_user_agent` để loại thiết bị cùng bộ giá trị với RBA. `labels` chỉ dành cho replay."""
        from app.utils.device import parse_user_agent

        parsed = parse_user_agent(user_agent)
        return cls(
            ts=timestamp.timestamp(),
            username=username,
            success=success,
            ip=ip,
            user_key=None if user_id is None else str(user_id),
            asn=asn,
            country=getattr(geo, "country", None),
            city=getattr(geo, "city", None),
            latitude=getattr(geo, "latitude", None),
            longitude=getattr(geo, "longitude", None),
            user_agent=user_agent,
            browser=parsed.browser,
            os=parsed.os,
            device_type=parsed.device_type,
            labels=dict(labels) if labels else {},
        )


@dataclass(slots=True)  # slots: replay giữ hàng triệu tài khoản, bỏ `__dict__` từng đối tượng tiết kiệm hàng trăm MB
class AccountHistory:
    """Quá khứ của một tài khoản mà luật cần: dựng từ DB ở luồng thật, từ luồng sự kiện đã phát ở replay."""

    last_event_ts: float | None = None  # lần thử gần nhất (mọi kết quả) — cho impossible travel
    last_event_lat: float | None = None
    last_event_lon: float | None = None
    last_success_ts: float | None = None  # lần THÀNH CÔNG gần nhất — cho tài khoản ngủ đông
    # Toạ độ của lần THÀNH CÔNG gần nhất — cho impossible travel (Phase 3: chỉ tính THÀNH CÔNG → THÀNH CÔNG; một lần
    # thử sai từ nơi xa không chứng minh chủ tài khoản đã ở đó). Để CUỐI lớp: không đổi thứ tự các trường sẵn có.
    last_success_lat: float | None = None
    last_success_lon: float | None = None
    # Hồ sơ hành vi (Milestone B, `unusual_device`): lần thành công ĐẦU TIÊN và các HỌ thiết bị chuẩn hoá đã từng đăng
    # nhập thành công (`device_family_of` — bỏ phiên bản trình duyệt), kèm thời điểm thấy lần đầu của từng họ.
    first_success_ts: float | None = None
    known_device_families: tuple[str, ...] = ()
    device_family_first_seen: tuple[float, ...] = ()  # song song với known_device_families
    n_success: int = 0
    # Hai tập nhỏ của MỘT tài khoản, chỉ dùng phép `in`: tuple nhẹ hơn frozenset ~4 lần khi có hàng triệu tài khoản (replay giai đoạn train RBA có 2,5 triệu).
    known_countries: tuple[str, ...] = ()  # quốc gia đã từng đăng nhập thành công
    known_devices: tuple[str, ...] = ()  # `ua_hash` đã từng đăng nhập thành công


@dataclass(frozen=True)
class Finding:
    """Kết quả thô của MỘT luật khi khớp; engine gắn thêm id, mức nghiêm trọng mặc định, ánh xạ MITRE và chế độ."""

    message: str  # câu ngắn tiếng Việt, cùng phong cách chuỗi cảnh báo hiện có
    evidence: Mapping[str, Any] = field(default_factory=dict)
    severity: str | None = None  # None = dùng mức mặc định của luật


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    severity: str
    message: str
    evidence: Mapping[str, Any]
    mode: str  # enforce (tạo cảnh báo) | shadow (chỉ ghi nhận, không tạo cảnh báo)
    techniques: tuple[str, ...]

    @property
    def is_shadow(self) -> bool:
        return self.mode == "shadow"


@dataclass
class Evaluation:
    """Kết quả chấm MỘT lần thử: các luật khớp, luật bị bỏ qua vì thiếu dữ liệu (kèm lý do) và luật lỗi (không bao giờ làm sập luồng đăng nhập)."""

    hits: list[RuleHit] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    elapsed_ms: float = 0.0

    @property
    def enforced(self) -> list[RuleHit]:
        return [h for h in self.hits if not h.is_shadow]

    @property
    def shadowed(self) -> list[RuleHit]:
        return [h for h in self.hits if h.is_shadow]

    def by_rule(self) -> dict[str, RuleHit]:
        return {h.rule_id: h for h in self.hits}
