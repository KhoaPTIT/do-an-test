"""Đặc trưng v2 (MR3) — ĐẶC TẢ bằng Python thuần.

Đây là định nghĩa gốc của mọi đặc trưng. Hai nơi dùng nó:
  - luồng realtime (MR12): dựng `HistorySummary` từ DB rồi gọi `features_from_summary`;
  - kiểm chứng: `features_sql.py` tính cùng các đặc trưng bằng DuckDB trên toàn bộ dữ liệu
    (nhanh gấp hàng nghìn lần) và test chứng minh hai bên cho kết quả bằng nhau.

Quy ước "trước đó" (chống rò rỉ): chỉ sự kiện có `ts_us` NHỎ HƠN HẲN sự kiện hiện tại mới được
tính (sự kiện cùng micro-giây loại trừ lẫn nhau). Cửa sổ thời gian là (t - W, t), mở ở đầu cũ.
Đặc trưng không bao giờ dùng nhãn (`Is Attack IP`, `Is Account Takeover`).

Tài khoản không tồn tại (`user_id = None`; trong RBA là "thùng chứa" -4324475583306591935):
đặc trưng theo user = NaN, đặc trưng cấp IP/ASN và độ hiếm toàn cục vẫn tính.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Sequence

US_PER_SECOND = 1_000_000
W_1H = 3_600 * US_PER_SECOND
W_24H = 24 * W_1H
W_7D = 7 * W_24H
DAY_US = W_24H

ALPHA = 1.0  # độ mạnh của prior toàn cục khi làm mịn p_user (Freeman)
NULL_KEY = "∅"  # giá trị thay cho thiếu dữ liệu khi so sánh/đếm
RBA_CATCHALL_USER_ID = -4324475583306591935  # "thùng chứa" tài khoản không tồn tại trong RBA

NOVELTY_ATTRS = ("country", "asn", "ip", "ua", "browser", "os", "device", "browser_family", "os_family")
FREEMAN_ATTRS = ("ip", "country", "asn", "ua", "browser", "os", "device")

DEVICE_CODES = {"mobile": 0, "desktop": 1, "tablet": 2, "bot": 3, "unknown": 4}
DEVICE_CODE_MISSING = 5

_VERSION_SUFFIX = re.compile(r" +[0-9][0-9.]*$")

FEATURE_GROUPS: dict[str, list[str]] = {
    "cur": ["cur_success", "cur_device_code"],
    "novelty": [f"new_{a}" for a in NOVELTY_ATTRS],
    "history": ["u_n_attempts", "u_n_success", "u_age_days"],
    "rhythm": [
        "u_secs_since_last", "u_secs_since_last_success", "u_fail_streak", "u_attempts_1h",
        "u_attempts_24h", "u_fails_24h", "u_distinct_ips_24h", "u_distinct_countries_7d",
    ],
    "freeman": [f"llr_{a}" for a in FREEMAN_ATTRS] + ["llr_sum"],
    "rarity": [f"rare_{a}" for a in FREEMAN_ATTRS],
    "infra_ip": [
        "ip_attempts_1h", "ip_attempts_24h", "ip_fail_ratio_24h", "ip_distinct_users_24h",
        "ip_unknown_attempts_24h", "ip_distinct_ua_24h", "ip_prior_attempts_all",
    ],
    "infra_asn": [
        "asn_attempts_1h", "asn_attempts_24h", "asn_fail_ratio_24h", "asn_distinct_users_24h",
        "asn_distinct_ips_24h", "asn_unknown_share_24h",
    ],
}
FEATURE_NAMES: list[str] = [name for names in FEATURE_GROUPS.values() for name in names]
FEATURE_VERSION = "v2"


def feature_signature() -> str:
    """Dấu vân tay của danh sách + thứ tự đặc trưng: đổi tên/thêm/bớt/đổi thứ tự thì đổi. Mô hình và bảng "thường thấy"
    lưu chữ ký lúc huấn luyện để phát hiện lệch phiên bản đặc trưng khi nạp."""
    return hashlib.sha1(",".join(FEATURE_NAMES).encode("utf-8")).hexdigest()[:12]


def strip_version(name: str) -> str:
    """'Chrome Mobile 46.0.2490' -> 'Chrome Mobile'. Không có hậu tố phiên bản thì giữ nguyên."""
    return _VERSION_SUFFIX.sub("", name)


@dataclass(frozen=True)
class EventRecord:
    ts_us: int
    user_id: int | None
    ip: str
    asn: int | None
    country: str | None
    ua: str | None
    browser: str | None
    os: str | None
    device_type: str | None
    success: bool


def attr_key(event: EventRecord, attr: str) -> str:
    """Giá trị so sánh của một thuộc tính (thiếu dữ liệu -> NULL_KEY)."""
    if attr == "ip":
        return event.ip
    if attr == "asn":
        return NULL_KEY if event.asn is None else str(event.asn)
    if attr == "browser_family":
        return strip_version(event.browser if event.browser is not None else NULL_KEY)
    if attr == "os_family":
        return strip_version(event.os if event.os is not None else NULL_KEY)
    value = {
        "country": event.country, "ua": event.ua, "browser": event.browser, "os": event.os,
        "device": event.device_type,
    }[attr]
    return NULL_KEY if value is None else value


@dataclass
class GlobalCounts:
    """Đếm toàn cục các lần đăng nhập THÀNH CÔNG của tài khoản thật đã xảy ra trước đó."""

    total: int = 0
    by_attr: dict[str, Counter] = field(default_factory=lambda: {a: Counter() for a in FREEMAN_ATTRS})

    @classmethod
    def from_events(cls, events: Iterable[EventRecord]) -> "GlobalCounts":
        counts = cls()
        for e in events:
            counts.total += 1
            for a in FREEMAN_ATTRS:
                counts.by_attr[a][attr_key(e, a)] += 1
        return counts


@dataclass
class HistorySummary:
    """Mọi thứ cần biết về quá khứ để tính đặc trưng của một sự kiện (đều strictly trước sự kiện)."""

    user_events: list[EventRecord] | None  # cùng tài khoản, toàn bộ lịch sử (None nếu tài khoản không tồn tại)
    ip_events: list[EventRecord]  # cùng IP, trong 24h gần nhất
    ip_prior_attempts_all: int  # cùng IP, mọi thời điểm
    asn_events: list[EventRecord]  # cùng ASN, trong 24h gần nhất (rỗng nếu ASN không rõ)
    global_counts: GlobalCounts


def summarize_history(event: EventRecord, prior: Sequence[EventRecord]) -> HistorySummary:
    """Dựng HistorySummary bằng cách lọc thô toàn bộ sự kiện trước đó (chậm, chính xác — dùng cho test)."""
    t = event.ts_us
    before = [e for e in prior if e.ts_us < t]
    user_events = None
    if event.user_id is not None:
        user_events = [e for e in before if e.user_id == event.user_id]
    same_ip = [e for e in before if e.ip == event.ip]
    asn_events = [] if event.asn is None else [e for e in before if e.asn == event.asn and e.ts_us > t - W_24H]
    return HistorySummary(
        user_events=user_events,
        ip_events=[e for e in same_ip if e.ts_us > t - W_24H],
        ip_prior_attempts_all=len(same_ip),
        asn_events=asn_events,
        global_counts=GlobalCounts.from_events(e for e in before if e.success and e.user_id is not None),
    )


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator > 0 else math.nan


def features_from_summary(event: EventRecord, summary: HistorySummary) -> dict[str, float]:
    t = event.ts_us
    nan = math.nan
    f: dict[str, float] = {name: nan for name in FEATURE_NAMES}

    f["cur_success"] = 1.0 if event.success else 0.0
    f["cur_device_code"] = float(DEVICE_CODES.get(event.device_type, DEVICE_CODE_MISSING))

    gc = summary.global_counts
    p_global = {a: (gc.by_attr[a][attr_key(event, a)] + 1.0) / (gc.total + 1.0) for a in FREEMAN_ATTRS}
    for a in FREEMAN_ATTRS:
        f[f"rare_{a}"] = -math.log(p_global[a])

    ue = summary.user_events
    if ue is not None:
        successes = [e for e in ue if e.success]
        n_success = len(successes)
        f["u_n_attempts"] = float(len(ue))
        f["u_n_success"] = float(n_success)

        for a in NOVELTY_ATTRS:
            key = attr_key(event, a)
            seen = sum(1 for e in successes if attr_key(e, a) == key)
            f[f"new_{a}"] = 1.0 if seen == 0 else 0.0

        llr_total = 0.0
        for a in FREEMAN_ATTRS:
            key = attr_key(event, a)
            seen = sum(1 for e in successes if attr_key(e, a) == key)
            p_user = (seen + ALPHA * p_global[a]) / (n_success + ALPHA)
            llr = math.log(p_global[a]) - math.log(p_user)
            f[f"llr_{a}"] = llr
            llr_total += llr
        f["llr_sum"] = llr_total

        if ue:
            f["u_age_days"] = (t - min(e.ts_us for e in ue)) / DAY_US
            f["u_secs_since_last"] = (t - max(e.ts_us for e in ue)) / US_PER_SECOND
        if successes:
            last_success_ts = max(e.ts_us for e in successes)
            f["u_secs_since_last_success"] = (t - last_success_ts) / US_PER_SECOND
            f["u_fail_streak"] = float(sum(1 for e in ue if e.ts_us > last_success_ts))
        else:
            f["u_fail_streak"] = float(len(ue))

        f["u_attempts_1h"] = float(sum(1 for e in ue if e.ts_us > t - W_1H))
        in_24h = [e for e in ue if e.ts_us > t - W_24H]
        f["u_attempts_24h"] = float(len(in_24h))
        f["u_fails_24h"] = float(sum(1 for e in in_24h if not e.success))
        f["u_distinct_ips_24h"] = float(len({e.ip for e in in_24h}))
        f["u_distinct_countries_7d"] = float(len({attr_key(e, "country") for e in ue if e.ts_us > t - W_7D}))

    ie = summary.ip_events
    f["ip_attempts_24h"] = float(len(ie))
    f["ip_attempts_1h"] = float(sum(1 for e in ie if e.ts_us > t - W_1H))
    f["ip_fail_ratio_24h"] = _ratio(sum(1 for e in ie if not e.success), len(ie))
    f["ip_distinct_users_24h"] = float(len({e.user_id for e in ie if e.user_id is not None}))
    f["ip_unknown_attempts_24h"] = float(sum(1 for e in ie if e.user_id is None))
    f["ip_distinct_ua_24h"] = float(len({attr_key(e, "ua") for e in ie}))
    f["ip_prior_attempts_all"] = float(summary.ip_prior_attempts_all)

    if event.asn is not None:
        ae = summary.asn_events
        f["asn_attempts_24h"] = float(len(ae))
        f["asn_attempts_1h"] = float(sum(1 for e in ae if e.ts_us > t - W_1H))
        f["asn_fail_ratio_24h"] = _ratio(sum(1 for e in ae if not e.success), len(ae))
        f["asn_distinct_users_24h"] = float(len({e.user_id for e in ae if e.user_id is not None}))
        f["asn_distinct_ips_24h"] = float(len({e.ip for e in ae}))
        f["asn_unknown_share_24h"] = _ratio(sum(1 for e in ae if e.user_id is None), len(ae))

    return f


def compute_features_spec(event: EventRecord, prior: Sequence[EventRecord]) -> dict[str, float]:
    return features_from_summary(event, summarize_history(event, prior))
