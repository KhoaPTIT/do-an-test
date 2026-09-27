"""Đặc trưng RBA (MR3: `ml/rba/features.py`) tính từ DB thật cho luồng /login (MR12).

`ml/rba/features.py` là ĐẶC TẢ thuần Python của 50 đặc trưng, đã viết sẵn để dùng ở đây (`HistorySummary` + `features_from_summary`)
— việc còn lại của module này CHỈ là dựng `HistorySummary` bằng truy vấn DB thay vì lọc một danh sách `EventRecord` có sẵn
trong bộ nhớ (`summarize_history`, dùng cho test/kiểm chứng, không dùng ở đây vì phải quét toàn bộ lịch sử mỗi lần).

Bốn truy vấn nhắm đúng phạm vi (không quét toàn bảng), cùng quy ước "chỉ tính sự kiện TRƯỚC lần thử hiện tại" như MR3:
  1. `user_events`  — toàn bộ lịch sử của TÀI KHOẢN (dùng chỉ mục `ix_login_events_user_created`); None nếu tài khoản không tồn tại.
  2. `ip_events`    — cùng IP trong 24 giờ gần nhất (dùng chỉ mục `ix_login_events_ip_address`).
  3. `asn_events`   — cùng ASN trong 24 giờ gần nhất (dùng chỉ mục `ix_login_events_asn`); rỗng nếu ASN không rõ.
  4. `global_counts` — đếm toàn cục theo TỪNG THUỘC TÍNH (ip/country/asn/ua/browser/os/device) của MỌI đăng nhập THÀNH CÔNG,
     tài khoản có thật, trên TOÀN BẢNG — không nhắm được vào một chỉ mục hẹp. Cache TTL ngắn (`GlobalCountsCache`) để một
     đợt đăng nhập dồn dập không quét lại bảng cho mỗi lần; xem giới hạn ở docstring của lớp đó.

⚠️ Giả định luồng THẬT: lần thử được chấm gần như ngay khi xảy ra (cache "trước sự kiện" ≈ "trước hiện tại"). KHÔNG dùng
module này để chấm lại log cũ hàng loạt — việc đó là của `backend/ml/rba/rule_replay.py` (đọc thẳng từ RBA, không qua DB).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import LoginEvent
from app.utils.time import ensure_utc
from ml.rba.features import US_PER_SECOND, EventRecord, GlobalCounts, HistorySummary, features_from_summary

logger = logging.getLogger("rba_live_features")

WINDOW_24H = timedelta(hours=24)
GLOBAL_COUNTS_CACHE_TTL_SECONDS = 30.0  # xem giới hạn ở GlobalCountsCache


def to_us(moment: datetime) -> int:
    return int(ensure_utc(moment).timestamp() * US_PER_SECOND)


def _event_record(row, *, ts_us: int | None = None) -> EventRecord:
    """`row` là một hàng đã SELECT các cột cần (không phải ORM `LoginEvent` đầy đủ, xem `_COLUMNS`) hoặc chính `LoginEvent`."""
    return EventRecord(
        ts_us=ts_us if ts_us is not None else to_us(row.created_at), user_id=row.user_id, ip=row.ip_address, asn=row.asn,
        country=row.country, ua=row.user_agent, browser=row.browser_name, os=row.os_name, device_type=row.device_type,
        success=row.success,
    )


_COLUMNS = (
    LoginEvent.user_id, LoginEvent.ip_address, LoginEvent.asn, LoginEvent.country, LoginEvent.user_agent,
    LoginEvent.browser_name, LoginEvent.os_name, LoginEvent.device_type, LoginEvent.success, LoginEvent.created_at,
)


def event_record_for(event: LoginEvent) -> EventRecord:
    """`EventRecord` của chính lần thử đang chấm (đã `db.flush()`, có `created_at`)."""
    return _event_record(event)


def _user_events(db: Session, user_id: int, before: datetime) -> list[EventRecord]:
    rows = db.execute(select(*_COLUMNS).where(LoginEvent.user_id == user_id, LoginEvent.created_at < before).order_by(LoginEvent.created_at)).all()
    return [_event_record(r) for r in rows]


def _ip_events(db: Session, ip: str, before: datetime) -> list[EventRecord]:
    rows = db.execute(
        select(*_COLUMNS).where(LoginEvent.ip_address == ip, LoginEvent.created_at < before, LoginEvent.created_at > before - WINDOW_24H)
    ).all()
    return [_event_record(r) for r in rows]


def _ip_prior_attempts_all(db: Session, ip: str, before: datetime) -> int:
    return db.execute(select(func.count()).select_from(LoginEvent).where(LoginEvent.ip_address == ip, LoginEvent.created_at < before)).scalar_one()


def _asn_events(db: Session, asn: int, before: datetime) -> list[EventRecord]:
    rows = db.execute(
        select(*_COLUMNS).where(LoginEvent.asn == asn, LoginEvent.created_at < before, LoginEvent.created_at > before - WINDOW_24H)
    ).all()
    return [_event_record(r) for r in rows]


@dataclass
class GlobalCountsCache:
    """`GlobalCounts` (MR3) của MỌI đăng nhập thành công, tài khoản có thật, TOÀN BẢNG — không nhắm được vào một chỉ mục
    hẹp nên cache lại (khoá theo `before`, xem `get`) thay vì quét cho mỗi lần đăng nhập.

    ⚠️ Giới hạn: (1) một snapshot cache có thể THIẾU vài dòng rất mới (giữa lúc cache được tính và `before` đang hỏi,
    tối đa `ttl_seconds`) — chấp nhận được cho luồng thật (chỉ ảnh hưởng độ hiếm/LLR lệch rất nhỏ); (2) KHÔNG BAO GIỜ
    THỪA — snapshot tính với mốc `before` cũ hơn hoặc bằng mốc đang hỏi nên không thể chứa chính dòng đang được chấm
    (điều kiện `_cutoff <= before` ở `get`); (3) quét toàn bảng — với bảng lớn cần thay bằng bộ đếm tăng dần lưu riêng
    (ngoài phạm vi MR12, demo hiện có vài nghìn dòng, đủ nhanh: đo ở `docs/realtime-integration.md`)."""

    ttl_seconds: float = GLOBAL_COUNTS_CACHE_TTL_SECONDS
    _cached: GlobalCounts | None = None
    _cutoff: datetime | None = None  # mốc "trước" mà `_cached` đã tính (đã loại mọi dòng có created_at >= mốc này)

    def get(self, db: Session, before: datetime) -> GlobalCounts:
        """`GlobalCounts` của mọi dòng có `created_at < before`. Dùng lại cache nếu mốc đã cache (`_cutoff`) KHÔNG SAU
        `before` (an toàn tuyệt đối: không thể lẫn dòng đang được chấm hoặc dòng SAU nó) và còn trong `ttl_seconds`."""
        if self._cached is not None and self._cutoff is not None and self._cutoff <= before and (before - self._cutoff).total_seconds() <= self.ttl_seconds:
            return self._cached
        self._cached = self._compute(db, before)
        self._cutoff = before
        return self._cached

    def invalidate(self) -> None:
        self._cached = None
        self._cutoff = None

    @staticmethod
    def _compute(db: Session, before: datetime) -> GlobalCounts:
        rows = db.execute(select(*_COLUMNS).where(LoginEvent.success.is_(True), LoginEvent.user_id.isnot(None), LoginEvent.created_at < before)).all()
        return GlobalCounts.from_events(_event_record(r) for r in rows)


_global_counts_cache = GlobalCountsCache()


def build_history_summary(db: Session, event: EventRecord, *, cache: GlobalCountsCache | None = None) -> HistorySummary:
    """`HistorySummary` cho `event` — bốn truy vấn mô tả ở docstring module. `before` = thời điểm của CHÍNH `event`."""
    cache = _global_counts_cache if cache is None else cache
    # `event.ts_us` là epoch micro-giây UTC (xem `to_us`) — dựng lại datetime UTC để so với `LoginEvent.created_at` (timezone=True, lưu UTC).
    before = datetime.fromtimestamp(event.ts_us / US_PER_SECOND, tz=timezone.utc)

    user_events = None if event.user_id is None else _user_events(db, event.user_id, before)
    asn_events = [] if event.asn is None else _asn_events(db, event.asn, before)
    return HistorySummary(
        user_events=user_events,
        ip_events=_ip_events(db, event.ip, before),
        ip_prior_attempts_all=_ip_prior_attempts_all(db, event.ip, before),
        asn_events=asn_events,
        global_counts=cache.get(db, before),
    )


def compute_rba_features(db: Session, event: EventRecord, *, cache: GlobalCountsCache | None = None) -> dict[str, float] | None:
    """50 đặc trưng RBA (`ml.rba.features.FEATURE_NAMES`) của `event`, hoặc `None` nếu có lỗi (không bao giờ raise — không
    được chặn/làm sập pipeline nền, cùng triết lý phần còn lại của `app/detection`)."""
    try:
        summary = build_history_summary(db, event, cache=cache)
        return features_from_summary(event, summary)
    except Exception:  # noqa: BLE001
        logger.exception("lỗi khi tính đặc trưng RBA cho user_id=%s ip=%s — bỏ qua thành phần ML", event.user_id, event.ip)
        return None
