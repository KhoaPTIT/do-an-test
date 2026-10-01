"""Dựng `RuleEngine` (MR9-10) cho luồng thật /login (MR12): trạng thái cửa sổ trong Redis (bền qua restart, dùng chung
kết nối với `rate_counter.py`), lịch sử tài khoản/thống kê toàn cục DỰNG LẠI TỪ DB mỗi lần (không giữ trong bộ nhớ tiến
trình) — luôn đúng dù ứng dụng chạy nhiều tiến trình/worker hay vừa khởi động lại, đổi lại phải truy vấn DB mỗi lần
đăng nhập; các truy vấn đều nhắm chỉ mục sẵn có (`ix_login_events_user_created`) nên rẻ (đo ở `docs/realtime-integration.md`).

    engine = build_rule_engine(db)
    evaluation = engine.evaluate(attempt)   # record=True: cũng ghi vào Redis cho lần sau

`ThreatIntel` (Tor/datacenter/VPN) nạp MỘT LẦN khi tiến trình khởi động (`load_threat_intel_at_startup`, đổi rất hiếm khi
chạy `scripts/update_threat_feeds.py`); `blocklist` DB-backed nhưng cache TTL ngắn (đổi khi quản trị viên thao tác, cần
thấy tương đối nhanh, không đáng để truy vấn DB cho mỗi lần đăng nhập)."""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.detection import rate_counter
from app.detection.engine import Blocklist, RedisStore, RuleConfig, RuleEngine, ThreatIntel
from app.detection.engine.intel import BlockEntry
from app.detection.engine.types import AccountHistory, LoginAttempt, ua_hash
from app.models import BlocklistEntry, LoginEvent, RuleOverride
from app.utils.time import ensure_utc

logger = logging.getLogger("rule_engine_runtime")

BLOCKLIST_CACHE_TTL_SECONDS = 15.0
RULE_CONFIG_CACHE_TTL_SECONDS = 15.0  # cùng lý do/độ dài với blocklist — đổi qua GET/PUT/DELETE /rules (MR17), cần thấy tương đối nhanh
_THREAT_INTEL: ThreatIntel | None = None


def load_threat_intel_at_startup() -> ThreatIntel:
    global _THREAT_INTEL
    try:
        _THREAT_INTEL = ThreatIntel.load()
        logger.info("đã nạp threat intel: %s", _THREAT_INTEL.status())
    except Exception:  # noqa: BLE001 — danh sách lỗi/thiếu không được chặn khởi động; luật liên quan tự bỏ qua (Evaluation.skipped)
        logger.exception("lỗi khi nạp threat intel — luật Tor/datacenter/VPN sẽ bị bỏ qua")
        _THREAT_INTEL = ThreatIntel()
    return _THREAT_INTEL


def _get_threat_intel() -> ThreatIntel:
    if _THREAT_INTEL is None:
        return load_threat_intel_at_startup()
    return _THREAT_INTEL


# ------------------------------------------------------------------------------------------------ lịch sử tài khoản từ DB


@dataclass
class DbAccountHistory:
    """`HistoryProvider` dựng lại từ DB mỗi lần gọi `get()` — không giữ trạng thái giữa các lần thử (`update()` là no-op:
    lần sau `get()` lại truy vấn DB, đã thấy chính lần thử vừa ghi)."""

    db: Session
    before: datetime  # lấy lịch sử TRƯỚC mốc này (thời điểm của lần thử đang chấm)

    def get(self, user_key: str | None) -> AccountHistory | None:
        if user_key is None:
            return None
        try:
            user_id = int(user_key)
        except ValueError:
            return None
        rows = self.db.execute(
            select(LoginEvent.created_at, LoginEvent.latitude, LoginEvent.longitude, LoginEvent.success, LoginEvent.country, LoginEvent.user_agent)
            .where(LoginEvent.user_id == user_id, LoginEvent.created_at < self.before)
            .order_by(LoginEvent.created_at)
        ).all()
        if not rows:
            return None
        history = AccountHistory()
        for created_at, lat, lon, success, country, agent in rows:
            history.last_event_ts = ensure_utc(created_at).timestamp()
            history.last_event_lat, history.last_event_lon = lat, lon
            if success:
                history.last_success_ts = ensure_utc(created_at).timestamp()
                history.n_success += 1
                if country and country not in history.known_countries:
                    history.known_countries += (country,)
                hashed = ua_hash(agent)
                if hashed and hashed not in history.known_devices:
                    history.known_devices += (hashed,)
        return history

    def update(self, attempt: LoginAttempt) -> None:
        pass  # xem docstring lớp: `get()` luôn đọc DB mới nhất, không cần giữ trạng thái riêng


# ------------------------------------------------------------------------------------------------ thống kê toàn cục (nhà mạng) từ DB


@dataclass
class DbGlobalStats:
    """`GlobalStats` (dùng bởi `rare_network_login`) — đếm đăng nhập THÀNH CÔNG của tài khoản có thật, theo ASN, mọi
    dòng TRƯỚC `before` (thời điểm của lần thử đang chấm). Dựng mới cho mỗi lần chấm (`build_rule_engine`) nên luôn
    thấy dữ liệu mới nhất.

    MR20 sửa hai lỗi của bản MR12: (1) thiếu điều kiện `created_at < before` — lần thử đang chấm đã `flush` vào DB nên
    bị đếm luôn (`asn_successes` luôn >= 1 với chính ASN của nó, `never_seen` không bao giờ đúng ở luồng thật), trái
    với quy ước "chưa gồm lần này" của luật và của bản trong bộ nhớ dùng khi replay; (2) kéo cột ASN của MỌI dòng về
    Python cho mỗi lần đăng nhập thành công (cache TTL theo instance không bao giờ trúng vì instance dựng mới mỗi
    lần) — nay đếm trong DB: `count(*)` một lần và `count` theo một ASN (chỉ mục `ix_login_events_asn`)."""

    db: Session
    before: datetime
    _total: int | None = field(default=None, init=False)

    def _scope(self):
        return (LoginEvent.success.is_(True), LoginEvent.user_id.isnot(None), LoginEvent.created_at < self.before)

    @property
    def total_successes(self) -> int:
        if self._total is None:
            self._total = self.db.execute(select(func.count()).select_from(LoginEvent).where(*self._scope())).scalar_one()
        return self._total

    def asn_successes(self, asn: int) -> int:
        return self.db.execute(select(func.count()).select_from(LoginEvent).where(*self._scope(), LoginEvent.asn == asn)).scalar_one()

    def update(self, attempt: LoginAttempt) -> None:
        pass  # bộ đếm đọc lại từ DB mỗi lần chấm, không cần cập nhật tức thời tại đây


# ------------------------------------------------------------------------------------------------ blocklist DB-backed, cache TTL ngắn

# "Chưa từng cache" = -inf, KHÔNG phải -1.0: `time.monotonic()` trên Linux đếm từ lúc MÁY khởi động, nên trong
# TTL giây đầu sau khi boot (vd docker-compose bật backend ngay khi máy lên) `now - (-1.0) < TTL` và việc làm mới bị
# bỏ qua — `invalidate_*` khi đó không có tác dụng. -inf thì `now - cached_at` luôn là +inf.
_blocklist_cache: Blocklist | None = None
_blocklist_cached_at = -math.inf


def refresh_blocklist(db: Session, force: bool = False) -> Blocklist:
    """`Blocklist` (bộ nhớ) dựng lại từ bảng `blocklist` mỗi `BLOCKLIST_CACHE_TTL_SECONDS` giây — quản trị viên thêm/xoá
    mục chặn được áp dụng trong khoảng đó, không phải ngay lập tức (đổi lấy không phải truy vấn DB cho mỗi lần đăng nhập)."""
    global _blocklist_cache, _blocklist_cached_at
    now = time.monotonic()
    if not force and _blocklist_cache is not None and now - _blocklist_cached_at < BLOCKLIST_CACHE_TTL_SECONDS:
        return _blocklist_cache
    blocklist = Blocklist()
    for row in db.execute(select(BlocklistEntry)).scalars():
        expires_at = None if row.expires_at is None else ensure_utc(row.expires_at).timestamp()
        blocklist.add_entry(BlockEntry(kind=row.kind, value=row.value, reason=row.reason or "", expires_at=expires_at, added_by=row.added_by))
    _blocklist_cache, _blocklist_cached_at = blocklist, now
    return blocklist


def invalidate_blocklist_cache() -> None:
    """Gọi ngay sau khi quản trị viên thêm/xoá một mục chặn, để không phải chờ hết TTL (MR13+ sẽ có router gọi hàm này)."""
    global _blocklist_cached_at
    _blocklist_cached_at = -math.inf


# ------------------------------------------------------------------------------------------------ rule config DB-backed, cache TTL ngắn

_rule_config_cache: RuleConfig | None = None
_rule_config_cached_at = -math.inf


def refresh_rule_config(db: Session, force: bool = False) -> RuleConfig:
    """`RuleConfig` dựng lại từ bảng `rule_overrides` mỗi `RULE_CONFIG_CACHE_TTL_SECONDS` giây (MR17) — trước đó luồng
    thật LUÔN chấm bằng mặc định của sổ đăng ký (`build_rule_engine(db)` gọi không truyền `config`, tương đương
    `RuleConfig()` rỗng); giờ đọc đè từ DB, cùng cơ chế cache với `refresh_blocklist` ở trên."""
    global _rule_config_cache, _rule_config_cached_at
    now = time.monotonic()
    if not force and _rule_config_cache is not None and now - _rule_config_cached_at < RULE_CONFIG_CACHE_TTL_SECONDS:
        return _rule_config_cache
    config = RuleConfig()
    for row in db.execute(select(RuleOverride)).scalars():
        if row.mode is not None:
            config.modes[row.rule_id] = row.mode
        if row.params is not None:
            config.params[row.rule_id] = dict(row.params)
    _rule_config_cache, _rule_config_cached_at = config, now
    return config


def invalidate_rule_config_cache() -> None:
    """Gọi ngay sau khi quản trị viên đổi cấu hình một luật (`PUT`/`DELETE /rules/{id}`, MR17)."""
    global _rule_config_cached_at
    _rule_config_cached_at = -math.inf


# ------------------------------------------------------------------------------------------------ dựng engine


def build_rule_engine(db: Session, config: RuleConfig | None = None, *, before: datetime | None = None) -> RuleEngine:
    """`RuleEngine` cho MỘT lần chấm. `store`: `RedisStore` dựng MỖI LẦN gọi trên `rate_counter.redis_client` hiện tại
    (không giữ client thành singleton ở module này — test thay `rate_counter.redis_client` bằng fakeredis qua
    `monkeypatch`, giữ singleton sẽ lỡ mất bản thay đó; dựng lại object `RedisStore` không tốn kém, chỉ giữ tham chiếu).
    Tiền tố khoá "rule:" (state.py) không đụng khoá của `rate_counter`. `intel` dùng chung/singleton (nạp một lần lúc
    khởi động). `history`, `stats`, `blocklist` dựng mới từ DB (rẻ, luôn đúng — xem docstring module). `before`: mốc
    "trước đó" cho lịch sử, mặc định là hiện tại. `config=None` (mặc định): đọc `rule_overrides` qua
    `refresh_rule_config` (MR17) — truyền tay một `RuleConfig` khác (vd hiệu chỉnh/replay ngoại tuyến, MR9-10) để BỎ
    QUA ghi đè của quản trị viên."""
    before = ensure_utc(before) if before is not None else datetime.now(timezone.utc)
    store = RedisStore(rate_counter.redis_client)
    resolved_config = refresh_rule_config(db) if config is None else config
    return RuleEngine(resolved_config, store=store, history=DbAccountHistory(db, before), intel=_get_threat_intel(), blocklist=refresh_blocklist(db), stats=DbGlobalStats(db, before))
