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
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.detection import rate_counter
from app.detection.engine import Blocklist, RedisStore, RuleConfig, RuleEngine, ThreatIntel
from app.detection.engine.intel import BlockEntry
from app.detection.engine.types import AccountHistory, LoginAttempt, device_family_of, ua_hash
from app.models import BlocklistEntry, LoginEvent, RuleOverride
from app.utils.device import parse_user_agent
from app.utils.time import ensure_utc

logger = logging.getLogger("rule_engine_runtime")

BLOCKLIST_CACHE_TTL_SECONDS = 15.0
RULE_CONFIG_CACHE_TTL_SECONDS = 15.0  # cùng lý do/độ dài với blocklist — đổi qua GET/PUT/DELETE /rules (MR17), cần thấy tương đối nhanh
_THREAT_INTEL: ThreatIntel | None = None
_BACKEND_DIR = Path(__file__).resolve().parents[2]


def threat_intel_directory() -> Path | None:
    """Thư mục danh sách theo cấu hình `THREAT_INTEL_DIR` (tương đối tính từ `backend/`); None = mặc định của
    `ThreatIntel.load` (`backend/threat_intel/`, dữ liệu thật)."""
    configured = get_settings().threat_intel_dir.strip()
    if not configured:
        return None
    path = Path(configured)
    return path if path.is_absolute() else _BACKEND_DIR / path


def load_threat_intel_at_startup() -> ThreatIntel:
    global _THREAT_INTEL
    try:
        _THREAT_INTEL = ThreatIntel.load(threat_intel_directory())
        status = _THREAT_INTEL.status()
        logger.info("đã nạp threat intel: %s", status)
        if status["data_kind"] in ("demo", "fixture"):
            logger.warning("threat intel đang dùng DỮ LIỆU %s (%s) — KHÔNG phải threat intelligence thực tế", status["data_kind"].upper(), status["source_dir"])
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
            select(LoginEvent.created_at, LoginEvent.latitude, LoginEvent.longitude, LoginEvent.success, LoginEvent.country, LoginEvent.city, LoginEvent.user_agent)
            .where(LoginEvent.user_id == user_id, LoginEvent.created_at < self.before)
            .order_by(LoginEvent.created_at)
        ).all()
        if not rows:
            return None
        history = AccountHistory()
        for created_at, lat, lon, success, country, city, agent in rows:
            history.last_event_ts = ensure_utc(created_at).timestamp()
            history.last_event_lat, history.last_event_lon = lat, lon
            if success:  # hồ sơ CHỈ học từ lần thành công (AccountHistory.record_success) — cùng mã với MemoryHistory
                parsed = parse_user_agent(agent)
                history.record_success(
                    ensure_utc(created_at).timestamp(), lat=lat, lon=lon, country=country, city=city,
                    device_family=device_family_of(agent, parsed.device_type, parsed.os, parsed.browser), agent_hash=ua_hash(agent),
                )
        return history

    def update(self, attempt: LoginAttempt) -> None:
        pass  # xem docstring lớp: `get()` luôn đọc DB mới nhất, không cần giữ trạng thái riêng


# ------------------------------------------------------------------------------------------------ thống kê toàn cục (nhà mạng) từ DB, có cache TTL ngắn


@dataclass
class DbGlobalStats:
    """`GlobalStats` (dùng bởi `rare_network_login`) — đếm đăng nhập THÀNH CÔNG của tài khoản có thật, theo ASN, TOÀN
    BẢNG. Cache TTL ngắn cùng lý do với `rba_live_features.GlobalCountsCache` (không nhắm được một chỉ mục hẹp)."""

    db: Session
    ttl_seconds: float = 30.0
    _total: int = field(default=0, init=False)
    _by_asn: dict[int, int] = field(default_factory=dict, init=False)
    _cached_at: float = field(default=-1.0, init=False)

    def _refresh(self) -> None:
        now = time.monotonic()
        if now - self._cached_at < self.ttl_seconds:
            return
        rows = self.db.execute(
            select(LoginEvent.asn).where(LoginEvent.success.is_(True), LoginEvent.user_id.isnot(None))
        ).all()
        self._total = len(rows)
        by_asn: dict[int, int] = {}
        for (asn,) in rows:
            if asn is not None:
                by_asn[asn] = by_asn.get(asn, 0) + 1
        self._by_asn = by_asn
        self._cached_at = now

    @property
    def total_successes(self) -> int:
        self._refresh()
        return self._total

    def asn_successes(self, asn: int) -> int:
        self._refresh()
        return self._by_asn.get(asn, 0)

    def update(self, attempt: LoginAttempt) -> None:
        pass  # bộ đếm đọc lại từ DB theo TTL, không cần cập nhật tức thời tại đây


# ------------------------------------------------------------------------------------------------ blocklist DB-backed, cache TTL ngắn

_blocklist_cache: Blocklist | None = None
_blocklist_cached_at = -1.0


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
    _blocklist_cached_at = -1.0


# ------------------------------------------------------------------------------------------------ rule config DB-backed, cache TTL ngắn

_rule_config_cache: RuleConfig | None = None
_rule_config_cached_at = -1.0


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
    _rule_config_cached_at = -1.0


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
    return RuleEngine(resolved_config, store=store, history=DbAccountHistory(db, before), intel=_get_threat_intel(), blocklist=refresh_blocklist(db), stats=DbGlobalStats(db))
