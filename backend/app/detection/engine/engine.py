"""Bộ máy chấm luật của rule engine v2 (MR9): nhận MỘT `LoginAttempt`, ghi vào các chỉ mục cửa sổ thời gian, chạy mọi luật đang bật và trả các luật khớp.

Thứ tự cho mỗi lần thử:
  1. GHI lần thử vào các chỉ mục (indexes.record) — nên số đếm đã gồm chính nó;
  2. lấy lịch sử tài khoản TRƯỚC lần thử (chưa gồm nó);
  3. chạy từng luật có chế độ ≠ off; luật thiếu dữ liệu bị BỎ QUA kèm lý do, luật lỗi được ghi lại và không ảnh hưởng luật khác (một luật hỏng không được
     làm sập luồng đăng nhập);
  4. cập nhật lịch sử và thống kê toàn hệ thống bằng lần thử này.

Engine không biết nguồn dữ liệu: luồng thật (MR12), replay log lịch sử (replay.py) và test đều gọi cùng `evaluate`. Nhãn (`LoginAttempt.labels`) không bao giờ được truyền cho luật.
"""

from __future__ import annotations

import logging
import time
from types import SimpleNamespace
from typing import Mapping

from app.detection.engine import indexes
from app.detection.engine.context import GlobalStats, HistoryProvider, MemoryGlobalStats, MemoryHistory
from app.detection.engine.intel import Blocklist, ThreatIntel
from app.detection.engine.registry import NEEDS, REGISTRY, RuleConfig, RuleContext, RuleSpec
from app.detection.engine.state import MemoryStore, WindowStore
from app.detection.engine.types import AccountHistory, Evaluation, LoginAttempt, RuleHit

logger = logging.getLogger("rule_engine")


class RuleEngine:
    def __init__(
        self,
        config: RuleConfig | None = None,
        *,
        store: WindowStore | None = None,
        history: HistoryProvider | None = None,
        intel: ThreatIntel | None = None,
        blocklist: Blocklist | None = None,
        stats: GlobalStats | None = None,
        registry: Mapping[str, RuleSpec] | None = None,
    ) -> None:
        self.registry = REGISTRY if registry is None else registry
        self.store = MemoryStore() if store is None else store
        self.history = MemoryHistory() if history is None else history
        self.intel = ThreatIntel() if intel is None else intel  # rỗng: luật hạ tầng bị bỏ qua vì chưa nạp danh sách
        self.blocklist = Blocklist() if blocklist is None else blocklist
        self.stats = MemoryGlobalStats() if stats is None else stats
        self.set_config(config or RuleConfig())

    def set_config(self, config: RuleConfig) -> None:
        """Áp cấu hình mới (bật/tắt, chế độ, tham số) — không mất trạng thái cửa sổ đã ghi."""
        self.config = config
        self._plan: list[tuple[RuleSpec, str, SimpleNamespace]] = []
        for spec in self.registry.values():
            mode = config.mode_of(spec)
            if mode != "off":
                self._plan.append((spec, mode, config.resolved_params(spec)))

    # ------------------------------------------------------------------------------------------------ dữ liệu thiếu

    def _available(self, attempt: LoginAttempt, history: AccountHistory | None) -> dict[str, bool]:
        """Bảng "dữ liệu nào có" của MỘT lần thử — tính một lần rồi dùng cho mọi luật (khoá là các mã trong `registry.NEEDS`)."""
        loaded = self.intel.loaded
        return {
            "account": attempt.user_exists,
            "asn": attempt.asn is not None,
            "country": bool(attempt.country),
            "geo": attempt.has_geo,
            "user_agent": bool(attempt.user_agent),
            "history": history is not None,
            "tor_list": loaded.get("tor", False),
            "datacenter_list": loaded.get("datacenter", False),
            "vpn_list": loaded.get("vpn", False),
            "global_stats": True,
        }

    @staticmethod
    def _missing(spec: RuleSpec, available: dict[str, bool]) -> str | None:
        """Lý do luật phải bỏ qua vì thiếu dữ liệu, hoặc None nếu đủ."""
        for need in spec.needs:
            if not available[need]:
                return f"thiếu {NEEDS[need]}"
        return None

    # ------------------------------------------------------------------------------------------------ chấm điểm

    def evaluate(self, attempt: LoginAttempt, record: bool = True) -> Evaluation:
        """Chấm MỘT lần thử. `record=False`: chỉ truy vấn, không ghi chỉ mục/lịch sử/thống kê (thử "nếu như" mà không đổi trạng thái)."""
        started = time.perf_counter()
        if record:
            indexes.record(self.store, attempt)
        history = self.history.get(attempt.user_key)
        available = self._available(attempt, history)

        result = Evaluation()
        for spec, mode, params in self._plan:
            reason = self._missing(spec, available)
            if reason is not None:
                result.skipped[spec.id] = reason
                continue
            ctx = RuleContext(attempt, self.store, history, self.intel, self.blocklist, self.stats, params)
            try:
                finding = spec.evaluate(ctx)
            except Exception as exc:  # noqa: BLE001 — một luật lỗi không được chặn các luật còn lại hay luồng đăng nhập
                logger.exception("luật %s lỗi", spec.id)
                result.errors[spec.id] = f"{type(exc).__name__}: {exc}"
                continue
            if finding is not None:
                result.hits.append(RuleHit(spec.id, finding.severity or spec.severity, finding.message, dict(finding.evidence), mode, spec.techniques))

        if record:
            self.history.update(attempt)
            self.stats.update(attempt)
        result.elapsed_ms = (time.perf_counter() - started) * 1000
        return result
