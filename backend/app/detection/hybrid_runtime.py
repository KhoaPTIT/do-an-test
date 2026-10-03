"""Risk engine lúc chạy thật: gộp 20 detector luật + tín hiệu của model bất thường thành MỘT điểm 0–100 và MỘT hành động.

Phase 4.1: thành phần ML là model bất thường Isolation Forest (`app/detection/ml_runtime.py`) — thay `hybrid_cp2`/RBA (cần bộ
dữ liệu 9GB, không tái lập được trong repo, lệch train/serve — audit Phase 4.0). Bộ gộp giữ nguyên (`combine_risk`, noisy-OR
có trọng số, MR11) với hồ sơ ngưỡng/trọng số luật DỰ PHÒNG — đúng cấu hình mà 20 hành vi VERIFIED của Phase 3 đã được đo.

An toàn (Phase 4.1H): ML CHỈ tăng điểm hoặc tạo tín hiệu bất thường bổ sung — KHÔNG BAO GIỜ tự dẫn tới "lock". Nếu có ML điểm
vượt `lock_at` nhưng riêng luật thì không, hành động bị hạ xuống "step_up" (`ml_lock_suppressed=True`). Khoá cứng vẫn cần luật
ghi đè (blocklist) hoặc bằng chứng luật đủ mạnh."""

from __future__ import annotations

import dataclasses
import logging
from pathlib import Path
from typing import Iterable

from app.detection.engine.types import RuleHit
from app.detection.hybrid import ActionBands, HybridProfile, RiskResult, RuleWeights, combine_risk

logger = logging.getLogger("hybrid_runtime")

# Hồ sơ đang dùng: trọng số luật mặc định + ngưỡng hành động — KHÔNG đổi ở Phase 4.1 (cấu hình của 20 hành vi VERIFIED).
_FALLBACK_PROFILE = HybridProfile(RuleWeights(), ActionBands(alert_at=40, step_up_at=65, lock_at=85), ml_calibration=None)
# Hồ sơ hiệu chỉnh trên RBA (MR11) — KHÔNG nạp ở runtime từ Phase 4.1 (thuộc hybrid_cp2); giữ để tham chiếu/test.
CALIBRATED_PROFILE_PATH = Path(__file__).resolve().parent / "hybrid" / "profiles" / "rba_calibrated.json"


def ml_lock_suppressed(result: RiskResult, bands: ActionBands) -> bool:
    """Điểm (có ML) đã tới mức khoá nhưng hành động bị chốt chặn hạ xuống — ML không bao giờ tự khoá."""
    return result.overridden_by is None and result.action != "lock" and result.score >= bands.lock_at


@dataclasses.dataclass(frozen=True)
class RiskOutcome:
    result: RiskResult
    ml_lock_suppressed: bool = False  # ML đẩy điểm tới mức khoá nhưng riêng luật không đủ -> đã hạ xuống step_up


class HybridEngine:
    def __init__(self) -> None:
        self.profile: HybridProfile = _FALLBACK_PROFILE

    @property
    def ml_available(self) -> bool:
        """Model bất thường đã nạp được chưa (`app/detection/ml_runtime.py`)."""
        from app.detection import ml_runtime

        return ml_runtime.get_runtime().available

    def evaluate(self, ml_prediction, hits: Iterable[RuleHit], *, bands: ActionBands | None = None) -> RiskResult:
        return self.evaluate_with_guard(ml_prediction, hits, bands=bands).result

    def evaluate_with_guard(self, ml_prediction, hits: Iterable[RuleHit], *, bands: ActionBands | None = None) -> RiskOutcome:
        """Điểm + hành động cho MỘT lần thử — không bao giờ raise. `ml_prediction`: `MLPrediction` hoặc None."""
        hits = list(hits)
        effective_bands = bands if bands is not None else self.profile.bands
        try:
            ml_probability = None if ml_prediction is None else ml_prediction.risk_probability
        except Exception:  # noqa: BLE001
            ml_probability = None
        try:
            result = combine_risk(ml_probability=ml_probability, hits=hits, weights=self.profile.weights, bands=effective_bands)
            if result.action == "lock" and result.overridden_by is None and ml_probability is not None:
                rules_only = combine_risk(ml_probability=None, hits=hits, weights=self.profile.weights, bands=effective_bands)
                if rules_only.action != "lock":
                    return RiskOutcome(dataclasses.replace(result, action="step_up"), ml_lock_suppressed=True)
            return RiskOutcome(result)
        except Exception:  # noqa: BLE001 — "không bao giờ raise" là bất biến của cả pipeline
            logger.exception("lỗi khi gộp điểm — coi như không có bằng chứng nào")
            return RiskOutcome(combine_risk(ml_probability=None, hits=(), weights=RuleWeights(), bands=effective_bands))


_engine: HybridEngine | None = None


def get_engine() -> HybridEngine:
    global _engine
    if _engine is None:
        _engine = HybridEngine()
    return _engine


def load_at_startup(db=None) -> HybridEngine:
    """Nạp model bất thường (nếu chưa) và ghi phiên bản vào `model_registry`; giữ tên cũ cho các script mô phỏng MR13–MR18."""
    from app.detection import ml_runtime, model_registry

    runtime = ml_runtime.get_runtime()
    if not runtime.available:
        runtime.load()
    if db is not None:
        model_registry.ensure_registered(db, runtime)
    return get_engine()
