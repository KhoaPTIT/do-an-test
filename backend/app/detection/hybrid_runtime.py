"""Nạp mô hình hybrid theo phiên bản đang active trong `model_registry`, chấm điểm luồng thật, fallback an toàn (MR12).

`HybridEngine.evaluate(features, hits)` là điểm vào duy nhất mà `app/detection/pipeline.py` gọi: luôn trả về một
`RiskResult` (không bao giờ raise), kể cả khi mô hình ML chưa nạp được (`ml_probability=None` — bộ gộp `combine_risk`
(MR11) đã coi đây là "không có bằng chứng đó", không phải "chắc chắn không", nên chỉ luật + danh tiếng vẫn hoạt động).

Nạp MỘT LẦN khi tiến trình khởi động (`app/main.py`, qua `get_engine()` singleton) — không nạp lại cho mỗi lần đăng nhập.
Nạp lỗi ở BẤT KỲ bước nào (thiếu hàng `model_registry`, thiếu file .joblib/.json, `feature_signature` lệch với bản đã
train) đều bị NUỐT và ghi log; khi đó dùng HỒ SƠ DỰ PHÒNG cứng (`_FALLBACK_PROFILE`, không có thành phần ML) để luật vẫn
được chấm điểm — "an toàn" ở đây nghĩa là KHÔNG BAO GIỜ tắt hẳn việc phát hiện chỉ vì mô hình lỗi."""

from __future__ import annotations

import logging
from typing import Iterable

import joblib
from sqlalchemy.orm import Session

from app.detection.engine.types import RuleHit
from app.detection.hybrid import ActionBands, HybridProfile, RiskResult, RuleWeights, combine_risk
from app.detection.model_registry import get_active
from ml.rba.features import feature_signature

logger = logging.getLogger("hybrid_runtime")

# Hồ sơ dự phòng khi chưa nạp được hồ sơ đã hiệu chỉnh (MR11) từ đĩa: bands rộng rãi, chỉ luật ghi đè + trọng số mặc
# định — vẫn cho điểm/hành động hợp lý (không phải "tắt hẳn"), chỉ là CHƯA hiệu chỉnh trên dữ liệu.
_FALLBACK_PROFILE = HybridProfile(RuleWeights(), ActionBands(alert_at=40, step_up_at=65, lock_at=85), ml_calibration=None)


class HybridEngine:
    def __init__(self) -> None:
        self.profile: HybridProfile = _FALLBACK_PROFILE
        self.scorer = None  # frame -> điểm thô của hybrid_cp2 (ml.rba.ensemble.HybridMinTail), None nếu chưa nạp được
        self.model_name: str | None = None
        self.model_version: str | None = None

    @property
    def ml_available(self) -> bool:
        return self.scorer is not None and self.profile.ml_calibration is not None

    def load(self, db: Session) -> None:
        """Nạp phiên bản đang active trong `model_registry`. Không raise — lỗi bất kỳ bước nào thì giữ nguyên trạng thái
        trước đó (hoặc hồ sơ dự phòng nếu chưa từng nạp được gì)."""
        try:
            entry = get_active(db)
            if entry is None:
                logger.warning("model_registry chưa có phiên bản active — dùng hồ sơ dự phòng (chỉ luật + danh tiếng, không có ML)")
                return
            if entry.feature_signature is not None and entry.feature_signature != feature_signature():
                logger.warning(
                    "model_registry %s/%s train với feature_signature=%s nhưng mã hiện tại là %s — bỏ qua thành phần ML (đặc trưng đã đổi, cần train lại)",
                    entry.name, entry.version, entry.feature_signature, feature_signature(),
                )
                return
            scorer = joblib.load(entry.artifact_path)
            profile = HybridProfile.from_file(entry.profile_path) if entry.profile_path else HybridProfile(RuleWeights(), self.profile.bands, None)
            self.scorer, self.profile, self.model_name, self.model_version = scorer, profile, entry.name, entry.version
            logger.info("đã nạp mô hình hybrid %s/%s (ml_available=%s)", entry.name, entry.version, self.ml_available)
        except Exception:  # noqa: BLE001 — không được chặn khởi động ứng dụng vì mô hình lỗi
            logger.exception("lỗi khi nạp mô hình hybrid — dùng hồ sơ dự phòng (chỉ luật + danh tiếng)")

    def ml_probability(self, features: dict[str, float] | None) -> float | None:
        """Xác suất tấn công đã hiệu chỉnh (0-1) từ 50 đặc trưng RBA, `None` nếu thiếu đặc trưng hoặc mô hình chưa sẵn sàng."""
        if features is None or not self.ml_available:
            return None
        try:
            import pandas as pd

            frame = pd.DataFrame([features])
            raw = self.scorer(frame)[0]
            return float(self.profile.ml_calibration.probability(raw))
        except Exception:  # noqa: BLE001
            logger.exception("lỗi khi chấm điểm ML — bỏ qua thành phần ML cho lần thử này")
            return None

    def evaluate(self, features: dict[str, float] | None, hits: Iterable[RuleHit]) -> RiskResult:
        """Điểm 0-100 + hành động cho MỘT lần thử — không bao giờ raise (mọi lỗi rơi về `combine_risk` với `ml_probability=None`)."""
        try:
            ml_probability = self.ml_probability(features)
        except Exception:  # noqa: BLE001 — phòng hờ kép, ml_probability() đã tự bắt lỗi nhưng không đánh đổi độ an toàn
            ml_probability = None
        try:
            return combine_risk(ml_probability=ml_probability, hits=hits, weights=self.profile.weights, bands=self.profile.bands)
        except Exception:  # noqa: BLE001 — combine_risk là hàm thuần không nên lỗi, nhưng "không bao giờ raise" là bất biến của cả pipeline
            logger.exception("lỗi khi gộp điểm hybrid — coi như không có bằng chứng nào")
            return combine_risk(ml_probability=None, hits=(), weights=RuleWeights(), bands=self.profile.bands)


_engine: HybridEngine | None = None


def get_engine() -> HybridEngine:
    """Singleton trong tiến trình — nạp lần đầu gọi (nếu `app/main.py` chưa gọi `load_at_startup` trước)."""
    global _engine
    if _engine is None:
        _engine = HybridEngine()
    return _engine


def load_at_startup(db: Session) -> HybridEngine:
    engine = get_engine()
    engine.load(db)
    return engine
