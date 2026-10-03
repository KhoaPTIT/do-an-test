"""Mô hình bất thường lúc chạy thật (Phase 4.1): trích đặc trưng từ DB bằng ĐÚNG đặc tả offline (`ml/features.py`).

Phần trích đặc trưng ở đây chỉ làm một việc: dựng danh sách `LoginRecord` cho các lần đăng nhập THÀNH CÔNG của tài khoản xảy
ra TRƯỚC HẲN sự kiện đang chấm — loại trừ tường minh chính sự kiện đó (đã `flush` vào DB trước khi chấm, xem
`app/detection/pipeline.py`) — rồi gọi `compute_features` dùng chung với offline."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import LoginEvent
from app.utils.time import ensure_utc
from ml.features import LoginRecord, compute_features, in_scope, make_record


def record_from_event(event) -> LoginRecord:
    """`event`: hàng `LoginEvent` (hoặc bất kỳ đối tượng nào có cùng các cột)."""
    return make_record(
        event.created_at, country=event.country, city=event.city, latitude=event.latitude, longitude=event.longitude, user_agent=event.user_agent,
    )


def prior_successes(db: Session, user_id: int, before: datetime, exclude_event_id: int | None = None) -> list[LoginRecord]:
    """Lần THÀNH CÔNG của tài khoản có `created_at` TRƯỚC HẲN `before`, tăng dần — không bao giờ gồm `exclude_event_id`."""
    query = select(LoginEvent).where(LoginEvent.user_id == user_id, LoginEvent.success.is_(True), LoginEvent.created_at < before)
    if exclude_event_id is not None:
        query = query.where(LoginEvent.id != exclude_event_id)
    rows = db.execute(query.order_by(LoginEvent.created_at, LoginEvent.id)).scalars().all()
    return [record_from_event(row) for row in rows]


def runtime_features(db: Session, event) -> tuple[bool, dict[str, float] | None]:
    """(thuộc phạm vi chấm?, đặc trưng) cho MỘT sự kiện đã ghi vào DB. Ngoài phạm vi (thất bại, tài khoản không tồn tại, hồ sơ
    chưa trưởng thành) thì không tính đặc trưng — mô hình chỉ học và chỉ chấm lần thành công của hồ sơ trưởng thành."""
    if not event.success or event.user_id is None:
        return False, None
    current = record_from_event(event)
    prior = prior_successes(db, event.user_id, ensure_utc(event.created_at), exclude_event_id=event.id)
    if not in_scope(prior, current):
        return False, None
    return True, compute_features(prior, current)


# ------------------------------------------------------------------------------------------------ model lúc chạy thật

logger = logging.getLogger("ml_runtime")

# Trọng số của tín hiệu ML trong noisy-OR của risk engine khi model báo BẤT THƯỜNG (chốt trước khi đo ở Phase 4.1): một
# mình đủ vượt ngưỡng "alert" của hồ sơ dự phòng (40) để tạo cảnh báo xem xét, KHÔNG đủ tới "step_up" (65) hay "lock" (85).
# Không bất thường thì ML không góp bằng chứng (None — "không có bằng chứng", không phải "chắc chắn an toàn").
ML_ANOMALY_WEIGHT = 0.45


@dataclass(frozen=True)
class MLPrediction:
    """Kết quả ML của MỘT lần thử. `available=False` khi model không nạp được; `in_scope=False` khi lần thử ngoài phạm vi chấm
    (thất bại, tài khoản không tồn tại, hồ sơ chưa trưởng thành) — khi đó không có điểm."""

    available: bool
    in_scope: bool
    model_name: str | None = None
    model_version: str | None = None
    anomaly_score: float | None = None
    threshold: float | None = None
    is_anomaly: bool = False
    top_features: tuple[dict, ...] = ()
    reason: str | None = None  # vì sao không có điểm: model_not_loaded | out_of_scope | error

    @property
    def risk_probability(self) -> float | None:
        """Bằng chứng đưa vào noisy-OR của risk engine (None = không có bằng chứng)."""
        return ML_ANOMALY_WEIGHT if self.available and self.in_scope and self.is_anomaly else None

    def to_dict(self) -> dict:
        return {
            "available": self.available, "in_scope": self.in_scope, "model": self.model_name, "version": self.model_version,
            "anomaly_score": None if self.anomaly_score is None else round(self.anomaly_score, 4),
            "threshold": None if self.threshold is None else round(self.threshold, 4),
            "is_anomaly": self.is_anomaly, "top_features": [dict(f) for f in self.top_features], "reason": self.reason,
        }


@dataclass
class MLRuntime:
    """Giữ model đã nạp trong tiến trình. Không bao giờ raise: nạp lỗi thì `available=False` và ghi `last_load_error`."""

    model: object | None = None
    artifact_dir: Path | None = None
    last_load_error: str | None = None
    loaded_at: datetime | None = None
    _attempted: bool = field(default=False, repr=False)

    @property
    def available(self) -> bool:
        return self.model is not None

    def load(self, directory: Path | str | None = None) -> bool:
        from ml.anomaly_model import ARTIFACT_DIR, AnomalyModel

        self._attempted = True
        self.artifact_dir = Path(directory) if directory is not None else ARTIFACT_DIR
        try:
            self.model = AnomalyModel.load(self.artifact_dir)
            self.last_load_error, self.loaded_at = None, datetime.now(timezone.utc)
            logger.info("đã nạp model bất thường %s %s từ %s (ngưỡng %.4f)", self.model.model_name, self.model.model_version, self.artifact_dir, self.model.threshold)
            return True
        except Exception as exc:  # noqa: BLE001 — model lỗi/thiếu không được chặn khởi động hay luồng đăng nhập
            self.model, self.last_load_error = None, f"{type(exc).__name__}: {exc}"
            logger.warning("ML không khả dụng — chỉ dùng 20 detector luật: %s", self.last_load_error)
            return False

    def disable(self, reason: str = "disabled") -> None:
        self.model, self.last_load_error, self._attempted = None, reason, True

    def status(self) -> dict:
        from ml.anomaly_model import METADATA_FILE, MODEL_FILE
        from ml.features import FEATURE_NAMES, feature_signature

        directory = self.artifact_dir
        meta = self.model.metadata if self.model is not None else {}
        return {
            "ml_available": self.available,
            "model_name": meta.get("model_name"), "model_version": meta.get("model_version"),
            "threshold": meta.get("threshold"), "trained_at": meta.get("created_at"),
            "feature_signature": meta.get("feature_signature"), "code_feature_signature": feature_signature(), "feature_names": FEATURE_NAMES,
            "artifact_dir": str(directory) if directory else None,
            "artifact_files": {name: bool(directory and (directory / name).is_file()) for name in (MODEL_FILE, METADATA_FILE)},
            "loaded_at": self.loaded_at.isoformat() if self.loaded_at else None,
            "last_load_error": self.last_load_error,
            "risk_weight_when_anomalous": ML_ANOMALY_WEIGHT,
            "scope": "chỉ lần đăng nhập THÀNH CÔNG của hồ sơ trưởng thành (≥10 lần, ≥7 ngày)",
            "can_lock": False,
        }

    def predict(self, db: Session, event) -> MLPrediction:
        if not self._attempted:
            self.load()
        if self.model is None:
            return MLPrediction(available=False, in_scope=False, reason="model_not_loaded")
        base = dict(model_name=self.model.model_name, model_version=self.model.model_version, threshold=self.model.threshold)
        try:
            in_scope, features = runtime_features(db, event)
            if not in_scope:
                return MLPrediction(available=True, in_scope=False, reason="out_of_scope", **base)
            s = self.model.score(features)
            return MLPrediction(available=True, in_scope=True, anomaly_score=s.anomaly_score, is_anomaly=s.is_anomaly, top_features=s.top_features, **base)
        except Exception:  # noqa: BLE001
            logger.exception("lỗi khi chấm ML cho login_event %s — bỏ qua tín hiệu ML", getattr(event, "id", None))
            return MLPrediction(available=True, in_scope=False, reason="error", **base)


_runtime: MLRuntime | None = None


def get_runtime() -> MLRuntime:
    global _runtime
    if _runtime is None:
        _runtime = MLRuntime()
    return _runtime


def load_at_startup() -> MLRuntime:
    runtime = get_runtime()
    runtime.load()
    return runtime
