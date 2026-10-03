"""Model bất thường dùng chung cho đánh giá offline và luồng /login (Phase 4.1): nạp artifact, chấm điểm, giải thích.

Artifact (thư mục `ARTIFACT_DIR`, không commit — sinh bằng `python -m ml.pipeline`):
  - `model.joblib`   — `sklearn.ensemble.IsolationForest` đã fit trên tập train;
  - `metadata.json`  — tên/phiên bản model, chữ ký đặc trưng, ngưỡng (chọn trên validation), thống kê train để giải thích.

Điểm bất thường = −`score_samples` (CÀNG CAO CÀNG LẠ); `is_anomaly` ⇔ điểm ≥ ngưỡng đã lưu."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from ml.features import FEATURE_NAMES, feature_signature, feature_vector

ARTIFACT_DIR = Path(os.environ.get("ML_MODEL_DIR") or Path(__file__).resolve().parent / "artifacts" / "anomaly_iforest")
MODEL_FILE = "model.joblib"
METADATA_FILE = "metadata.json"

REASON_LABELS_VI = {
    "hour_deviation": "giờ đăng nhập lệch thói quen",
    "is_new_location": "vị trí chưa từng thấy",
    "is_new_device": "thiết bị chưa từng thấy",
    "log_minutes_since_last_success": "khoảng cách tới lần đăng nhập trước bất thường",
    "logins_last_24h": "số lần đăng nhập 24 giờ qua bất thường",
    "log_distance_km_from_home": "xa vị trí quen",
    "log_travel_speed_kmh": "tốc độ di chuyển bất thường",
}


class ModelLoadError(RuntimeError):
    pass


@dataclass(frozen=True)
class Score:
    anomaly_score: float
    is_anomaly: bool
    top_features: tuple[dict, ...]


class AnomalyModel:
    def __init__(self, estimator, metadata: dict) -> None:
        if metadata.get("feature_signature") != feature_signature() or metadata.get("feature_names") != FEATURE_NAMES:
            raise ModelLoadError(
                f"artifact train với chữ ký đặc trưng {metadata.get('feature_signature')} nhưng mã hiện tại là {feature_signature()} — cần train lại"
            )
        self.estimator = estimator
        self.metadata = metadata
        self.threshold = float(metadata["threshold"])
        self.model_name = metadata["model_name"]
        self.model_version = metadata["model_version"]
        self._mean = metadata["train_feature_mean"]
        self._std = metadata["train_feature_std"]

    @classmethod
    def load(cls, directory: Path | str = ARTIFACT_DIR) -> "AnomalyModel":
        import joblib

        directory = Path(directory)
        model_path, meta_path = directory / MODEL_FILE, directory / METADATA_FILE
        if not model_path.is_file() or not meta_path.is_file():
            raise ModelLoadError(f"chưa có artifact ở {directory} (chạy: cd backend && python -m ml.pipeline)")
        metadata = json.loads(meta_path.read_text(encoding="utf-8"))
        return cls(joblib.load(model_path), metadata)

    def scores(self, matrix) -> list[float]:
        import numpy as np

        return [float(-s) for s in self.estimator.score_samples(np.asarray(matrix, dtype=float))]

    def explain(self, features: dict[str, float], top_n: int = 3) -> tuple[dict, ...]:
        """Đặc trưng lệch nhiều nhất so với phân phối của tập train (z-score) — gợi ý "vì sao", không phải nguyên nhân chính xác."""
        rows = []
        for i, name in enumerate(FEATURE_NAMES):
            std = self._std[i] if self._std[i] > 1e-9 else 1.0
            z = (features[name] - self._mean[i]) / std
            rows.append({"feature": name, "label": REASON_LABELS_VI[name], "value": round(float(features[name]), 4), "z": round(float(z), 2)})
        rows.sort(key=lambda r: -abs(r["z"]))
        return tuple(r for r in rows[:top_n] if abs(r["z"]) >= 1.0)

    def score(self, features: dict[str, float]) -> Score:
        value = self.scores([feature_vector(features)])[0]
        return Score(anomaly_score=value, is_anomaly=value >= self.threshold, top_features=self.explain(features))
