"""Nạp mô hình đã huấn luyện và chấm điểm bất thường lúc chạy thật.

Mô hình được huấn luyện offline bằng ml/train.py và lưu ra file .pkl.
Nếu chưa có file mô hình, hàm predict_anomaly() trả về None và hệ thống
tự động chỉ dựa vào rule. Nhờ vậy API vẫn chạy được ngay từ đầu,
trước khi nhóm kịp huấn luyện mô hình.
"""
import logging
from typing import Optional

import numpy as np

from app.config import ML_MIN_HISTORY, MODEL_PATH
from app.detection.features import EventData, extract_features

log = logging.getLogger(__name__)

_bundle = None
_load_attempted = False


def _load():
    """Nạp mô hình một lần duy nhất, có nhớ kết quả."""
    global _bundle, _load_attempted
    if _load_attempted:
        return _bundle
    _load_attempted = True
    try:
        import joblib
        _bundle = joblib.load(MODEL_PATH)
        log.info("Đã nạp mô hình từ %s", MODEL_PATH)
    except Exception as exc:
        log.warning("Chưa nạp được mô hình (%s). Hệ thống sẽ chỉ dùng rule.", exc)
        _bundle = None
    return _bundle


def reload_model():
    """Buộc nạp lại mô hình. Dùng sau khi huấn luyện lại."""
    global _bundle, _load_attempted
    _load_attempted = False
    _bundle = None
    return _load()


def model_info() -> dict:
    b = _load()
    if b is None:
        return {"loaded": False}
    return {
        "loaded": True,
        "features": b.get("features", []),
        "trained_at": b.get("trained_at"),
        "calibration": b.get("calibration", {}),
        "metrics": b.get("metrics", {}),
    }


def predict_anomaly(event: EventData, ctx: dict) -> Optional[float]:
    """Trả về điểm bất thường trong thang 0-100, hoặc None nếu không dùng được.

    None xảy ra trong hai trường hợp:
      1. Chưa có file mô hình.
      2. User chưa đủ lịch sử (cold start) nên đặc trưng hành vi không đáng tin.
    """
    bundle = _load()
    if bundle is None:
        return None
    if ctx["history_count"] < ML_MIN_HISTORY:
        return None

    x = np.array([extract_features(event, ctx)], dtype=float)
    x_scaled = bundle["scaler"].transform(x)

    # decision_function: giá trị càng nhỏ (âm) thì càng bất thường.
    raw = float(bundle["iso"].decision_function(x_scaled)[0])

    # Quy đổi tuyến tính về thang 0-100 dựa trên hai mốc đã tính lúc huấn luyện:
    #   normal_ref  = phân vị 50 điểm thô của dữ liệu bình thường  -> 0
    #   anomaly_ref = phân vị 1 điểm thô của dữ liệu bình thường   -> 100
    cal = bundle.get("calibration", {})
    normal_ref = cal.get("normal_ref", 0.1)
    anomaly_ref = cal.get("anomaly_ref", -0.1)

    span = normal_ref - anomaly_ref
    if span <= 1e-9:
        return 0.0
    score = (normal_ref - raw) / span * 100.0
    return float(min(100.0, max(0.0, score)))


def predict_supervised(event: EventData, ctx: dict) -> Optional[float]:
    """Điểm từ mô hình có giám sát (Random Forest), dùng để so sánh
    trong phần đánh giá của báo cáo. Không tham gia chấm điểm chạy thật.
    """
    bundle = _load()
    if bundle is None or "rf" not in bundle:
        return None
    x = np.array([extract_features(event, ctx)], dtype=float)
    x_scaled = bundle["scaler"].transform(x)
    return float(bundle["rf"].predict_proba(x_scaled)[0][1] * 100.0)
