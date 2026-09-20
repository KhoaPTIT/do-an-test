"""Tầng 3 — ML (nhiệm vụ 7.1), chạy SONG SONG tầng 1 (rule) và tầng 2
(behavioral scoring), KHÔNG THAY THẾ — đúng yêu cầu checklist gốc.

Dùng model Isolation Forest đã huấn luyện ở backend/ml/train.py. Nếu chưa
train (chưa chạy `python -m ml.train`), module tự chuyển sang "không khả
dụng" — không raise lỗi, không chặn luồng đăng nhập (giống triết lý xử lý
lỗi của app/detection/geoip.py).

⚠️ Đây là tầng THAM KHẢO — xem docs/ml-evaluation.md mục 5 (giới hạn thật):
huấn luyện trên dữ liệu tự sinh, chưa qua kiểm định với dữ liệu tấn công
thật. Alert loại `ml_anomaly` nên được đọc như một gợi ý, không phải kết
luận chắc chắn.
"""

from __future__ import annotations

import json
import logging
import os

import numpy as np

from ml.features import FEATURE_NAMES

logger = logging.getLogger("ml_model")

# Tên tiếng Việt dễ hiểu cho từng đặc trưng — dùng khi giải thích (explain()).
# hour_sin/hour_cos cố tình KHÔNG có trong bảng này: chỉ là mã hoá lượng
# giác của giờ, một mình chúng không có ý nghĩa để báo cho admin đọc.
_FEATURE_LABELS_VI = {
    "day_of_week": "thứ trong tuần",
    "hour_deviation_from_avg": "độ lệch giờ so với thói quen",
    "is_new_location": "vị trí mới (chưa từng thấy)",
    "is_new_device": "thiết bị mới (chưa từng thấy)",
    "minutes_since_last_login": "thời gian kể từ lần đăng nhập trước",
    "logins_last_24h": "số lần đăng nhập trong 24h qua",
    "distance_km_from_home": "khoảng cách so với vị trí quen thuộc",
}

_ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "ml", "artifacts")

_scaler = None
_iso_forest = None
_meta: dict | None = None
_load_attempted = False


def _load() -> None:
    global _scaler, _iso_forest, _meta, _load_attempted
    if _load_attempted:
        return
    _load_attempted = True

    try:
        import joblib  # import trễ — tránh phụ thuộc joblib nếu chưa cần ML

        _scaler = joblib.load(os.path.join(_ARTIFACTS_DIR, "scaler.joblib"))
        _iso_forest = joblib.load(os.path.join(_ARTIFACTS_DIR, "isolation_forest.joblib"))
        with open(os.path.join(_ARTIFACTS_DIR, "meta.json"), encoding="utf-8") as f:
            _meta = json.load(f)
        logger.info("Đã tải model ML tầng 3 (Isolation Forest) từ %s", _ARTIFACTS_DIR)
    except FileNotFoundError:
        logger.warning("Chưa có model ML tầng 3 (chạy `python -m ml.train` trước) — tầng 3 tạm tắt.")
        _scaler = None
        _iso_forest = None
        _meta = None
    except Exception:  # noqa: BLE001 — model lỗi/hỏng cũng không được chặn luồng đăng nhập
        logger.exception("Lỗi khi tải model ML tầng 3 — tầng 3 tạm tắt.")
        _scaler = None
        _iso_forest = None
        _meta = None


def is_available() -> bool:
    _load()
    return _iso_forest is not None and _scaler is not None


def predict(features: dict) -> dict | None:
    """Trả {"is_anomaly": bool, "anomaly_score": float} hoặc None nếu model
    chưa sẵn sàng. Không bao giờ raise — mọi lỗi được nuốt và log lại.
    """
    _load()
    if _iso_forest is None or _scaler is None:
        return None

    try:
        vector = np.array([[features[name] for name in FEATURE_NAMES]])
        scaled = _scaler.transform(vector)
        raw_pred = _iso_forest.predict(scaled)[0]  # -1 = bất thường, 1 = bình thường
        anomaly_score = float(-_iso_forest.score_samples(scaled)[0])
        return {"is_anomaly": bool(raw_pred == -1), "anomaly_score": anomaly_score}
    except Exception:  # noqa: BLE001
        logger.exception("Lỗi khi suy luận ML tầng 3 cho 1 lần đăng nhập — bỏ qua, không chặn luồng.")
        return None


def explain(features: dict, top_n: int = 3) -> str:
    """Giải thích NGƯỜI ĐỌC ĐƯỢC: đặc trưng nào lệch nhiều nhất so với phân
    phối "bình thường" đã học (mean/std của tập train, lưu ở meta.json).
    Dùng cho message của Alert 'ml_anomaly' — thay vì chỉ đưa 1 điểm số,
    chỉ ra CỤ THỂ điều gì khiến lần đăng nhập này bị coi là lạ.

    Trả chuỗi rỗng nếu model/thống kê chưa sẵn sàng (không raise).
    """
    _load()
    if _meta is None or "feature_mean" not in _meta:
        return ""

    try:
        means = _meta["feature_mean"]
        stds = _meta["feature_std"]
        deviations = []
        for i, name in enumerate(FEATURE_NAMES):
            if name not in _FEATURE_LABELS_VI:
                continue
            std = stds[i] if stds[i] > 1e-6 else 1.0
            z = (features[name] - means[i]) / std
            deviations.append((abs(z), z, name))

        deviations.sort(key=lambda item: item[0], reverse=True)
        top = deviations[:top_n]

        parts = []
        for _abs_z, z, name in top:
            if abs(z) < 0.5:
                continue  # gần mức trung bình, không đáng nhắc tới
            direction = "cao hơn" if z > 0 else "thấp hơn"
            parts.append(f"{_FEATURE_LABELS_VI[name]} ({direction} bình thường rõ rệt)")

        if not parts:
            return "không có đặc trưng nào lệch rõ rệt so với thói quen"
        return "Yếu tố khác thường nhất: " + "; ".join(parts) + "."
    except Exception:  # noqa: BLE001
        logger.exception("Lỗi khi giải thích kết quả ML — bỏ qua.")
        return ""
