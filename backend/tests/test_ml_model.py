"""Kiểm tra nhiệm vụ 7.1 — tầng 3 (ML) không bao giờ chặn luồng đăng nhập,
kể cả khi chưa train model."""

import app.detection.ml_model as ml_model
from ml.features import FEATURE_NAMES

_SAMPLE_FEATURES = {name: 0.0 for name in FEATURE_NAMES}


def _reset_module_cache():
    ml_model._load_attempted = False
    ml_model._scaler = None
    ml_model._iso_forest = None
    ml_model._meta = None


def test_predict_returns_none_when_model_not_trained(monkeypatch):
    _reset_module_cache()
    monkeypatch.setattr(ml_model, "_ARTIFACTS_DIR", "duong-dan-khong-ton-tai")

    result = ml_model.predict(_SAMPLE_FEATURES)

    assert result is None
    assert ml_model.is_available() is False
    _reset_module_cache()


def test_predict_works_with_real_trained_model_if_present():
    """Nếu đã chạy `python -m ml.train` (artifacts có sẵn), model phải tải
    được và trả kết quả đúng dạng. Nếu chưa train, bỏ qua test này."""
    _reset_module_cache()
    if not ml_model.is_available():
        import pytest

        pytest.skip("Chưa train model ML (chạy `python -m ml.train` trước)")

    result = ml_model.predict(_SAMPLE_FEATURES)

    assert result is not None
    assert isinstance(result["is_anomaly"], bool)
    assert isinstance(result["anomaly_score"], float)
    _reset_module_cache()


def test_predict_never_raises_on_malformed_features():
    _reset_module_cache()
    if not ml_model.is_available():
        import pytest

        pytest.skip("Chưa train model ML")

    # Thiếu hết các key -> lẽ ra KeyError, nhưng predict() phải nuốt lỗi và trả None.
    result = ml_model.predict({})

    assert result is None
    _reset_module_cache()
