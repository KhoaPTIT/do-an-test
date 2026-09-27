"""MR12 — app/detection/hybrid_runtime.py: nạp theo model_registry, fallback an toàn khi thiếu/lỗi/lệch feature_signature,
không bao giờ raise ra ngoài evaluate()."""

import joblib
import pytest

from app.detection import hybrid_runtime, model_registry
from app.detection.hybrid import ActionBands
from app.detection.hybrid.calibration import HybridProfile, MonotonicCalibrator, RuleWeights
from app.models import ModelRegistryEntry


def _scorer_half(frame):
    """joblib/pickle cần một hàm ĐẶT TÊN, nạp lại được từ module — không dùng lambda (không pickle được)."""
    return [0.5] * len(frame)


def _scorer_high(frame):
    return [0.9] * len(frame)


@pytest.fixture()
def engine():
    return hybrid_runtime.HybridEngine()


def test_a_fresh_engine_starts_on_the_fallback_profile_with_ml_unavailable(engine):
    assert engine.ml_available is False
    assert engine.profile.ml_calibration is None
    result = engine.evaluate(None, [])
    assert result.action == "allow" and result.ml_probability is None


def test_load_uses_the_fallback_when_nothing_is_registered(db_session, engine):
    engine.load(db_session)
    assert engine.ml_available is False and engine.model_name is None


def test_load_succeeds_against_the_real_registered_artifacts(db_session, engine):
    model_registry.ensure_registered(db_session)
    engine.load(db_session)
    assert engine.ml_available is True and engine.model_name == "hybrid_cp2" and engine.model_version == "cp2"
    assert engine.profile.ml_calibration is not None and len(engine.profile.weights.entries) > 0


def test_load_falls_back_safely_when_the_artifact_file_is_missing(db_session, engine, tmp_path):
    db_session.add(ModelRegistryEntry(name="hybrid_cp2", version="broken", artifact_path=str(tmp_path / "khong_co.joblib"), is_active=True))
    db_session.commit()
    engine.load(db_session)
    assert engine.ml_available is False  # lỗi khi joblib.load -> giữ hồ sơ dự phòng, không raise


def test_load_skips_ml_when_the_feature_signature_does_not_match(db_session, engine, tmp_path):
    fake_scorer_path = tmp_path / "fake.joblib"
    joblib.dump(_scorer_half, fake_scorer_path)
    db_session.add(ModelRegistryEntry(name="hybrid_cp2", version="stale", artifact_path=str(fake_scorer_path), feature_signature="lech-phien-ban", is_active=True))
    db_session.commit()
    engine.load(db_session)
    assert engine.ml_available is False and engine.scorer is None


def test_load_accepts_a_registry_row_without_a_profile_path(db_session, engine, tmp_path):
    fake_scorer_path = tmp_path / "fake2.joblib"
    joblib.dump(_scorer_high, fake_scorer_path)
    db_session.add(ModelRegistryEntry(name="hybrid_cp2", version="noprofile", artifact_path=str(fake_scorer_path), profile_path=None, is_active=True))
    db_session.commit()
    engine.load(db_session)
    assert engine.scorer is not None and engine.profile.ml_calibration is None  # không có hồ sơ hiệu chỉnh -> không có thành phần ML dù đã nạp được scorer
    assert engine.ml_probability({"x": 1.0}) is None


def test_ml_probability_returns_none_without_features_or_without_ml(engine):
    assert engine.ml_probability(None) is None
    assert engine.ml_probability({"a": 1.0}) is None  # ml_available vẫn False


def test_ml_probability_swallows_scorer_errors(engine):
    def boom(frame):
        raise RuntimeError("lỗi mô hình")

    engine.scorer = boom
    engine.profile = HybridProfile(RuleWeights(), ActionBands(10, 50, 90), MonotonicCalibrator((0.0, 1.0), (0.0, 1.0)))
    assert engine.ml_probability({"a": 1.0}) is None


def test_evaluate_combines_ml_probability_with_hits_when_available(engine):
    engine.scorer = lambda frame: [3.0] * len(frame)
    engine.profile = HybridProfile(RuleWeights(), ActionBands(alert_at=10, step_up_at=50, lock_at=90), MonotonicCalibrator((0.0, 5.0), (0.0, 1.0)))
    result = engine.evaluate({"a": 1.0}, [])
    assert result.ml_probability == pytest.approx(0.6) and result.score == 60 and result.action == "step_up"


def test_evaluate_uses_the_group_default_bands_when_no_override_is_given(engine):
    engine.scorer = lambda frame: [3.0] * len(frame)
    engine.profile = HybridProfile(RuleWeights(), ActionBands(alert_at=10, step_up_at=50, lock_at=90), MonotonicCalibrator((0.0, 5.0), (0.0, 1.0)))
    result = engine.evaluate({"a": 1.0}, [])
    assert result.score == 60 and result.action == "step_up"  # ActionBands mặc định của profile: [50,90) -> step_up


def test_evaluate_uses_a_per_user_bands_override_when_given(engine):
    """MR15: cùng điểm 60 như test ở trên, nhưng ngưỡng riêng của tài khoản (đã nới lỏng) đẩy step_up_at lên 65 -> 60
    giờ chỉ còn 'alert', không phải 'step_up' nữa — chứng minh override THỰC SỰ đổi được hành động, không bị bỏ qua."""
    engine.scorer = lambda frame: [3.0] * len(frame)
    engine.profile = HybridProfile(RuleWeights(), ActionBands(alert_at=10, step_up_at=50, lock_at=90), MonotonicCalibrator((0.0, 5.0), (0.0, 1.0)))
    looser_bands = ActionBands(alert_at=20, step_up_at=65, lock_at=90)
    result = engine.evaluate({"a": 1.0}, [], bands=looser_bands)
    assert result.score == 60 and result.action == "alert"


def test_evaluate_falls_back_to_no_evidence_when_combining_the_real_hits_blows_up(engine, monkeypatch):
    """Mô phỏng combine_risk lỗi KHI CÓ bằng chứng thật (`hits` khác rỗng) — evaluate() phải bắt lỗi đó và rơi về gọi
    lại combine_risk thật với hits=() (đường dự phòng), không raise ra ngoài."""
    real_combine_risk = hybrid_runtime.combine_risk

    def flaky(*, hits, **kwargs):
        if tuple(hits):
            raise RuntimeError("lỗi giả lập khi có bằng chứng")
        return real_combine_risk(hits=hits, **kwargs)

    monkeypatch.setattr("app.detection.hybrid_runtime.combine_risk", flaky)
    result = engine.evaluate(None, [object()])
    assert result.score == 0 and result.action == "allow"  # rơi về "không có bằng chứng nào", không raise


def test_singleton_get_engine_returns_the_same_instance():
    a, b = hybrid_runtime.get_engine(), hybrid_runtime.get_engine()
    assert a is b


# --------------------------------------------------------------------------------------- ml_component (MR13)


def test_ml_component_returns_none_without_features_or_without_ml(engine):
    assert engine.ml_component(None) is None
    assert engine.ml_component({"a": 1.0}) is None  # ml_available vẫn False


def test_ml_component_swallows_errors_from_a_scorer_without_triggered_by(engine):
    """`ml_probability` chấp nhận MỌI callable làm scorer (chỉ cần gọi được); `ml_component` cần thêm `.triggered_by()`
    (chỉ `HybridMinTail` thật có) — scorer giả trong các test khác của file này (hàm/lambda trần) không có, phải rơi
    về `None` chứ không được raise."""
    engine.scorer = lambda frame: [3.0] * len(frame)
    engine.profile = HybridProfile(RuleWeights(), ActionBands(10, 50, 90), MonotonicCalibrator((0.0, 5.0), (0.0, 1.0)))
    assert engine.ml_component({"a": 1.0}) is None


def test_ml_component_against_the_real_trained_model_returns_a_known_component_name(db_session, engine):
    """Nạp `hybrid_cp2` THẬT (không giả lập) — `triggered_by` phải trả đúng tên một trong ba thành phần của
    `HybridMinTail` (ml/rba/ensemble.py), khớp `ML_COMPONENT_FAMILY` mà app/detection/alert_intelligence.py dùng."""
    from ml.rba.explain import COMPONENT_LABELS
    from ml.rba.features import FEATURE_NAMES

    model_registry.ensure_registered(db_session)
    engine.load(db_session)
    assert engine.ml_available is True

    features = {name: 0.0 for name in FEATURE_NAMES}
    component = engine.ml_component(features)
    assert component in COMPONENT_LABELS
