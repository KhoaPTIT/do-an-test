"""Hybrid risk engine (MR11): gộp điểm ML đã hiệu chỉnh, kết quả rule engine v2 (MR9-10) và danh tiếng hạ tầng thành một
điểm 0-100 và một hành động (allow/alert/step_up/lock).

    from app.detection.hybrid import ActionBands, HybridProfile, RuleWeights, combine_risk

    profile = HybridProfile.from_file("app/detection/hybrid/profiles/rba_calibrated.json")
    ml_probability = None if profile.ml_calibration is None else profile.ml_calibration.probability(raw_ml_score)
    result = combine_risk(ml_probability=ml_probability, hits=rule_engine_evaluation.hits, weights=profile.weights, bands=profile.bands)
    print(result.score, result.action, [c.source for c in result.contributions[:3]])

Cách hiệu chỉnh trọng số/ngưỡng từ RBA và số đo: `ml/rba/hybrid_calibrate.py`, tài liệu `docs/hybrid-risk-engine.md`.
CHƯA nối vào `app/detection/pipeline.py` — việc đó cùng phần nạp model theo phiên bản là của MR12.
"""

from app.detection.hybrid.calibration import ACTIONS, HybridConfigError, ActionBands, HybridProfile, MonotonicCalibrator, RuleWeightEntry, RuleWeights
from app.detection.hybrid.combine import REPUTATION_CATEGORY, Contribution, RiskResult, combine_risk, noisy_or

__all__ = [
    "ACTIONS", "ActionBands", "Contribution", "HybridConfigError", "HybridProfile", "MonotonicCalibrator", "REPUTATION_CATEGORY",
    "RiskResult", "RuleWeightEntry", "RuleWeights", "combine_risk", "noisy_or",
]
