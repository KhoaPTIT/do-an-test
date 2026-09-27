"""Hybrid risk engine (MR11): gộp xác suất ML đã hiệu chỉnh, kết quả luật và danh tiếng hạ tầng thành MỘT điểm 0–100 và
MỘT hành động — noisy-OR có trọng số, cộng luật GHI ĐÈ cho quyết định chắc chắn (blocklist).

Vì sao noisy-OR chứ không phải "luật HOẶC mô hình" (gộp cảnh báo): MR10 (`docs/rule-ml-overlap.md`) đo trực tiếp trên RBA
rằng gộp kiểu "bất kỳ bên nào báo là báo" không tăng recall so với chỉ nới ngưỡng của một mình mô hình đến cùng tổng báo
nhầm — tăng báo nhầm mà không tăng phát hiện. Noisy-OR CÓ TRỌNG SỐ coi mỗi bằng chứng là một xác suất độc lập
(`RuleWeights`, hiệu chỉnh ở `ml/rba/hybrid_calibrate.py`): luật ồn (đa số các luật khi đứng một mình, theo MR10) tự động
đóng góp ít vì trọng số thấp, luật đáng tin đóng góp nhiều — không cần đặt tay "luật nào được tính".

Luật SHADOW vẫn là bằng chứng ở đây: chế độ shadow (`RuleSpec.default_mode`) chỉ quyết định RuleEngine có tự tạo cảnh báo
hay không (xem app/detection/engine/engine.py), không phải luật đó vô giá trị — trọng số calibrate đã phản ánh đúng độ
tin cậy của nó, tách biệt khỏi quyết định "có tự động phiền người dùng hay không" của rule engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from app.detection.engine.registry import CATEGORIES, REGISTRY, RuleSpec
from app.detection.engine.types import RuleHit
from app.detection.hybrid.calibration import ActionBands, RuleWeights

REPUTATION_CATEGORY = "Danh tiếng hạ tầng"
assert REPUTATION_CATEGORY in CATEGORIES  # lỗi sớm nếu ai đổi tên nhóm trong registry.py mà quên sửa ở đây (test cũng kiểm tra lại)


def noisy_or(probabilities: Iterable[float | None]) -> float:
    """Xác suất ÍT NHẤT MỘT bằng chứng đúng, coi các bằng chứng ĐỘC LẬP: 1 − Π(1 − p_i). `None` = không có bằng chứng đó,
    bị bỏ qua (không phải "chắc chắn không", khác 0.0). Danh sách rỗng hoặc toàn `None` trả 0.0 (không có bằng chứng nào).

    Phân rã đúng nghĩa (không phải xấp xỉ kiểu Shapley/z-score như MR8 dùng để giải thích mô hình ML): trong không gian
    log, log(1 − P) = Σ log(1 − p_i), nên đóng góp CHÍNH XÁC của bằng chứng thứ i vào (1 − P) là thừa số (1 − p_i), không
    phụ thuộc thứ tự cộng vào — `Contribution.weight` chính là p_i này."""
    complement = 1.0
    seen = False
    for p in probabilities:
        if p is None:
            continue
        seen = True
        complement *= 1.0 - min(max(float(p), 0.0), 1.0)
    return 1.0 - complement if seen else 0.0


@dataclass(frozen=True)
class Contribution:
    """Một bằng chứng đã góp vào điểm. `source`: `"ml"` hoặc mã luật. `weight`: xác suất coi bằng chứng này đúng nếu chỉ
    một mình nó xuất hiện (p_i ở trên). `group`: `"ml"` | `"rule"` | `"reputation"`."""

    source: str
    label: str
    weight: float
    group: str


@dataclass(frozen=True)
class RiskResult:
    """Kết quả chấm MỘT lần thử. `contributions` sắp theo `weight` giảm dần — dùng thẳng để giải thích cảnh báo (MR13):
    2–3 mục đầu là "vì sao" chính, đúng tinh thần đã đo độ trung thực ở MR8 (top-k là NGUYÊN NHÂN CHỦ ĐẠO, không phải
    toàn bộ lý do)."""

    score: int  # 0-100
    action: str  # một trong calibration.ACTIONS
    probability: float  # score / 100, giữ độ chính xác đầy đủ (score đã làm tròn để hiển thị)
    ml_probability: float | None
    rule_probability: float
    reputation_probability: float
    overridden_by: str | None  # mã luật đã ghi đè, None nếu không luật nào ghi đè
    contributions: tuple[Contribution, ...]

    @property
    def is_overridden(self) -> bool:
        return self.overridden_by is not None


def combine_risk(
    *,
    ml_probability: float | None,
    hits: Iterable[RuleHit],
    weights: RuleWeights,
    bands: ActionBands,
    registry: Mapping[str, RuleSpec] | None = None,
) -> RiskResult:
    """Chấm MỘT lần thử.

    `ml_probability`: xác suất tấn công ĐÃ HIỆU CHỈNH (0–1, ví dụ qua `MonotonicCalibrator.probability`), hoặc `None` nếu
    mô hình không khả dụng — bỏ qua thành phần này, không chặn luồng (cùng triết lý `app/detection/ml_model.py`).
    `hits`: các luật đã khớp của MỘT lần thử (`Evaluation.hits` — gồm cả luật `shadow`, xem docstring module)."""
    registry = REGISTRY if registry is None else registry
    rule_probs: list[float] = []
    reputation_probs: list[float] = []
    contributions: list[Contribution] = []
    overridden_by: str | None = None
    seen: set[str] = set()

    for hit in hits:
        if hit.rule_id in seen:  # engine chỉ khớp tối đa 1 lần/luật/lần thử; phòng hờ khi gọi trực tiếp với dữ liệu tuỳ ý
            continue
        seen.add(hit.rule_id)
        if overridden_by is None and hit.rule_id in weights.override_rule_ids:
            overridden_by = hit.rule_id
        weight = weights.weight_of(hit.rule_id)
        spec = registry.get(hit.rule_id)
        is_reputation = spec is not None and spec.category == REPUTATION_CATEGORY
        (reputation_probs if is_reputation else rule_probs).append(weight)
        contributions.append(Contribution(hit.rule_id, hit.message, weight, "reputation" if is_reputation else "rule"))

    rule_probability = noisy_or(rule_probs)
    reputation_probability = noisy_or(reputation_probs)
    if ml_probability is not None:
        contributions.append(Contribution("ml", "mô hình học máy", float(ml_probability), "ml"))

    if overridden_by is not None:
        probability = 1.0
    else:
        probability = noisy_or([ml_probability, rule_probability if rule_probs else None, reputation_probability if reputation_probs else None])

    score = min(100, max(0, round(probability * 100)))
    action = "lock" if overridden_by is not None else bands.classify(score)
    contributions.sort(key=lambda c: -c.weight)
    return RiskResult(
        score=score, action=action, probability=probability, ml_probability=ml_probability, rule_probability=rule_probability,
        reputation_probability=reputation_probability, overridden_by=overridden_by, contributions=tuple(contributions),
    )
