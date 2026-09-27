"""Cấu hình đã hiệu chỉnh của hybrid risk engine (MR11): xác suất luật, đường cong hiệu chỉnh mô hình ML, ngưỡng hành động.

Mọi kiểu ở đây chỉ là DỮ LIỆU (đọc/ghi JSON, kiểm tra hợp lệ) — việc TÍNH ra chúng từ RBA nằm ở `ml/rba/hybrid_calibrate.py`
(mirror của `app/detection/engine/registry.RuleConfig` <- `ml/rba/rule_tuning.py`). `combine.py` dùng các kiểu này để chấm.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import numpy as np

ACTIONS = ("allow", "alert", "step_up", "lock")
DEFAULT_WEIGHT = 0.05  # chưa hiệu chỉnh được trên RBA (xem RuleWeights.weight_of): coi là bằng chứng YẾU, không phải "không có ý nghĩa"
DEFAULT_OVERRIDE_RULE_IDS = frozenset({"blocklist_hit"})


class HybridConfigError(ValueError):
    """Hồ sơ hybrid risk engine sai định dạng hoặc ngoài khoảng hợp lệ."""


@dataclass(frozen=True)
class MonotonicCalibrator:
    """Hàm bậc thang tuyến tính từng đoạn, ĐƠN ĐIỆU KHÔNG GIẢM: điểm thô của mô hình -> xác suất tấn công đã hiệu chỉnh.

    Học bằng hồi quy isotonic trên val (`ml.rba.ensemble.IsotonicCalibrator`, MR6) rồi xuất lại thành một dãy điểm gãy
    (`xs`, `ys`) — nội suy tuyến tính giữa các điểm gãy xấp xỉ rất sát hàm bậc thang gốc nhưng không cần scikit-learn hay
    tệp .joblib lúc chấm điểm thật (chỉ JSON thuần + numpy, giống triết lý `RuleConfig` của rule engine)."""

    xs: tuple[float, ...]
    ys: tuple[float, ...]

    def __post_init__(self) -> None:
        if len(self.xs) != len(self.ys) or len(self.xs) < 2:
            raise HybridConfigError("cần ít nhất 2 điểm gãy, xs và ys phải cùng độ dài")
        if any(b <= a for a, b in zip(self.xs, self.xs[1:])):
            raise HybridConfigError("xs phải tăng NGẶT")
        if any(b < a for a, b in zip(self.ys, self.ys[1:])):
            raise HybridConfigError("ys phải không giảm (đơn điệu) — hàm phải luôn tăng hoặc giữ nguyên")
        if min(self.ys) < 0.0 or max(self.ys) > 1.0:
            raise HybridConfigError("ys phải nằm trong [0, 1] (là xác suất)")

    def probability(self, scores):
        """Nội suy `xs -> ys`; ngoài hai đầu thì giữ nguyên giá trị biên (không ngoại suy). Nhận số hoặc mảng, trả đúng kiểu đó."""
        scalar = np.isscalar(scores)
        values = np.clip(np.interp(np.atleast_1d(np.asarray(scores, dtype=float)), self.xs, self.ys, left=self.ys[0], right=self.ys[-1]), 0.0, 1.0)
        return float(values[0]) if scalar else values

    def to_dict(self) -> dict[str, Any]:
        return {"xs": list(self.xs), "ys": list(self.ys)}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "MonotonicCalibrator":
        try:
            return cls(tuple(float(x) for x in data["xs"]), tuple(float(y) for y in data["ys"]))
        except (KeyError, TypeError) as exc:
            raise HybridConfigError(f"đường hiệu chỉnh sai định dạng: {exc}") from exc


@dataclass(frozen=True)
class RuleWeightEntry:
    """Trọng số của MỘT luật: xác suất coi lần khớp của luật này là tấn công NẾU CHỈ MỘT MÌNH nó xuất hiện (dùng làm p_i
    trong noisy-OR — xem `combine.noisy_or`). `calibrated=False` nghĩa là đo được trên RBA (ví dụ luật cần IP/danh sách
    thật mà RBA không có) nên `weight` chỉ là giá trị đặt trước (`DEFAULT_WEIGHT`), không phải số đo."""

    weight: float
    calibrated: bool
    n: int = 0  # số dòng luật khớp dùng để đo (0 nếu calibrated=False)
    ci95: tuple[float, float] | None = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.weight <= 1.0:
            raise HybridConfigError(f"trọng số {self.weight} phải trong [0, 1]")
        if self.n < 0:
            raise HybridConfigError("n phải >= 0")
        if self.ci95 is not None and self.ci95[0] > self.ci95[1]:
            raise HybridConfigError("ci95 phải là (thấp, cao) với thấp <= cao")

    def to_dict(self) -> dict[str, Any]:
        return {"weight": self.weight, "calibrated": self.calibrated, "n": self.n, "ci95": None if self.ci95 is None else list(self.ci95)}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RuleWeightEntry":
        try:
            ci = data.get("ci95")
            return cls(float(data["weight"]), bool(data["calibrated"]), int(data.get("n", 0)), None if ci is None else (float(ci[0]), float(ci[1])))
        except (KeyError, TypeError, IndexError) as exc:
            raise HybridConfigError(f"trọng số luật sai định dạng: {exc}") from exc


@dataclass(frozen=True)
class RuleWeights:
    """Trọng số của mọi luật + danh sách luật GHI ĐÈ (khớp là kết luận ngay, không qua noisy-OR — dành cho quyết định của
    con người như blocklist, không phải bằng chứng xác suất) + trọng số mặc định cho luật không có trong `entries`."""

    entries: Mapping[str, RuleWeightEntry] = field(default_factory=dict)
    override_rule_ids: frozenset[str] = DEFAULT_OVERRIDE_RULE_IDS
    default_weight: float = DEFAULT_WEIGHT

    def __post_init__(self) -> None:
        if not 0.0 <= self.default_weight <= 1.0:
            raise HybridConfigError(f"trọng số mặc định {self.default_weight} phải trong [0, 1]")

    def weight_of(self, rule_id: str) -> float:
        entry = self.entries.get(rule_id)
        return self.default_weight if entry is None else entry.weight

    def to_dict(self) -> dict[str, Any]:
        return {
            "weights": {rule_id: entry.to_dict() for rule_id, entry in self.entries.items()},
            "override_rule_ids": sorted(self.override_rule_ids),
            "default_weight": self.default_weight,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RuleWeights":
        try:
            entries = {rule_id: RuleWeightEntry.from_dict(entry) for rule_id, entry in data.get("weights", {}).items()}
            override = frozenset(data.get("override_rule_ids", DEFAULT_OVERRIDE_RULE_IDS))
            default_weight = float(data.get("default_weight", DEFAULT_WEIGHT))
        except (TypeError, AttributeError) as exc:
            raise HybridConfigError(f"trọng số luật sai định dạng: {exc}") from exc
        return cls(entries, override, default_weight)


@dataclass(frozen=True)
class ActionBands:
    """Ba điểm cắt trên thang 0–100 chia bốn hành động: dưới `alert_at` là `allow`; [alert_at, step_up_at) là `alert`
    (hiện trong bảng điều khiển, không cản người dùng); [step_up_at, lock_at) là `step_up` (yêu cầu xác thực thêm);
    từ `lock_at` trở lên là `lock` (khoá tạm) — cũng là hành động khi một luật GHI ĐÈ khớp, bất kể điểm."""

    alert_at: int
    step_up_at: int
    lock_at: int

    def __post_init__(self) -> None:
        for name, value in (("alert_at", self.alert_at), ("step_up_at", self.step_up_at), ("lock_at", self.lock_at)):
            if not 0 <= value <= 100:
                raise HybridConfigError(f"{name}={value} phải trong [0, 100]")
        if not self.alert_at < self.step_up_at < self.lock_at:
            raise HybridConfigError(f"cần alert_at < step_up_at < lock_at (nhận {self.alert_at}, {self.step_up_at}, {self.lock_at})")

    def classify(self, score: int) -> str:
        if score >= self.lock_at:
            return "lock"
        if score >= self.step_up_at:
            return "step_up"
        if score >= self.alert_at:
            return "alert"
        return "allow"

    def to_dict(self) -> dict[str, int]:
        return {"alert_at": self.alert_at, "step_up_at": self.step_up_at, "lock_at": self.lock_at}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ActionBands":
        try:
            return cls(int(data["alert_at"]), int(data["step_up_at"]), int(data["lock_at"]))
        except (KeyError, TypeError) as exc:
            raise HybridConfigError(f"ngưỡng hành động sai định dạng: {exc}") from exc


@dataclass(frozen=True)
class HybridProfile:
    """Hồ sơ đầy đủ để chấm điểm: trọng số luật, ngưỡng hành động, đường hiệu chỉnh mô hình (None nếu chưa có/không dùng
    thành phần ML — `combine_risk` khi đó chỉ gộp luật và danh tiếng, giống triết lý "model không khả dụng thì bỏ qua,
    không chặn luồng" của `app/detection/ml_model.py`)."""

    weights: RuleWeights
    bands: ActionBands
    ml_calibration: MonotonicCalibrator | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"rule_weights": self.weights.to_dict(), "bands": self.bands.to_dict(), "ml_calibration": None if self.ml_calibration is None else self.ml_calibration.to_dict()}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "HybridProfile":
        if not isinstance(data, Mapping) or set(data) - {"rule_weights", "bands", "ml_calibration"}:
            raise HybridConfigError("hồ sơ chỉ có khoá 'rule_weights', 'bands', 'ml_calibration'")
        if "bands" not in data:
            raise HybridConfigError("hồ sơ thiếu khoá bắt buộc 'bands'")
        calibration = data.get("ml_calibration")
        return cls(RuleWeights.from_dict(data.get("rule_weights", {})), ActionBands.from_dict(data["bands"]), None if calibration is None else MonotonicCalibrator.from_dict(calibration))

    @classmethod
    def from_file(cls, path: str | Path) -> "HybridProfile":
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise HybridConfigError(f"hồ sơ không phải JSON hợp lệ: {exc}") from exc
        return cls.from_dict(data)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
