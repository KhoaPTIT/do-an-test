"""Kết hợp mô hình, hiệu chỉnh xác suất và chọn ngưỡng theo mục tiêu (MR6).

Ba công cụ:

1. `EcdfCalibrator` — đổi điểm thô của một mô hình thành "xác suất đuôi": tỉ lệ đăng nhập HỢP LỆ (trọng số dân số)
   có điểm ≥ s. Đó chính là tỉ lệ báo nhầm nếu đặt ngưỡng tại s, nên hai mô hình có thang điểm khác hẳn nhau (log-odds
   của LightGBM, khoảng cách của kNN...) so sánh và kết hợp được với nhau. Học chỉ từ các dòng hợp lệ của `val`.
2. `HybridMinTail` — cảnh báo khi BẤT KỲ bộ phát hiện nào báo động: điểm = −log10(min xác suất đuôi). Mỗi bộ phát hiện
   có thể có "cổng" (ví dụ mô hình chiếm tài khoản chỉ áp dụng cho đăng nhập thành công). Khi các bộ phát hiện chia ngân
   sách báo nhầm, tổng báo nhầm ≤ tổng các phần — cách kết hợp đơn giản, giải thích được và không cần nhãn chung.
3. `IsotonicCalibrator` — đổi điểm thành XÁC SUẤT có ý nghĩa (theo tỉ lệ tấn công của tập hiệu chỉnh) bằng hồi quy đơn điệu.

Chọn ngưỡng (`threshold_for_fpr`, `realized_rates`) chỉ cần các dòng âm tính của `val`; thử chuyển ngưỡng sang
`test`/`late` cho biết tỉ lệ báo nhầm thực tế khi phân phối trôi.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression

from ml.rba import metrics as M

TAIL_FLOOR = 1e-7

Gate = Callable[[pd.DataFrame], np.ndarray]
Scorer = Callable[[pd.DataFrame], np.ndarray]


def gate_success(frame: pd.DataFrame) -> np.ndarray:
    """Cổng "chỉ đăng nhập thành công": chiếm tài khoản chỉ xảy ra với đăng nhập đã qua bước mật khẩu."""
    return frame["cur_success"].to_numpy(dtype=float) == 1.0


def gate_success_with_history(frame: pd.DataFrame) -> np.ndarray:
    """Cổng cho mô hình học từ kẻ tấn công mô phỏng: đăng nhập thành công VÀ tài khoản đã có lịch sử thành công.
    Mô hình chưa bao giờ thấy tài khoản mới (xem models.simulated_attacker_sets) nên không được phép phán ở đó."""
    return (frame["cur_success"].to_numpy(dtype=float) == 1.0) & (frame["u_n_success"].to_numpy(dtype=float) >= 1.0)


@dataclass
class EcdfCalibrator:
    reference: M.NegativeReference

    @classmethod
    def fit(cls, scores: np.ndarray, weights: np.ndarray | None = None) -> "EcdfCalibrator":
        scores = np.asarray(scores, dtype=float)
        weights = np.ones(len(scores)) if weights is None else np.asarray(weights, dtype=float)
        return cls(M.NegativeReference.build(scores, weights))

    def tail(self, scores: np.ndarray) -> np.ndarray:
        """Tỉ lệ đăng nhập hợp lệ (có trọng số) có điểm >= scores; nằm trong [TAIL_FLOOR, 1]."""
        return np.maximum(self.reference.fpr_at(np.asarray(scores, dtype=float)), TAIL_FLOOR)


@dataclass
class Component:
    name: str
    scorer: Scorer
    calibrator: EcdfCalibrator
    gate: Gate | None = None  # dòng không qua cổng không bị bộ phát hiện này báo động (đuôi = 1)


class HybridMinTail:
    """Điểm = −log10(min xác suất đuôi của các bộ phát hiện). Cao hơn = đáng ngờ hơn; 2 nghĩa là "hiếm hơn 1% đăng
    nhập hợp lệ" ở ít nhất một bộ phát hiện."""

    def __init__(self, components: list[Component]):
        self.components = components

    def _tails(self, frame: pd.DataFrame) -> np.ndarray:
        columns = []
        for component in self.components:
            tail = component.calibrator.tail(component.scorer(frame))
            if component.gate is not None:
                tail = np.where(component.gate(frame), tail, 1.0)
            columns.append(tail)
        return np.column_stack(columns)

    def __call__(self, frame: pd.DataFrame) -> np.ndarray:
        return -np.log10(self._tails(frame).min(axis=1))

    def triggered_by(self, frame: pd.DataFrame) -> np.ndarray:
        """Tên bộ phát hiện có xác suất đuôi nhỏ nhất của từng dòng (dùng để gán loại cảnh báo ở MR13)."""
        names = np.array([c.name for c in self.components])
        return names[self._tails(frame).argmin(axis=1)]


@dataclass
class IsotonicCalibrator:
    model: IsotonicRegression

    @classmethod
    def fit(cls, scores: np.ndarray, y: np.ndarray, weights: np.ndarray | None = None) -> "IsotonicCalibrator":
        model = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip", increasing=True)
        model.fit(np.asarray(scores, dtype=float), np.asarray(y, dtype=float), sample_weight=weights)
        return cls(model)

    def probability(self, scores: np.ndarray) -> np.ndarray:
        return self.model.predict(np.asarray(scores, dtype=float))


def reliability_table(prob: np.ndarray, y: np.ndarray, weights: np.ndarray, bins: int = 10) -> list[dict]:
    """Chia dòng theo phân vị của xác suất dự đoán; so xác suất trung bình dự đoán với tỉ lệ tấn công thực (có trọng số)."""
    prob, y, weights = (np.asarray(a, dtype=float) for a in (prob, y, weights))
    order = np.argsort(prob, kind="mergesort")
    edges = np.linspace(0, len(prob), bins + 1).astype(int)
    rows = []
    for lo, hi in zip(edges[:-1], edges[1:]):
        idx = order[lo:hi]
        w = weights[idx]
        rows.append(
            {
                "predicted": float((prob[idx] * w).sum() / w.sum()),
                "observed": float((y[idx] * w).sum() / w.sum()),
                "weight_share": float(w.sum() / weights.sum()),
            }
        )
    return rows


def brier_score(prob: np.ndarray, y: np.ndarray, weights: np.ndarray) -> float:
    prob, y, weights = (np.asarray(a, dtype=float) for a in (prob, y, weights))
    return float((weights * (prob - y) ** 2).sum() / weights.sum())


def threshold_for_fpr(neg_scores: np.ndarray, neg_weights: np.ndarray, fpr_target: float) -> float:
    """Ngưỡng thấp nhất sao cho cảnh báo khi điểm > ngưỡng có FPR <= fpr_target trên tập âm tính cho trước."""
    ref = M.NegativeReference.build(np.asarray(neg_scores, dtype=float), np.asarray(neg_weights, dtype=float))
    return ref.exceeding_score(fpr_target)


def realized_rates(scores: np.ndarray, y: np.ndarray, weights: np.ndarray, threshold: float) -> dict:
    """Tỉ lệ báo nhầm (âm tính) và recall (dương tính) thực tế khi dùng ngưỡng đã chọn trên tập khác."""
    scores, y, weights = np.asarray(scores, dtype=float), np.asarray(y, dtype=bool), np.asarray(weights, dtype=float)
    flagged = scores > threshold
    neg_total = weights[~y].sum()
    pos_total = weights[y].sum()
    return {
        "fpr": float(weights[~y & flagged].sum() / neg_total) if neg_total > 0 else None,
        "recall": float(weights[y & flagged].sum() / pos_total) if pos_total > 0 else None,
    }
