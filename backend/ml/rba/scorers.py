"""Sổ đăng ký mô hình/luật chấm điểm cho khung đánh giá (MR4–MR6).

Mỗi mục là một "nhà máy" nhận toàn bộ bảng đặc trưng (để các mô hình có tham số tự học từ phân vùng `train`)
và trả về hàm `frame -> điểm` (càng cao càng đáng ngờ, không NaN). MR6 bổ sung LightGBM và hybrid vào đây.
"""

from __future__ import annotations

from typing import Callable

import numpy as np
import pandas as pd

from ml.rba import baselines
from ml.rba.eval_tasks import Scorer
from ml.rba.features import FREEMAN_ATTRS


def random_scorer(seed: int = 0) -> Scorer:
    """Điểm ngẫu nhiên: đường cơ sở tuyệt đối — ROC-AUC phải ≈ 0,5, PR-AUC ≈ tỉ lệ dương tính."""

    def score(frame: pd.DataFrame) -> np.ndarray:
        return np.random.default_rng(seed).random(len(frame))

    return score


SCORER_FACTORIES: dict[str, Callable[[pd.DataFrame], Scorer]] = {
    "random": lambda df: random_scorer(),
    "freeman_all": lambda df: baselines.freeman_scorer(),
    "freeman_no_ip": lambda df: baselines.freeman_scorer(tuple(a for a in FREEMAN_ATTRS if a != "ip")),
    "tier2_current": lambda df: baselines.tier2_scorer(),
    "rules_tuned": lambda df: baselines.fit_tuned_rules(df),
    "isolation_forest": lambda df: baselines.IsolationForestScorer().fit(df),
}
