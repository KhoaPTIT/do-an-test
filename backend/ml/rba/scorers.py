"""Sổ đăng ký mô hình/luật chấm điểm cho khung đánh giá (MR4–MR6).

Mỗi mục là một "nhà máy" nhận toàn bộ bảng đặc trưng (để các mô hình có tham số tự học từ phân vùng `train`)
và trả về hàm `frame -> điểm` (càng cao càng đáng ngờ, không NaN). MR6 bổ sung LightGBM và hybrid vào đây.
"""

from __future__ import annotations

from typing import Callable

import joblib
import numpy as np
import pandas as pd

from ml.rba import baselines, models
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


def _artifact(name: str) -> Callable[[pd.DataFrame], Scorer]:
    """Nạp mô hình đã huấn luyện bởi `python -m ml.rba.train` (LightGBM lưu .txt/.json, còn lại .joblib)."""

    def factory(df: pd.DataFrame) -> Scorer:
        if (models.ARTIFACT_DIR / f"{name}.txt").exists():
            return models.GbmScorer.load(name)
        path = models.ARTIFACT_DIR / f"{name}.joblib"
        if path.exists():
            return joblib.load(path)
        raise FileNotFoundError(f"Chưa có mô hình {name} — chạy `python -m ml.rba.train` trước")

    return factory


for _name in ("gbm_attack_ip", "gbm_attacker_sim", "gbm_combined", "gbm_combined_global", "knn_distance", "autoencoder", "hybrid"):
    SCORER_FACTORIES[_name] = _artifact(_name)

# Mô hình chốt ở CP2 (ml/rba/selection.py): cùng vai trò với bản MR6 nhưng đặc trưng đã chọn lại; đứng cạnh bản MR6 để so trước/sau
for _name in ("gbm_attack_ip_cp2", "gbm_attacker_sim_cp2", "isolation_forest_cp2", "hybrid_cp2"):
    SCORER_FACTORIES[_name] = _artifact(_name)
