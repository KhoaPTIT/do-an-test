"""GET /model-health — checklist MR17 "sức khoẻ model (drift, phiên bản)": danh sách phiên bản đã đăng ký
(`model_registry`, MR12) + trôi đặc trưng (PSI, `ml/rba/drift.py`, MR12) giữa dữ liệu train RBA và `login_events` THẬT
hiện tại — MR12 đã tính đây là một phân tích NGOẠI TUYẾN một lần (`python -m ml.rba.drift`); giờ có endpoint để dashboard
xem trực tiếp.

⚠️ Tính PSI cần đọc file parquet train RBA (không đổi khi chạy — cache VĨNH VIỄN trong tiến trình, không TTL) VÀ tính
lại đặc trưng RBA cho `login_events` thật (`is_synthetic=False`) — KHÔNG rẻ như `refresh_blocklist`/`refresh_rule_config`
(vài round-trip DB/dòng, xem `docs/realtime-integration.md`). Đo trực tiếp lúc dựng MR17: KHÔNG giới hạn số dòng khiến
request treo >30 GIÂY trên ~1.500 dòng thật đã tích luỹ — giới hạn `CURRENT_ROWS_LIMIT` (300 dòng GẦN NHẤT) đưa xuống
còn ~2 giây (chi tiết `docs/dashboard-v2.md`). Cache TTL DÀI (mặc định 10 phút, khác hẳn 15 giây của blocklist/rule
config, vì trôi đặc trưng không đổi nhanh) + `?refresh=true` để quản trị viên chủ động tính lại ngay khi cần.

Yêu cầu JWT admin hợp lệ (nhiệm vụ 5.1).
"""

import math
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_admin
from app.models import ModelRegistryEntry
from app.schemas import FeatureDriftOut, ModelHealthOut, ModelVersionOut

router = APIRouter()

DRIFT_CACHE_TTL_SECONDS = 600.0
TOP_N_FEATURES = 15
# Mỗi dòng tốn vài round-trip DB (compute_rba_features) — đo trực tiếp: ~1.500 dòng khiến request treo >30s. Giới hạn
# ở ĐÂY (endpoint LIVE, admin đang chờ), KHÔNG giới hạn ở CLI script (python -m ml.rba.drift, chạy tay, chờ được).
CURRENT_ROWS_LIMIT = 300

_drift_cache: ModelHealthOut | None = None  # chỉ phần drift được cache — versions luôn đọc DB mới (rẻ)
_drift_cached_at = -math.inf  # -inf, không phải -1.0 — lý do ở app/detection/rule_engine_runtime.py (_blocklist_cached_at)
_reference_frame_cache = None  # pd.DataFrame train RBA — KHÔNG đổi khi tiến trình đang chạy, cache vĩnh viễn (không TTL)


def invalidate_drift_cache() -> None:
    """Xoá cache DRIFT (không đụng `_reference_frame_cache` — file train RBA không đổi, xem docstring module). Gọi
    trong test setup (`conftest.py`) để một test không đọc nhầm kết quả đã cache từ DB của test KHÁC (TTL 600s dài hơn
    nhiều so với thời gian chạy một bộ test, nên rất dễ rò rỉ nếu không xoá)."""
    global _drift_cached_at
    _drift_cached_at = -math.inf


def _get_reference_frame():
    global _reference_frame_cache
    if _reference_frame_cache is None:
        from ml.rba.drift import reference_frame

        _reference_frame_cache = reference_frame()
    return _reference_frame_cache


def _compute_drift(db: Session) -> tuple[datetime, bool, int, int, list[FeatureDriftOut]]:
    import numpy as np

    from ml.rba.drift import current_frame, psi_report

    reference = _get_reference_frame()
    current = current_frame(db=db, limit=CURRENT_ROWS_LIMIT)
    rows = psi_report(reference, current)[:TOP_N_FEATURES]
    top_features = [
        FeatureDriftOut(feature=r.feature, psi=None if np.isnan(r.psi) else r.psi, verdict=r.verdict, n_reference=r.n_reference, n_current=r.n_current)
        for r in rows
    ]
    low_confidence = rows[0].low_confidence if rows else True
    n_reference = rows[0].n_reference if rows else 0
    n_current = rows[0].n_current if rows else 0
    return datetime.now(timezone.utc), low_confidence, n_reference, n_current, top_features


@router.get("/model-health", response_model=ModelHealthOut)
def get_model_health(
    refresh: bool = Query(False, description="Bỏ qua cache TTL, tính lại drift ngay (chậm — quét lại toàn bộ login_events thật)"),
    db: Session = Depends(get_db),
    _admin: dict = Depends(require_admin),
):
    global _drift_cache, _drift_cached_at

    versions = [ModelVersionOut.model_validate(row) for row in db.query(ModelRegistryEntry).order_by(ModelRegistryEntry.id.desc()).all()]

    now = time.monotonic()
    if refresh or _drift_cache is None or now - _drift_cached_at >= DRIFT_CACHE_TTL_SECONDS:
        computed_at, low_confidence, n_reference, n_current, top_features = _compute_drift(db)
        _drift_cache = ModelHealthOut(
            versions=[], drift_computed_at=computed_at, drift_low_confidence=low_confidence,
            drift_n_reference=n_reference, drift_n_current=n_current, drift_top_features=top_features,
        )
        _drift_cached_at = now

    return ModelHealthOut(
        versions=versions, drift_computed_at=_drift_cache.drift_computed_at, drift_low_confidence=_drift_cache.drift_low_confidence,
        drift_n_reference=_drift_cache.drift_n_reference, drift_n_current=_drift_cache.drift_n_current, drift_top_features=_drift_cache.drift_top_features,
    )
