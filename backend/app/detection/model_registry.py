"""Bảng `model_registry`: phiên bản model bất thường ĐANG CHẠY (Phase 4.1; MR12 dùng cho `hybrid_cp2`).

`ensure_registered(db)` được gọi lúc khởi động SAU khi `ml_runtime` nạp model: ghi (nếu chưa có) một hàng cho đúng
`model_version` vừa nạp và đánh dấu nó là hàng active DUY NHẤT của `MODEL_NAME` — lịch sử các phiên bản trước được giữ lại
(`is_active=False`). Không nạp được model thì không ghi gì. Không bao giờ raise (không được chặn khởi động)."""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ModelRegistryEntry

logger = logging.getLogger("model_registry")

MODEL_NAME = "isolation_forest"


def get_active(db: Session, name: str = MODEL_NAME) -> ModelRegistryEntry | None:
    return db.execute(select(ModelRegistryEntry).where(ModelRegistryEntry.name == name, ModelRegistryEntry.is_active.is_(True))).scalars().first()


def ensure_registered(db: Session, runtime=None) -> ModelRegistryEntry | None:
    from app.detection import ml_runtime

    runtime = runtime or ml_runtime.get_runtime()
    try:
        if not runtime.available:
            logger.warning("model bất thường chưa nạp được (%s) — không ghi model_registry", runtime.last_load_error)
            return None
        meta = runtime.model.metadata
        rows = db.execute(select(ModelRegistryEntry).where(ModelRegistryEntry.name == meta["model_name"])).scalars().all()
        entry = next((r for r in rows if r.version == meta["model_version"]), None)
        if entry is None:
            entry = ModelRegistryEntry(
                name=meta["model_name"], version=meta["model_version"], artifact_path=str(runtime.artifact_dir),
                profile_path=None, feature_signature=meta["feature_signature"], is_active=True,
            )
            db.add(entry)
        for r in rows:
            r.is_active = r is entry
        entry.is_active = True
        db.commit()
        logger.info("model_registry: %s/%s đang active (%s)", entry.name, entry.version, entry.artifact_path)
        return entry
    except Exception:  # noqa: BLE001
        logger.exception("lỗi khi ghi model_registry — model vẫn chạy, chỉ thiếu bản ghi phiên bản")
        db.rollback()
        return None
