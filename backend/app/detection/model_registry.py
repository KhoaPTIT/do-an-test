"""Bảng `model_registry` (MR12: "nạp model theo phiên bản, fallback an toàn"): phiên bản mô hình hybrid đang dùng.

Tự đăng ký (`ensure_registered`) — không cần script nạp riêng: lần đầu khởi động (`app/main.py`), nếu chưa có hàng nào cho
`(HYBRID_NAME, HYBRID_VERSION)` thì tạo một hàng trỏ tới artifact hiện có trên đĩa (`ml/artifacts/rba_cp2/hybrid_cp2.joblib`
+ hồ sơ hiệu chỉnh MR11) và đánh dấu `is_active`. `app/detection/hybrid_runtime.py` đọc hàng active để biết nạp file nào —
đổi phiên bản mô hình sau này chỉ cần thêm một hàng mới rồi cập nhật `is_active`, không phải sửa code.
"""

from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ModelRegistryEntry
from ml.rba.features import feature_signature
from ml.rba.models import ARTIFACT_DIR as ML_ARTIFACT_DIR

logger = logging.getLogger("model_registry")

HYBRID_NAME = "hybrid_cp2"
HYBRID_VERSION = "cp2"
_ARTIFACT_PATH = ML_ARTIFACT_DIR / f"{HYBRID_NAME}.joblib"
_PROFILE_PATH = Path(__file__).resolve().parent / "hybrid" / "profiles" / "rba_calibrated.json"


def get_active(db: Session, name: str = HYBRID_NAME) -> ModelRegistryEntry | None:
    return db.execute(select(ModelRegistryEntry).where(ModelRegistryEntry.name == name, ModelRegistryEntry.is_active.is_(True))).scalars().first()


def ensure_registered(db: Session) -> ModelRegistryEntry | None:
    """Đảm bảo có một hàng active cho `HYBRID_NAME` nếu artifact đã có trên đĩa; không tự raise (gọi ở startup, một lỗi ở
    đây không được chặn cả ứng dụng khởi động — cùng triết lý `app/detection/ml_model.py`)."""
    try:
        existing = get_active(db)
        if existing is not None:
            return existing
        if not _ARTIFACT_PATH.is_file():
            logger.warning("chưa có artifact %s — hybrid risk engine tạm tắt thành phần ML cho tới khi train (python -m ml.rba.selection)", _ARTIFACT_PATH)
            return None
        entry = ModelRegistryEntry(
            name=HYBRID_NAME, version=HYBRID_VERSION, artifact_path=str(_ARTIFACT_PATH),
            profile_path=str(_PROFILE_PATH) if _PROFILE_PATH.is_file() else None,
            feature_signature=feature_signature(), is_active=True,
        )
        db.add(entry)
        db.commit()
        logger.info("đã đăng ký model_registry %s/%s (%s)", HYBRID_NAME, HYBRID_VERSION, _ARTIFACT_PATH)
        return entry
    except Exception:  # noqa: BLE001
        logger.exception("lỗi khi tự đăng ký model_registry — hybrid risk engine tạm tắt thành phần ML")
        db.rollback()
        return None
