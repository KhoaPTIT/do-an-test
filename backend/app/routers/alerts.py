"""GET /alerts — danh sách cảnh báo phân trang cho dashboard (nhiệm vụ 4.3).

Yêu cầu JWT admin hợp lệ (nhiệm vụ 5.1).
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_admin
from app.models import Alert
from app.schemas import PaginatedAlerts

router = APIRouter()

# MR13: mặc định "priority" (novelty × độ tin cậy × importance, alert_intelligence.priority_score) — đúng bullet "xếp
# hạng ưu tiên" của MR13, thay vì luôn mới nhất lên đầu; "recent" giữ lại hành vi CŨ (MR12 trở về trước) cho ai cần.
# NULLS LAST: alert tầng 1-2-3 cũ (trước MR13, không có priority_score) rơi xuống cuối thay vì chen lên đầu vì NULL.
_SORTS = {
    "priority": (Alert.priority_score.desc().nulls_last(), Alert.created_at.desc()),
    "recent": (Alert.created_at.desc(),),
}


@router.get("/alerts", response_model=PaginatedAlerts)
def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    sort: str = Query("priority", pattern="^(priority|recent)$"),
    db: Session = Depends(get_db),
    _admin: dict = Depends(require_admin),
):
    query = db.query(Alert).order_by(*_SORTS[sort])
    total = query.count()
    items = query.offset((page - 1) * page_size).limit(page_size).all()
    return PaginatedAlerts(items=items, total=total, page=page, page_size=page_size)
