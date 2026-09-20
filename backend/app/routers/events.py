"""GET /login-events — bảng log phân trang cho dashboard (nhiệm vụ 4.3),
có bộ lọc (nâng cấp thêm sau Tuần 7 — dashboard thật cần lọc được khi log
đã lên tới hàng nghìn bản ghi).

Yêu cầu JWT admin hợp lệ (nhiệm vụ 5.1) — xem app/dependencies.py.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_admin
from app.detection.scoring import LOW_RISK_MAX, MEDIUM_RISK_MAX
from app.models import LoginEvent
from app.schemas import PaginatedLoginEvents

router = APIRouter()


@router.get("/login-events", response_model=PaginatedLoginEvents)
def list_login_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    username: str | None = Query(None, description="Lọc gần đúng theo username (không phân biệt hoa/thường)"),
    success: bool | None = Query(None, description="Lọc theo kết quả đăng nhập"),
    risk_level: str | None = Query(None, pattern="^(low|medium|high)$", description="low | medium | high — theo ngưỡng mục 4.2"),
    is_synthetic: bool | None = Query(None, description="True = chỉ dữ liệu giả lập, False = chỉ dữ liệu thật"),
    db: Session = Depends(get_db),
    _admin: dict = Depends(require_admin),
):
    query = db.query(LoginEvent)

    if username:
        query = query.filter(LoginEvent.attempted_username.ilike(f"%{username}%"))
    if success is not None:
        query = query.filter(LoginEvent.success.is_(success))
    if is_synthetic is not None:
        query = query.filter(LoginEvent.is_synthetic.is_(is_synthetic))
    if risk_level == "low":
        query = query.filter(LoginEvent.risk_score.isnot(None), LoginEvent.risk_score < LOW_RISK_MAX)
    elif risk_level == "medium":
        query = query.filter(LoginEvent.risk_score >= LOW_RISK_MAX, LoginEvent.risk_score <= MEDIUM_RISK_MAX)
    elif risk_level == "high":
        query = query.filter(LoginEvent.risk_score > MEDIUM_RISK_MAX)

    query = query.order_by(LoginEvent.created_at.desc())
    total = query.count()
    items = query.offset((page - 1) * page_size).limit(page_size).all()
    return PaginatedLoginEvents(items=items, total=total, page=page, page_size=page_size)
