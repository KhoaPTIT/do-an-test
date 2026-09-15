"""GET /login-events — bảng log phân trang cho dashboard (nhiệm vụ 4.3).

Yêu cầu JWT admin hợp lệ (nhiệm vụ 5.1) — xem app/dependencies.py.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_admin
from app.models import LoginEvent
from app.schemas import PaginatedLoginEvents

router = APIRouter()


@router.get("/login-events", response_model=PaginatedLoginEvents)
def list_login_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    _admin: dict = Depends(require_admin),
):
    query = db.query(LoginEvent).order_by(LoginEvent.created_at.desc())
    total = query.count()
    items = query.offset((page - 1) * page_size).limit(page_size).all()
    return PaginatedLoginEvents(items=items, total=total, page=page, page_size=page_size)
