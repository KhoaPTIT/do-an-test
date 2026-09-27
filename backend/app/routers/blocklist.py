"""GET /blocklist — danh sách khoá tạm/chặn hiện có (tự động từ MR16 khi risk engine đề xuất `lock`, thủ công từ MR9)
cho quản trị viên xem. DELETE /blocklist/{id} — "nút mở khoá" (checklist MR16): gỡ một mục chặn TRƯỚC hạn dùng.

Yêu cầu JWT admin hợp lệ (nhiệm vụ 5.1) — xem app/dependencies.py.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_admin
from app.detection.rule_engine_runtime import invalidate_blocklist_cache
from app.models import AuditLog, BlocklistEntry
from app.schemas import BlocklistEntryOut, PaginatedBlocklist

router = APIRouter()


@router.get("/blocklist", response_model=PaginatedBlocklist)
def list_blocklist(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    active_only: bool = Query(True, description="Chỉ hiện mục còn hiệu lực (chưa hết hạn) — bỏ để xem cả lịch sử đã hết hạn."),
    db: Session = Depends(get_db),
    _admin: dict = Depends(require_admin),
):
    query = db.query(BlocklistEntry)
    if active_only:
        now = datetime.now(timezone.utc)
        query = query.filter((BlocklistEntry.expires_at.is_(None)) | (BlocklistEntry.expires_at > now))
    query = query.order_by(BlocklistEntry.created_at.desc())

    total = query.count()
    items = query.offset((page - 1) * page_size).limit(page_size).all()
    return PaginatedBlocklist(items=items, total=total, page=page, page_size=page_size)


@router.delete("/blocklist/{entry_id}", status_code=204)
def unlock_blocklist_entry(entry_id: int, db: Session = Depends(get_db), admin: dict = Depends(require_admin)):
    entry = db.get(BlocklistEntry, entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Không thấy mục chặn")

    # Ghi lại TOÀN BỘ chi tiết vào audit log TRƯỚC KHI xoá — xoá hàng thật (giống Blocklist.remove() trong bộ nhớ,
    # app/detection/engine/intel.py) nên đây là nơi DUY NHẤT thông tin mục chặn còn được lưu lại sau khi mở khoá.
    db.add(AuditLog(
        actor=admin.get("username", "admin"), action="unlock", target_type="blocklist", target_id=entry.id,
        detail={"kind": entry.kind, "value": entry.value, "reason": entry.reason, "added_by": entry.added_by,
                "expires_at": entry.expires_at.isoformat() if entry.expires_at else None},
    ))
    db.delete(entry)
    db.commit()
    invalidate_blocklist_cache()
