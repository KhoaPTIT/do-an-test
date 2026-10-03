"""GET /ml/status — trạng thái model bất thường đang chạy (Phase 4.1): đã nạp chưa, phiên bản, ngưỡng, chữ ký đặc trưng,
artifact, lỗi nạp gần nhất. Yêu cầu JWT admin. Không trả dữ liệu đăng nhập nào."""

from fastapi import APIRouter, Depends

from app.dependencies import require_admin

router = APIRouter()


@router.get("/ml/status")
def ml_status(_admin: dict = Depends(require_admin)) -> dict:
    from app.detection import ml_runtime

    return ml_runtime.get_runtime().status()
