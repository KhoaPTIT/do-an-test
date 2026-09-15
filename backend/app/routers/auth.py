"""POST /login — đăng nhập web app mẫu (nhiệm vụ 2.1).

Đường nhanh: CHỈ xác thực mật khẩu rồi trả response ngay. Toàn bộ detection
engine (GeoIP, rule tầng 1, risk score tầng 2, baseline...) chạy BẤT ĐỒNG BỘ
ở app/detection/pipeline.py (nhiệm vụ 5.2) — không còn chặn thời gian phản
hồi. Không log payload ở đâu (không print/logging.debug request) để mật
khẩu không bao giờ lộ ra dạng plain text trong log hệ thống.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.detection.pipeline import run_detection_pipeline
from app.models import User
from app.schemas import LoginRequest, LoginResponse
from app.security import verify_password

router = APIRouter()


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, request: Request, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()

    # So khớp hash chứ không so plain text.
    success = verify_password(payload.password, user.password_hash) if user else False

    background_tasks.add_task(
        run_detection_pipeline,
        username=payload.username,
        user_id=user.id if user else None,
        success=success,
        ip=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent"),
        timestamp=datetime.now(timezone.utc),
    )

    if success:
        return LoginResponse(success=True, message="Login successful")

    # Thông báo giống hệt nhau cho "sai mật khẩu" và "tài khoản không tồn tại"
    # để không lộ thông tin tài khoản có tồn tại hay không (docs/api-contract.md mục 3).
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"success": False, "message": "Invalid username or password"},
    )
