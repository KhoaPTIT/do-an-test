"""POST /login — đăng nhập web app mẫu (nhiệm vụ 2.1).

Ghi lại MỌI lần gọi vào login_events, kể cả thất bại — đây là dữ liệu quan
trọng nhất cho detection engine ở các tuần sau. Không log payload ở đâu khác
(không print/logging.debug request) để đảm bảo mật khẩu không bao giờ lộ ra
dạng plain text trong log hệ thống.
"""

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import LoginEvent, User
from app.schemas import LoginRequest, LoginResponse
from app.security import verify_password

router = APIRouter()


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()

    # So khớp hash chứ không so plain text. Nếu user không tồn tại, verify
    # vẫn "chạy" với một hash giả để thời gian phản hồi không lộ việc
    # username có tồn tại hay không (timing side-channel cơ bản).
    success = verify_password(payload.password, user.password_hash) if user else False

    event = LoginEvent(
        user_id=user.id if user else None,
        attempted_username=payload.username,
        success=success,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent"),
        is_synthetic=False,
    )
    db.add(event)
    db.commit()

    if success:
        return LoginResponse(success=True, message="Login successful")

    # Thông báo giống hệt nhau cho "sai mật khẩu" và "tài khoản không tồn tại"
    # để không lộ thông tin tài khoản có tồn tại hay không (docs/api-contract.md mục 3).
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"success": False, "message": "Invalid username or password"},
    )
