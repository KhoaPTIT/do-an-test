"""POST /login — đăng nhập web app mẫu (nhiệm vụ 2.1) + rule-based
detection tầng 1 chạy ngay sau khi ghi log (nhiệm vụ 3.3).

Ghi lại MỌI lần gọi vào login_events, kể cả thất bại. Không log payload ở
đâu khác (không print/logging.debug request) để mật khẩu không bao giờ lộ
ra dạng plain text trong log hệ thống.
"""

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.detection.geoip import lookup_ip
from app.detection.rules import (
    GeoPoint,
    is_brute_force,
    is_credential_stuffing,
    is_impossible_travel,
    register_login_failure,
)
from app.models import Alert, LoginEvent, User
from app.schemas import LoginRequest, LoginResponse
from app.security import verify_password

router = APIRouter()

# Tầng 1 chưa có công thức chấm điểm đầy đủ (0-100, sẽ làm ở Tuần 4 —
# nhiệm vụ 4.2). Alert ở tầng này dùng risk_score/severity cố định, sẽ
# được compute_risk_score() thay thế/ghi đè khi tầng 2 hoạt động.
_RULE_TIER1_RISK_SCORE = 80
_RULE_TIER1_SEVERITY = "high"

_ALERT_MESSAGES = {
    "brute_force": "Phát hiện dò mật khẩu liên tiếp cho tài khoản '{target}'.",
    "credential_stuffing": "Phát hiện thử nhiều tài khoản khác nhau từ cùng IP {target}.",
    "impossible_travel": "Đăng nhập từ vị trí cách xa bất thường so với lần trước trong thời gian quá ngắn.",
}


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()

    # So khớp hash chứ không so plain text.
    success = verify_password(payload.password, user.password_hash) if user else False

    ip = request.client.host if request.client else "unknown"
    geo = lookup_ip(ip)

    event = LoginEvent(
        user_id=user.id if user else None,
        attempted_username=payload.username,
        success=success,
        ip_address=ip,
        user_agent=request.headers.get("user-agent"),
        country=geo.country if geo else None,
        city=geo.city if geo else None,
        latitude=geo.latitude if geo else None,
        longitude=geo.longitude if geo else None,
        is_synthetic=False,
    )
    db.add(event)
    db.flush()  # cần event.id để Alert tham chiếu tới

    triggered: list[tuple[str, str]] = []  # (alert_type, target hiển thị trong message)

    # Impossible travel: so với lần đăng nhập gần nhất TRƯỚC đó của cùng user
    # (bất kể thành công/thất bại — vị trí vẫn là tín hiệu hữu ích).
    if user is not None:
        previous_event = (
            db.query(LoginEvent)
            .filter(LoginEvent.user_id == user.id, LoginEvent.id != event.id)
            .order_by(LoginEvent.created_at.desc())
            .first()
        )
        if previous_event is not None:
            previous_point = GeoPoint(previous_event.latitude, previous_event.longitude, previous_event.created_at)
            current_point = GeoPoint(event.latitude, event.longitude, event.created_at)
            if is_impossible_travel(previous_point, current_point):
                triggered.append(("impossible_travel", ""))

    if not success:
        register_login_failure(payload.username, ip)

        if is_brute_force(payload.username):
            triggered.append(("brute_force", payload.username))

        if is_credential_stuffing(ip):
            triggered.append(("credential_stuffing", ip))

    for alert_type, target in triggered:
        db.add(
            Alert(
                login_event_id=event.id,
                user_id=user.id if user else None,
                alert_type=alert_type,
                severity=_RULE_TIER1_SEVERITY,
                risk_score=_RULE_TIER1_RISK_SCORE,
                message=_ALERT_MESSAGES[alert_type].format(target=target),
            )
        )

    db.commit()

    if success:
        return LoginResponse(success=True, message="Login successful")

    # Thông báo giống hệt nhau cho "sai mật khẩu" và "tài khoản không tồn tại"
    # để không lộ thông tin tài khoản có tồn tại hay không (docs/api-contract.md mục 3).
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"success": False, "message": "Invalid username or password"},
    )
