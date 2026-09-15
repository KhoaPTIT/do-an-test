"""POST /login — đăng nhập web app mẫu (nhiệm vụ 2.1) + rule-based
detection tầng 1 (nhiệm vụ 3.3) + behavioral scoring tầng 2 (nhiệm vụ 4.1-4.2).

Ghi lại MỌI lần gọi vào login_events, kể cả thất bại. Không log payload ở
đâu khác (không print/logging.debug request) để mật khẩu không bao giờ lộ
ra dạng plain text trong log hệ thống.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.detection.baseline import (
    is_known_location,
    record_known_device_if_new,
    record_known_location_if_new,
    update_baseline_after_successful_login,
)
from app.detection.geoip import lookup_ip
from app.detection.rate_counter import check_fail_count
from app.detection.rules import (
    GeoPoint,
    is_brute_force,
    is_credential_stuffing,
    is_impossible_travel,
    register_login_failure,
)
from app.detection.scoring import (
    SUCCESS_AFTER_FAIL_STREAK_MIN_FAILS,
    classify_severity,
    compute_risk_score,
)
from app.models import Alert, LoginEvent, User, UserBaseline
from app.schemas import LoginRequest, LoginResponse
from app.security import verify_password
from app.utils.device import compute_device_fingerprint

router = APIRouter()

# Tầng 1 (brute_force/credential_stuffing/impossible_travel) chưa có điểm
# 0-100 riêng theo checklist — dùng mức cố định "cao" cho tới khi risk_score
# tầng 2 (bên dưới) trở thành nguồn duy nhất cho login_events.risk_score.
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

    now = datetime.now(timezone.utc)
    ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent")
    geo = lookup_ip(ip)
    device_fingerprint = compute_device_fingerprint(user_agent)

    # Đọc counter fail TRƯỚC khi register_login_failure cập nhật thêm, để
    # biết "có chuỗi fail ngay trước lần này không" (dùng cho cả tier 1 lẫn
    # scoring tier 2 bên dưới).
    recent_fail_count = check_fail_count(f"fail:{payload.username}")

    event = LoginEvent(
        user_id=user.id if user else None,
        attempted_username=payload.username,
        success=success,
        ip_address=ip,
        user_agent=user_agent,
        device_fingerprint=device_fingerprint,
        country=geo.country if geo else None,
        city=geo.city if geo else None,
        latitude=geo.latitude if geo else None,
        longitude=geo.longitude if geo else None,
        is_synthetic=False,
        created_at=now,
    )
    db.add(event)
    db.flush()  # cần event.id để Alert tham chiếu tới

    triggered: list[tuple[str, str]] = []  # (alert_type, target hiển thị trong message)

    # --- Tầng 1: impossible travel (so với lần đăng nhập gần nhất TRƯỚC đó) ---
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

    # --- Tầng 1: brute force / credential stuffing (chỉ xét khi FAIL) ---
    is_brute_force_flag = False
    if not success:
        register_login_failure(payload.username, ip)

        is_brute_force_flag = is_brute_force(payload.username)
        if is_brute_force_flag:
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

    # --- Tầng 2: behavioral scoring (nhiệm vụ 4.1-4.2) ---
    if user is not None:
        baseline = db.query(UserBaseline).filter(UserBaseline.user_id == user.id).first()
        login_hour = event.created_at.hour + event.created_at.minute / 60
        known_location = is_known_location(db, user.id, event.country, event.city)
        had_fail_streak = recent_fail_count >= SUCCESS_AFTER_FAIL_STREAK_MIN_FAILS

        risk_score, factors = compute_risk_score(
            baseline=baseline,
            login_hour=login_hour,
            is_new_location=not known_location,
            consecutive_fail=is_brute_force_flag,
            success_after_fail_streak=success and had_fail_streak,
        )
        event.risk_score = risk_score

        severity = classify_severity(risk_score)
        if severity != "low":
            db.add(
                Alert(
                    login_event_id=event.id,
                    user_id=user.id,
                    alert_type="high_risk_score",
                    severity=severity,
                    risk_score=risk_score,
                    message=f"Risk score {risk_score}/100 ({severity}) cho tài khoản '{user.username}'.",
                )
            )

        if success:
            update_baseline_after_successful_login(db, user, event)
            record_known_device_if_new(db, user, device_fingerprint, user_agent)
            record_known_location_if_new(db, user, event.country, event.city)

    db.commit()

    if success:
        return LoginResponse(success=True, message="Login successful")

    # Thông báo giống hệt nhau cho "sai mật khẩu" và "tài khoản không tồn tại"
    # để không lộ thông tin tài khoản có tồn tại hay không (docs/api-contract.md mục 3).
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"success": False, "message": "Invalid username or password"},
    )
