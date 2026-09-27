"""POST /login — đăng nhập web app mẫu (nhiệm vụ 2.1). Không log payload ở đâu (không print/logging.debug request) để
mật khẩu không bao giờ lộ ra dạng plain text trong log hệ thống.

Đường nhanh (mặc định, không đổi từ MR12): CHỈ xác thực mật khẩu rồi trả response ngay, detection engine chạy NỀN
(`app/detection/pipeline.py`, nhiệm vụ 5.2) — không chặn thời gian phản hồi.

MR16 "Phản ứng tự động (mô phỏng)" đổi đường đi cho HAI trường hợp, THỰC THI THẬT các đề xuất mà trước đó chỉ ghi nhận
(`ResponseAction.status` luôn `"recommended"` từ MR12):
  1. Tài khoản hoặc IP đang bị KHOÁ (`Blocklist`, `app/detection/engine/intel.py` — đã hỗ trợ `kind="username"` + hạn
     dùng từ MR9): từ chối NGAY LẬP TỨC, KHÔNG xác thực mật khẩu (không lộ tài khoản có tồn tại/mật khẩu đúng hay không
     cho một request chắc chắn bị từ chối).
  2. Mật khẩu ĐÚNG nhưng hybrid risk engine đề xuất `step_up`/`lock` CHO CHÍNH lần thử này: phải CHỜ kết quả chấm điểm
     (`await run_detection_pipeline` trực tiếp, KHÔNG qua `BackgroundTasks`) trước khi trả response — đây là cách DUY
     NHẤT biết được có cần OTP/khoá ngay hay không, đổi lại độ trễ CAO HƠN đường nhanh cho ĐÚNG những lần thử này (đo
     được, xem `docs/automated-response.md`). Lần thử SAI mật khẩu vẫn đi đường nhanh như cũ (không có gì để "chờ"
     thêm khi đã từ chối rồi — OTP chỉ có ý nghĩa SAU KHI mật khẩu đã đúng).

`POST /login/verify-otp` hoàn tất bước xác thực thêm ở (2).
"""

from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.detection.engine.types import LoginAttempt
from app.detection.pipeline import run_detection_pipeline
from app.detection.response_execution import OTP_MAX_ATTEMPTS, OTP_TTL, generate_otp_code, hash_otp_code, otp_code_matches
from app.detection.rule_engine_runtime import refresh_blocklist
from app.models import AuditLog, OtpChallenge, ResponseAction, User
from app.schemas import LoginRequest, LoginResponse, OtpVerifyRequest
from app.security import verify_password
from app.utils.network import resolve_client_ip
from app.utils.time import ensure_utc

router = APIRouter()

_LOCKED_MESSAGE = "Tài khoản hoặc nguồn đăng nhập đang tạm khoá do hoạt động bất thường. Thử lại sau."
_OTP_INVALID_MESSAGE = "Mã xác thực không đúng hoặc đã hết hạn."


def _locked_response() -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_423_LOCKED, content={"success": False, "message": _LOCKED_MESSAGE, "locked": True})


@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, request: Request, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    ip = resolve_client_ip(request)
    user_agent = request.headers.get("user-agent")
    now = datetime.now(timezone.utc)

    # --- MR16 (1): chặn NGAY nếu tài khoản hoặc IP đang bị khoá — TRƯỚC CẢ khi xác thực mật khẩu (không tốn bcrypt
    # cho một request chắc chắn bị từ chối, không lộ mật khẩu đúng/sai qua thời gian phản hồi khi đã bị khoá). Không
    # tra ASN ở đây (đắt — cần GeoIP) nên khối chặn theo ASN không bị bắt ở bước này; vẫn được bắt sau khi mật khẩu
    # đúng, ở nhánh `result.hybrid_action == "lock"` bên dưới (pipeline CÓ tra ASN) — precheck chỉ là đường tắt cho các
    # loại rẻ để kiểm (ip/cidr/username), không phải ranh giới an toàn duy nhất.
    precheck_attempt = LoginAttempt(ts=now.timestamp(), username=payload.username, success=False, ip=ip)
    block_entry = refresh_blocklist(db).match(precheck_attempt)
    if block_entry is not None:
        # Không chạy lại toàn bộ pipeline chấm điểm cho một kết quả đã CHẮC CHẮN là "lock" — nhưng vẫn ghi vết để
        # quản trị viên thấy được là có người tiếp tục thử vào một tài khoản/IP đang bị khoá.
        db.add(AuditLog(
            actor="system", action="reject_blocked_login", target_type="blocklist", target_id=None,
            detail={"username": payload.username, "ip": ip, "blocklist_kind": block_entry.kind, "blocklist_value": block_entry.value},
        ))
        db.commit()
        return _locked_response()

    user = db.query(User).filter(User.username == payload.username).first()
    # So khớp hash chứ không so plain text.
    success = verify_password(payload.password, user.password_hash) if user else False

    if not success:
        background_tasks.add_task(
            run_detection_pipeline, username=payload.username, user_id=user.id if user else None, success=False, ip=ip, user_agent=user_agent, timestamp=now,
        )
        # Thông báo giống hệt nhau cho "sai mật khẩu" và "tài khoản không tồn tại" để không lộ thông tin tài khoản có
        # tồn tại hay không (docs/api-contract.md mục 3).
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"success": False, "message": "Invalid username or password"})

    # --- MR16 (2): mật khẩu ĐÚNG — CHỜ kết quả chấm điểm (không background) để biết CHÍNH lần thử này có cần OTP/khoá.
    result = await run_detection_pipeline(username=payload.username, user_id=user.id, success=True, ip=ip, user_agent=user_agent, timestamp=now)

    if result.hybrid_action == "lock":
        return _locked_response()

    if result.hybrid_action == "step_up":
        code = generate_otp_code()
        challenge = OtpChallenge(login_event_id=result.login_event_id, user_id=user.id, code_hash=hash_otp_code(code), expires_at=now + OTP_TTL)
        db.add(challenge)
        db.flush()

        pending = (
            db.query(ResponseAction)
            .filter(ResponseAction.login_event_id == result.login_event_id, ResponseAction.action == "step_up")
            .order_by(ResponseAction.id.desc())
            .first()
        )
        if pending is not None:
            pending.status, pending.executed_at = "executed", now
        db.add(AuditLog(actor="system", action="execute_step_up", target_type="login_event", target_id=result.login_event_id, detail={"otp_challenge_id": challenge.id}))
        db.commit()

        return LoginResponse(
            success=False,
            message=f"Cần xác thực thêm — mã demo: {code} (hệ thống thật sẽ gửi qua SMS/email, KHÔNG BAO GIỜ hiện trực tiếp như thế này).",
            step_up_required=True, challenge_id=challenge.id, demo_otp_code=code,
        )

    return LoginResponse(success=True, message="Login successful")


@router.post("/login/verify-otp", response_model=LoginResponse)
def verify_otp(payload: OtpVerifyRequest, db: Session = Depends(get_db)):
    challenge = db.get(OtpChallenge, payload.challenge_id)
    now = datetime.now(timezone.utc)
    invalid = LoginResponse(success=False, message=_OTP_INVALID_MESSAGE)

    # Thông báo GIỐNG NHAU cho mọi lý do thất bại (không tồn tại/đã dùng/hết hạn/quá số lần/sai mã) — không lộ chi tiết.
    if challenge is None or challenge.verified_at is not None or challenge.attempts >= OTP_MAX_ATTEMPTS or ensure_utc(challenge.expires_at) < now:
        return invalid

    if not otp_code_matches(payload.code, challenge.code_hash):
        challenge.attempts += 1
        db.commit()
        return invalid

    challenge.verified_at = now
    db.commit()
    return LoginResponse(success=True, message="Login successful")
