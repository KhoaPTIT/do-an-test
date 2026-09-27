"""MR16 — "Phản ứng tự động (mô phỏng)": THỰC THI THẬT các đề xuất `step_up`/`lock` mà hybrid risk engine (MR11) chỉ
mới đưa ra dạng GỢI Ý từ MR12 (`ResponseAction.status` luôn `"recommended"`, chưa làm gì cả). THUẦN (không đụng DB) —
orchestration nằm ở hai nơi TUỲ hành động, vì mỗi hành động cần bối cảnh khác nhau:
  - `lock` → `app/detection/pipeline.py` (đã có sẵn DB session + toàn bộ ngữ cảnh chấm điểm, không cần chờ HTTP) tạo
    thẳng một `BlocklistEntry` có hạn dùng — TÁI DÙNG NGUYÊN bộ máy blocklist đã có từ MR9 (`Blocklist.match()` đã hỗ
    trợ `kind="username"` + hạn dùng từ đầu, chỉ chưa ai TỰ ĐỘNG thêm mục nào vào đó).
  - `step_up` → `app/routers/auth.py` (cần trả OTP THẲNG trong response HTTP nên phải ở lớp router, không phải pipeline
    nền) tạo một `OtpChallenge`.

⚠️ OTP GIẢ LẬP: mã trả THẲNG trong response `POST /login` (không có nhà cung cấp SMS/email nào được tích hợp — đúng
tinh thần "mô phỏng" của MR16, xem checklist) — dùng `secrets` (không phải `random`) để đúng thói quen tạo mã, dù ở
đây mã bị echo lại ngay trong response nên độ ngẫu nhiên không thực sự bảo vệ được gì trong cấu hình demo này.
"""

from __future__ import annotations

import secrets
from datetime import timedelta

from app.security import hash_password, verify_password

# Thời hạn khoá tự động (khác hạn dùng của mục blocklist THỦ CÔNG do quản trị viên tự đặt, không giới hạn ở đây) — 30
# phút: đủ để cắt đứt một đợt tấn công đang diễn ra, đủ ngắn để không khoá một tài khoản thật quá lâu vì báo nhầm.
LOCK_TTL = timedelta(minutes=30)

OTP_TTL = timedelta(minutes=5)
OTP_MAX_ATTEMPTS = 5
OTP_CODE_LENGTH = 6


def lock_kind_and_value(*, user_id: int | None, username: str, ip: str) -> tuple[str, str]:
    """(`kind`, `value`) cho `BlocklistEntry` khi hành động là "lock" — "Khoá tạm TÀI KHOẢN" (`kind="username"`) khi
    tài khoản tồn tại; "chặn IP" (`kind="ip"`) khi không (tên đăng nhập không tồn tại thì không có tài khoản nào để
    khoá, hạ tầng — IP — là thứ duy nhất còn lại đáng chặn)."""
    if user_id is not None:
        return "username", username
    return "ip", ip


def generate_otp_code() -> str:
    return f"{secrets.randbelow(10 ** OTP_CODE_LENGTH):0{OTP_CODE_LENGTH}d}"


def hash_otp_code(code: str) -> str:
    return hash_password(code)


def otp_code_matches(code: str, code_hash: str) -> bool:
    return verify_password(code, code_hash)
