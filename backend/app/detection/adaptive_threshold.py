"""MR15 — "Vòng phản hồi": suy ra `threshold_delta` cho `UserRiskProfile` từ lịch sử phản hồi (`Alert.feedback`), và áp
lệch đó vào `ActionBands` khi chấm điểm CHO CHÍNH tài khoản đó. THUẦN (không đụng DB) — orchestration (đọc phản hồi,
ghi `UserRiskProfile`) nằm ở `backend/scripts/retrain_from_feedback.py` (script ĐỊNH KỲ, không chạy ngay mỗi lần bấm
phản hồi — xem docstring ở đó) và `app/detection/pipeline.py` (đọc `UserRiskProfile` lúc chấm điểm).

Công thức CỐ Ý đơn giản và CHỈ NỚI LỎNG (không bao giờ âm — không tự động thắt chặt xuống dưới mặc định nhóm dù phản
hồi toàn "đúng"): mỗi phản hồi "báo nhầm" RÒNG (trừ đi phản hồi "đúng") kéo `threshold_delta` lên `LEARNING_RATE`
điểm, tối đa `MAX_DELTA`. "Ròng" để một tài khoản có cả phản hồi đúng lẫn sai không bị coi là toàn báo nhầm chỉ vì có
vài lần báo nhầm xen giữa nhiều lần đúng."""

from __future__ import annotations

from dataclasses import replace

from app.detection.hybrid.calibration import ActionBands

MIN_FEEDBACK_FOR_PERSONAL_THRESHOLD = 3  # dưới ngưỡng này: mẫu quá nhỏ để tin, dùng thẳng ngưỡng NHÓM (mặc định)
LEARNING_RATE = 4.0  # điểm nới lỏng cho mỗi phản hồi "báo nhầm" RÒNG (đã trừ "đúng") — xem docstring module
MAX_DELTA = 20.0  # trần nới lỏng — không để một tài khoản trôi quá xa khỏi ngưỡng đã hiệu chỉnh (MR11)


def compute_delta(feedback_count: int, false_positive_count: int) -> float:
    """`threshold_delta` mới cho MỘT tài khoản, từ tổng số phản hồi và số phản hồi "báo nhầm" trong đó. `0.0` nếu chưa
    đủ mẫu (`feedback_count < MIN_FEEDBACK_FOR_PERSONAL_THRESHOLD`) hoặc phản hồi "đúng" nhiều hơn/bằng "báo nhầm"."""
    if feedback_count < MIN_FEEDBACK_FOR_PERSONAL_THRESHOLD:
        return 0.0
    true_positive_count = feedback_count - false_positive_count
    net_false_positives = false_positive_count - true_positive_count
    if net_false_positives <= 0:
        return 0.0
    return min(LEARNING_RATE * net_false_positives, MAX_DELTA)


def apply_delta(bands: ActionBands, delta: float) -> ActionBands:
    """Dịch CẢ BA mốc (`alert_at`/`step_up_at`/`lock_at`) lên CÙNG một lượng, giữ nguyên khoảng cách tương đối giữa
    các tầng — nên LUÔN còn hợp lệ (`alert_at < step_up_at < lock_at`, `ActionBands.__post_init__`) miễn là cùng một
    lượng dịch không đẩy `lock_at` (mốc cao nhất) vượt 100; vì vậy kẹp CHÍNH `delta` ở `100 - lock_at` TRƯỚC khi dịch,
    KHÔNG kẹp riêng từng mốc sau khi dịch (kẹp riêng có thể khiến hai mốc trùng nhau ở 100, vi phạm bất biến thứ tự
    nghiêm ngặt). `delta <= 0` trả nguyên `bands` (không tạo bản sao thừa)."""
    if delta <= 0:
        return bands
    safe_delta = round(min(delta, MAX_DELTA, 100 - bands.lock_at))
    if safe_delta <= 0:
        return bands  # lock_at đã ở/gần 100 — không còn chỗ để nới lỏng thêm mà vẫn hợp lệ
    return replace(bands, alert_at=bands.alert_at + safe_delta, step_up_at=bands.step_up_at + safe_delta, lock_at=bands.lock_at + safe_delta)
