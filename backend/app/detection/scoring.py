"""Chấm điểm risk score tầng 2 (nhiệm vụ 4.2).

Trọng số và ngưỡng phân loại lấy NGUYÊN VĂN checklist mục 4.2:
  lệch giờ +20, IP lạ +30, fail liên tiếp +40, đăng nhập thành công ngay
  sau chuỗi fail +50. Dưới 40 = bình thường, 40-70 = trung bình, trên 70 = cao.

Hàm này tính điểm tổng hợp cho MỌI lần đăng nhập (kể cả không khớp rule
tầng 1), để lưu vào login_events.risk_score đúng yêu cầu checklist.
Alert tầng 1 (brute_force/credential_stuffing/impossible_travel) ở
routers/auth.py vẫn giữ nguyên — Alert "high_risk_score" ở đây là bổ sung,
không thay thế.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.detection.baseline import is_in_learning_mode
from app.models import UserBaseline

UNUSUAL_HOUR_WEIGHT = 20
UNKNOWN_LOCATION_WEIGHT = 30
CONSECUTIVE_FAIL_WEIGHT = 40
SUCCESS_AFTER_FAIL_STREAK_WEIGHT = 50

LOW_RISK_MAX = 40  # < 40: bình thường
MEDIUM_RISK_MAX = 70  # 40-70: trung bình, > 70: cao

# ⚠️ Giả định (docs/api-contract.md mục 6) — không có trong checklist gốc.
UNUSUAL_HOUR_STDDEV_MULTIPLIER = 2.5
MIN_STDDEV_HOURS = 0.5  # tránh stddev quá nhỏ khiến mọi lệch nhỏ đều bị tính bất thường
SUCCESS_AFTER_FAIL_STREAK_MIN_FAILS = 3  # "chuỗi" = nhiều hơn 1 lần fail


@dataclass
class RiskFactors:
    unusual_hour: bool = False
    unknown_location: bool = False
    consecutive_fail: bool = False
    success_after_fail_streak: bool = False

    def total_score(self) -> int:
        score = 0
        if self.unusual_hour:
            score += UNUSUAL_HOUR_WEIGHT
        if self.unknown_location:
            score += UNKNOWN_LOCATION_WEIGHT
        if self.consecutive_fail:
            score += CONSECUTIVE_FAIL_WEIGHT
        if self.success_after_fail_streak:
            score += SUCCESS_AFTER_FAIL_STREAK_WEIGHT
        return min(score, 100)


def classify_severity(score: int) -> str:
    if score < LOW_RISK_MAX:
        return "low"
    if score <= MEDIUM_RISK_MAX:
        return "medium"
    return "high"


def is_unusual_hour(baseline: UserBaseline | None, login_hour: float) -> bool:
    """False khi đang ở chế độ học hoặc thiếu baseline — không đủ dữ liệu để kết luận."""
    if baseline is None or is_in_learning_mode(baseline) or baseline.avg_login_hour is None:
        return False

    stddev = max(baseline.stddev_login_hour or 0.0, MIN_STDDEV_HOURS)
    # Khoảng cách theo đường tròn 24h (23h và 1h chỉ cách nhau 2h, không phải 22h).
    diff = abs(login_hour - baseline.avg_login_hour)
    diff = min(diff, 24 - diff)
    return diff > UNUSUAL_HOUR_STDDEV_MULTIPLIER * stddev


def explain_factors(factors: RiskFactors, *, baseline: UserBaseline | None, login_hour: float) -> str:
    """Sinh chuỗi NGẮN GỌN, kiểu gạch đầu dòng, cho các yếu tố đã kích hoạt —
    dùng cho message của Alert 'high_risk_score'. Chỉ đủ chi tiết để đọc
    lướt hiểu ngay (số giờ lệch, không kèm câu văn dài) — chi tiết đầy đủ
    hơn (avg/stddev) đã có sẵn trong tooltip/trang chi tiết nếu cần tra lại.
    """
    parts: list[str] = []

    if factors.unusual_hour and baseline is not None and baseline.avg_login_hour is not None:
        diff = abs(login_hour - baseline.avg_login_hour)
        diff = min(diff, 24 - diff)
        parts.append(f"lệch giờ {diff:.1f}h (+{UNUSUAL_HOUR_WEIGHT}đ)")
    if factors.unknown_location:
        parts.append(f"vị trí lạ (+{UNKNOWN_LOCATION_WEIGHT}đ)")
    if factors.consecutive_fail:
        parts.append(f"đang bị dò mật khẩu (+{CONSECUTIVE_FAIL_WEIGHT}đ)")
    if factors.success_after_fail_streak:
        parts.append(f"thành công sau chuỗi fail (+{SUCCESS_AFTER_FAIL_STREAK_WEIGHT}đ)")

    if not parts:
        return "điểm nền, không yếu tố nổi bật"
    return ", ".join(parts)


def compute_risk_score(
    *,
    baseline: UserBaseline | None,
    login_hour: float,
    is_new_location: bool,
    consecutive_fail: bool,
    success_after_fail_streak: bool,
) -> tuple[int, RiskFactors]:
    in_learning_mode = baseline is None or is_in_learning_mode(baseline)

    factors = RiskFactors(
        unusual_hour=is_unusual_hour(baseline, login_hour),
        # Chế độ học: chưa đủ dữ liệu để biết "vị trí quen thuộc" là gì -> không tính lạ.
        unknown_location=is_new_location and not in_learning_mode,
        consecutive_fail=consecutive_fail,
        success_after_fail_streak=success_after_fail_streak,
    )
    return factors.total_score(), factors
