"""Nhóm "Hồ sơ hành vi" (Phase 3 — Milestone B): so lần đăng nhập với HỒ SƠ RIÊNG của chính tài khoản, không phải với
ngưỡng toàn hệ thống hay mô hình học máy toàn cục. Chỉ chấm khi hồ sơ đã TRƯỞNG THÀNH (đủ lịch sử để "lạ" có nghĩa) — trị
đúng vấn đề đã đo ở MR18: `ml_anomaly` báo gần như mọi lần đăng nhập của tài khoản mới.

Cảnh báo của nhóm này có `alert_type="behavior_anomaly"` (app/detection/consolidation.py)."""

from __future__ import annotations

from datetime import datetime, timezone

from app.detection.engine.registry import Param, RuleContext, rule
from app.detection.engine.types import Finding

CATEGORY = "Hồ sơ hành vi"
_DAY = 86_400


def _iso(ts: float | None) -> str | None:
    return None if ts is None else datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


@rule(
    id="unusual_device",
    verification="verified",  # Milestone B — artifacts/behavior_verification/unusual_device.json
    title="Thiết bị chưa từng thấy",
    category=CATEGORY,
    severity="low",
    techniques=("T1078",),
    description=(
        "Đăng nhập THÀNH CÔNG từ một thiết bị (họ chuẩn hoá: loại thiết bị | hệ điều hành | trình duyệt, bỏ phiên bản) mà tài khoản CHƯA "
        "từng đăng nhập thành công, khi hồ sơ của tài khoản đã trưởng thành."
    ),
    params=(
        Param("min_successes", 10, "số lần đăng nhập thành công tối thiểu để hồ sơ được coi là trưởng thành", "lần", 1, 10_000),
        Param("min_profile_days", 7, "tuổi hồ sơ tối thiểu (từ lần thành công đầu tiên)", "ngày", 0, 3650),
    ),
    needs=("account", "history", "user_agent"),
    notes=(
        "Thiết bị chuẩn hoá theo họ nên cập nhật phiên bản (Chrome 120 → 121) KHÔNG phải thiết bị mới; User-Agent không nhận diện được giữ nguyên làm "
        "họ riêng. Không phân biệt được người dùng MUA thiết bị mới với kẻ tấn công — vì vậy mức thấp, chỉ cảnh báo, không tự step_up/lock. Khi một hành vi "
        "tấn công rõ hơn cùng khớp (impossible_travel, tài khoản ngủ đông...), hành vi đó làm detector chính và unusual_device là bằng chứng bổ trợ."
    ),
)
def unusual_device(ctx: RuleContext) -> Finding | None:
    a, h, p = ctx.attempt, ctx.history, ctx.p
    if not a.success or h is None or h.first_success_ts is None:
        return None
    family = a.device_family
    if not family or family in h.known_device_families:
        return None
    profile_age_days = (a.ts - h.first_success_ts) / _DAY
    if h.n_success < p.min_successes or profile_age_days < p.min_profile_days:
        return None  # hồ sơ chưa trưởng thành: "lạ" chưa có nghĩa
    return Finding(
        f"Tài khoản '{a.username}' đăng nhập từ thiết bị chưa từng thấy ({family}); đã quen {len(h.known_device_families)} thiết bị "
        f"qua {h.n_success} lần thành công trong {profile_age_days:.0f} ngày.",
        {
            "current_device": family,
            "known_devices": list(h.known_device_families),
            "known_device_count": len(h.known_device_families),
            "successful_login_count": h.n_success,
            "profile_age_days": round(profile_age_days, 1),
            "profile_first_seen": _iso(h.first_success_ts),
            "known_devices_first_seen": {f: _iso(t) for f, t in zip(h.known_device_families, h.device_family_first_seen)},
            "current_context": {"ip": a.ip, "country": a.country, "browser": a.browser, "os": a.os, "device_type": a.device_type},
        },
    )
