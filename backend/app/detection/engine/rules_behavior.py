"""Nhóm "Hồ sơ hành vi" (Phase 3 — Milestone B): so lần đăng nhập với HỒ SƠ RIÊNG của chính tài khoản, không phải với
ngưỡng toàn hệ thống hay mô hình học máy toàn cục. Chỉ chấm khi hồ sơ đã TRƯỞNG THÀNH (đủ lịch sử để "lạ" có nghĩa) — trị
đúng vấn đề đã đo ở MR18: `ml_anomaly` báo gần như mọi lần đăng nhập của tài khoản mới.

Cảnh báo của nhóm này có `alert_type="behavior_anomaly"` (app/detection/consolidation.py)."""

from __future__ import annotations

from app.detection.engine import indexes as K
from app.detection.engine.profile import MATURITY_PARAMS, assess_hour, iso, maturity
from app.detection.engine.registry import Param, RuleContext, rule
from app.detection.engine.types import VELOCITY_WINDOW_S, Finding

CATEGORY = "Hồ sơ hành vi"


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
    params=MATURITY_PARAMS,
    needs=("account", "history", "user_agent"),
    notes=(
        "Thiết bị chuẩn hoá theo họ nên cập nhật phiên bản (Chrome 120 → 121) KHÔNG phải thiết bị mới; User-Agent không nhận diện được giữ nguyên làm "
        "họ riêng. Không phân biệt được người dùng MUA thiết bị mới với kẻ tấn công — vì vậy mức thấp, chỉ cảnh báo, không tự step_up/lock. Khi một hành vi "
        "tấn công rõ hơn cùng khớp (impossible_travel, tài khoản ngủ đông...), hành vi đó làm detector chính và unusual_device là bằng chứng bổ trợ."
    ),
)
def unusual_device(ctx: RuleContext) -> Finding | None:
    a, h, p = ctx.attempt, ctx.history, ctx.p
    if not a.success:
        return None
    m = maturity(h, a.ts, min_successes=p.min_successes, min_profile_days=p.min_profile_days)
    if not m.mature:
        return None  # hồ sơ chưa trưởng thành: "lạ" chưa có nghĩa
    family = a.device_family
    if not family or family in h.known_device_families:
        return None
    return Finding(
        f"Tài khoản '{a.username}' đăng nhập từ thiết bị chưa từng thấy ({family}); đã quen {len(h.known_device_families)} thiết bị "
        f"qua {m.successful_login_count} lần thành công trong {m.profile_age_days:.0f} ngày.",
        {
            "current_device": family,
            "known_devices": list(h.known_device_families),
            "known_device_count": len(h.known_device_families),
            "successful_login_count": m.successful_login_count,
            "profile_age_days": round(m.profile_age_days, 1),
            "profile_first_seen": iso(h.first_success_ts),
            "known_devices_first_seen": {f: iso(t) for f, t in zip(h.known_device_families, h.device_family_first_seen)},
            "current_context": {"ip": a.ip, "country": a.country, "browser": a.browser, "os": a.os, "device_type": a.device_type},
        },
    )


@rule(
    id="unusual_location",
    verification="verified",  # Milestone C — artifacts/behavior_verification/unusual_location.json
    title="Vị trí chưa từng thấy",
    category=CATEGORY,
    severity="medium",
    techniques=("T1078",),
    description=(
        "Đăng nhập THÀNH CÔNG từ một QUỐC GIA chưa từng xuất hiện trong lịch sử đăng nhập thành công của tài khoản, khi hồ sơ đã trưởng thành. "
        "Thành phố mới trong một quốc gia đã quen không bị coi là lạ."
    ),
    params=MATURITY_PARAMS,
    needs=("account", "history", "country"),
    notes=(
        "So với TOÀN BỘ hồ sơ vị trí (mọi quốc gia/thành phố từng đăng nhập thành công, kèm số lần/thấy lần đầu/lần cuối), không chỉ lần trước. "
        "Thiếu GeoIP (không có quốc gia) thì bỏ qua. Không phân biệt được chuyến đi hợp lệ ĐẦU TIÊN tới một nước với kẻ tấn công — mức trung bình, "
        "chỉ cảnh báo. Hai lần thành công cách nhau quá xa so với thời gian là impossible_travel (detector chính), vị trí mới là bằng chứng bổ trợ."
    ),
)
def unusual_location(ctx: RuleContext) -> Finding | None:
    a, h, p = ctx.attempt, ctx.history, ctx.p
    if not a.success:
        return None
    m = maturity(h, a.ts, min_successes=p.min_successes, min_profile_days=p.min_profile_days)
    if not m.mature or not h.known_countries or a.country in h.known_countries:
        return None
    locations = [
        {"location": loc, "count": n, "first_seen": iso(f), "last_seen": iso(l)}
        for loc, n, f, l in zip(h.known_locations, h.location_counts, h.location_first_seen, h.location_last_seen)
    ]
    return Finding(
        f"Tài khoản '{a.username}' đăng nhập thành công từ quốc gia chưa từng thấy {a.country}"
        f"{f' ({a.city})' if a.city else ''}; lịch sử: {', '.join(h.known_countries)} qua {m.successful_login_count} lần trong {m.profile_age_days:.0f} ngày.",
        {
            "current_country": a.country,
            "current_city": a.city,
            "known_countries": list(h.known_countries),
            "known_locations": locations,
            "successful_login_count": m.successful_login_count,
            "profile_age_days": round(m.profile_age_days, 1),
            "first_seen_location": h.first_location,
            "profile_first_seen": iso(h.first_success_ts),
        },
    )


@rule(
    id="unusual_hour",
    title="Giờ đăng nhập khác thói quen",
    category=CATEGORY,
    severity="low",
    techniques=("T1078",),
    description=(
        "Đăng nhập THÀNH CÔNG vào một giờ nằm NGOÀI mọi khung giờ mà CHÍNH tài khoản đã từng đăng nhập thành công (histogram 24 giờ "
        "làm mượt vòng tròn), khi hồ sơ đã trưởng thành và có khung giờ rõ ràng. Không có giờ nào 'luôn nguy hiểm': người làm ca đêm "
        "có khung giờ ban đêm; người có nhiều khung giờ (sáng, trưa, tối) được coi là bình thường ở cả ba."
    ),
    params=MATURITY_PARAMS + (
        Param("smoothing_hours", 2, "bán kính làm mượt vòng tròn của histogram giờ (nhân tam giác): giờ cách một lần thành công ≤ bán kính thuộc khung giờ đã thiết lập", "giờ", 0, 6),
        Param("max_coverage", 0.75, "tỉ lệ tối đa của 24 giờ đã thuộc khung giờ quen; vượt mức này hồ sơ quá phân tán — NOT_APPLICABLE, không cảnh báo", "", 0.0, 1.0),
    ),
    needs=("account", "history"),
    notes=(
        "Milestone C.1 thay detector 3σ quanh giờ trung tâm (giả định một cụm đối xứng — báo nhầm 32 lần trên lưu lượng bình thường v3, "
        "artifacts/candidates/unusual_hour/fp_analysis.json). Hồ sơ = histogram 24 ô theo giờ UTC, CHỈ học từ lần thành công. Giờ tính theo "
        "UTC nhất quán cho cả hồ sơ và lần đăng nhập (hệ thống không có múi giờ người dùng; không mô phỏng DST). Một lần thành công duy "
        "nhất ở một giờ đã đủ đưa giờ đó (± bán kính) vào khung quen."
    ),
)
def unusual_hour(ctx: RuleContext) -> Finding | None:
    a, h, p = ctx.attempt, ctx.history, ctx.p
    if not a.success:
        return None
    m = maturity(h, a.ts, min_successes=p.min_successes, min_profile_days=p.min_profile_days)
    if not m.mature:
        return None
    hour = assess_hour(h, a.ts, smoothing_hours=p.smoothing_hours, max_coverage=p.max_coverage)
    if hour is None or hour.status != "UNUSUAL":
        return None
    return Finding(
        f"Tài khoản '{a.username}' đăng nhập lúc {hour.current_hour:.1f}h UTC, ngoài mọi khung giờ quen ({', '.join(hour.usual_hour_ranges)}; "
        f"{hour.sample_count} lần thành công), cách lần thành công gần nhất {hour.nearest_usual_hours_away:.1f}h.",
        {
            "current_hour": round(hour.current_hour, 2),
            "hour_probability": round(hour.hour_probability, 4),
            "usual_hour_ranges": list(hour.usual_hour_ranges),
            "nearest_usual_hours_away": round(hour.nearest_usual_hours_away, 2),
            "profile_coverage": round(hour.coverage, 3),
            "successful_login_count": m.successful_login_count,
            "profile_age_days": round(m.profile_age_days, 1),
            "profile_method": f"circular_histogram_24h_triangular_smoothing_{p.smoothing_hours}h",
            "reason": "outside_established_login_windows",
            "timezone": "UTC",
        },
    )


@rule(
    id="login_velocity_spike",
    verification="verified",  # Milestone C — artifacts/behavior_verification/login_velocity_spike.json
    title="Đăng nhập thành công dồn dập bất thường",
    category=CATEGORY,
    severity="medium",
    techniques=("T1078",),
    description=(
        "NHIỀU lần đăng nhập THÀNH CÔNG vào cùng một tài khoản trong 10 phút, vượt hẳn đỉnh lịch sử của chính tài khoản trong cùng độ dài cửa sổ. "
        "Khác brute_force (nhiều lần THẤT BẠI): đây là phiên đăng nhập hợp lệ bị dùng dồn dập (bot dùng thông tin đăng nhập đã chiếm được, chia sẻ tài khoản...)."
    ),
    params=MATURITY_PARAMS + (
        Param("min_successes_in_window", 8, "số lần thành công tối thiểu trong cửa sổ 10 phút (gồm lần này)", "lần", 2, 10_000),
        Param("min_velocity_ratio", 2.0, "tối thiểu số lần gấp ĐỈNH lịch sử của tài khoản trong cùng cửa sổ", "lần", 1.0, 100.0),
    ),
    needs=("account", "history"),
    notes=(
        f"Cửa sổ cố định {int(VELOCITY_WINDOW_S)}s để so cùng độ dài với đỉnh lịch sử (`AccountHistory.baseline_peak`: chỉ các cửa sổ kết thúc TRƯỚC cửa sổ "
        "hiện tại, nên chính đợt dồn dập không tự nâng nền; chỉ học từ lần thành công — lần thất bại "
        "không làm tăng nền). Tài khoản dịch vụ/lập trình viên có đỉnh lịch sử cao nên cần dồn dập hơn hẳn mới khớp. Chỉ sự kiện XÁC THỰC (/login) được tính; "
        "làm mới phiên/token không đi qua pipeline này."
    ),
)
def login_velocity_spike(ctx: RuleContext) -> Finding | None:
    a, h, p = ctx.attempt, ctx.history, ctx.p
    if not a.success:
        return None
    m = maturity(h, a.ts, min_successes=p.min_successes, min_profile_days=p.min_profile_days)
    if not m.mature:
        return None
    recent = ctx.store.log_count(K.ok_user(a.user_key), ctx.since(VELOCITY_WINDOW_S))
    if recent < p.min_successes_in_window:
        return None
    baseline_peak = max(h.baseline_peak(a.ts), 1)  # nền KHÔNG gồm các lần thành công của chính đợt đang diễn ra
    ratio = recent / baseline_peak
    if ratio < p.min_velocity_ratio:
        return None
    daily_rate = m.successful_login_count / max(m.profile_age_days, 1.0)
    return Finding(
        f"Tài khoản '{a.username}' có {recent} lần đăng nhập thành công trong {int(VELOCITY_WINDOW_S // 60)} phút — gấp {ratio:.1f} lần đỉnh lịch sử "
        f"({baseline_peak} lần/{int(VELOCITY_WINDOW_S // 60)} phút; trung bình {daily_rate:.1f} lần/ngày).",
        {
            "recent_success_count": recent,
            "window_minutes": int(VELOCITY_WINDOW_S // 60),
            "baseline_peak_in_window": baseline_peak,
            "baseline_rate_per_day": round(daily_rate, 2),
            "velocity_ratio": round(ratio, 2),
            "successful_login_count": m.successful_login_count,
            "profile_age_days": round(m.profile_age_days, 1),
        },
    )
