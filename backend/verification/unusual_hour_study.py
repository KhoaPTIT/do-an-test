"""Nghiên cứu unusual_hour (Phase 3 — Milestone C.1): phân tích báo nhầm và so sánh detector CŨ (3σ vòng tròn, Milestone
C) với detector hiện tại trên CÙNG bộ đánh giá (20+20 kịch bản, lưu lượng bình thường v3 — không sửa).

    python -m verification.unusual_hour_study --detector legacy_sigma --out <thư mục>
    python -m verification.unusual_hour_study --detector current --out <thư mục>

Mỗi lần gọi chạy trong MỘT tiến trình riêng: detector được chọn và bật ở trạng thái ứng viên (enforce + verified) TRƯỚC
khi bất kỳ pipeline nào được dựng, rồi chạy lưu lượng bình thường + 20+20 kịch bản của unusual_hour qua pipeline thật.
Ghi `<out>/<detector>.json`: chỉ số + phân tích từng báo nhầm trên lưu lượng bình thường (giờ hiện tại, các giờ đăng nhập
THÀNH CÔNG trước đó của chính tài khoản, tham số hồ sơ, lý do detector khớp, nhóm nguyên nhân).

`legacy_sigma_unusual_hour` dưới đây là bản sao NGUYÊN VẸN của detector Milestone C (commit a58bc12) — chỉ dùng để so sánh,
không đăng ký vào sổ luật."""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.detection.engine.profile import circular_hour_distance, hour_of_day, hour_profile, maturity
from app.detection.engine.registry import Param, RuleContext
from app.detection.engine.types import Finding

RULE = "unusual_hour"

# ------------------------------------------------------------------------------------------------ detector cũ (3σ)

LEGACY_SIGMA_PARAMS = (
    Param("min_successes", 10, "", "lần", 1, 10_000),
    Param("min_profile_days", 7, "", "ngày", 0, 3650),
    Param("deviation_sigmas", 3.0, "", "σ", 0.5, 10.0),
    Param("min_deviation_hours", 4.0, "", "giờ", 0.5, 12.0),
    Param("min_concentration", 0.5, "", "", 0.0, 1.0),
)


def legacy_sigma_unusual_hour(ctx: RuleContext) -> Finding | None:
    a, h, p = ctx.attempt, ctx.history, ctx.p
    if not a.success:
        return None
    m = maturity(h, a.ts, min_successes=p.min_successes, min_profile_days=p.min_profile_days)
    if not m.mature:
        return None
    hp = hour_profile(h)
    if hp is None or hp.concentration < p.min_concentration:
        return None
    current = hour_of_day(a.ts)
    deviation = circular_hour_distance(current, hp.center)
    threshold = max(p.deviation_sigmas * hp.spread_hours, p.min_deviation_hours)
    if deviation <= threshold:
        return None
    return Finding(
        f"Tài khoản '{a.username}' đăng nhập lúc {current:.1f}h UTC, lệch {deviation:.1f}h so với giờ quen {hp.center:.1f}h "
        f"(ngưỡng {threshold:.1f}h, {hp.sample_count} lần thành công).",
        {
            "current_hour": round(current, 2),
            "usual_hour_center": round(hp.center, 2),
            "hour_deviation": round(deviation, 2),
            "threshold_hours": round(threshold, 2),
            "spread_hours": round(hp.spread_hours, 2),
            "concentration": round(hp.concentration, 3),
            "sample_count": hp.sample_count,
            "profile_age_days": round(m.profile_age_days, 1),
            "timezone": "UTC",
        },
    )


DETECTORS = ("legacy_sigma", "current")


def install(detector: str) -> None:
    """Chọn detector cho unusual_hour và bật nó ở trạng thái ứng viên — chỉ trong tiến trình này."""
    from app.detection.engine.registry import REGISTRY

    spec = REGISTRY[RULE]
    if detector == "legacy_sigma":
        spec = dataclasses.replace(spec, evaluate=legacy_sigma_unusual_hour, params=LEGACY_SIGMA_PARAMS)
    REGISTRY[RULE] = dataclasses.replace(spec, verification="verified", default_mode="enforce")


# ------------------------------------------------------------------------------------------------ phân tích báo nhầm

def simulated_role(username: str, n_users: int = 50) -> str:
    """Vai trò mô phỏng của tài khoản trong lưu lượng bình thường v3 (cùng quy ước đánh số với
    `verification.normal_traffic.generate`) — CHỈ để đọc báo cáo, không dùng để phân nhóm hay trong detector."""
    u = int(username.removeprefix("user"))
    if u >= n_users:
        extra = ("night_shift",) * 3 + ("heavy_daily",) * 3 + ("developer",) + ("service_like",) + ("geo_missing",) * 2 + ("new_account",) * 3
        return extra[u - n_users]
    return "office" if u < 12 else "traveller" if u < 16 else "dormant" if u < 19 else "regular"


def _hour_histogram(hours: list[float]) -> list[int]:
    hist = [0] * 24
    for h in hours:
        hist[int(h) % 24] += 1
    return hist


def _modes(hist: list[int], min_share: float = 0.1) -> list[int]:
    """Các đỉnh cục bộ (vòng tròn) của histogram giờ chiếm ≥ `min_share` tổng số mẫu, sau khi làm mượt [1,2,1]."""
    n = sum(hist) or 1
    smooth = [hist[(i - 1) % 24] + 2 * hist[i] + hist[(i + 1) % 24] for i in range(24)]
    peaks = [i for i in range(24) if smooth[i] > 0 and smooth[i] >= smooth[(i - 1) % 24] and smooth[i] > smooth[(i + 1) % 24]]
    return [i for i in peaks if smooth[i] / (4 * n) >= min_share]


def classify(current: float, prior: list[float], center: float) -> tuple[str, str]:
    """Nhóm nguyên nhân của MỘT báo nhầm, chỉ từ hình dạng hồ sơ (không dùng vai trò mô phỏng). Thứ tự kiểm tra cố định."""
    nearest = min(circular_hour_distance(current, h) for h in prior)
    hist = _hour_histogram(prior)
    modes = _modes(hist)
    crosses_midnight = any(h >= 22 for h in prior) and any(h < 2 for h in prior)
    nearest_hour = min(prior, key=lambda h: circular_hour_distance(current, h))
    opposite_sides = (current >= 12) != (nearest_hour >= 12) and circular_hour_distance(current, nearest_hour) < 6
    seen_share = sum(1 for h in prior if circular_hour_distance(current, h) <= 1.0) / len(prior)
    if crosses_midnight and opposite_sides:
        return "MIDNIGHT_WRAP", f"giờ hiện tại {current:.1f}h và lần thành công gần nhất {nearest_hour:.1f}h nằm hai bên nửa đêm"
    if 20 <= center or center < 5:
        return "NIGHT_SHIFT", f"hồ sơ có giờ trung tâm ban đêm ({center:.1f}h)"
    if len(modes) >= 2 and seen_share > 0:
        return "MULTI_MODAL_SCHEDULE", f"hồ sơ có {len(modes)} cụm giờ ({modes}); giờ hiện tại thuộc một cụm đã thấy ({seen_share:.0%} lần thành công trong ±1h)"
    if seen_share > 0:
        return "WIDE_NORMAL_WINDOW", f"giờ hiện tại đã xuất hiện trong lịch sử ({seen_share:.0%} lần thành công trong ±1h) nhưng xa giờ trung tâm"
    if len(prior) < 20:
        return "SPARSE_PROFILE", f"chỉ {len(prior)} lần thành công, lần gần nhất cách {nearest:.1f}h"
    return "OTHER", f"lần thành công gần nhất cách {nearest:.1f}h"


def analyse_false_positives(env) -> list[dict]:
    from app.models import LoginEvent

    db = env.session_factory()
    try:
        rows = []
        for alert in env.detector_alerts(RULE):
            event = db.get(LoginEvent, alert.login_event_id)
            ts = event.created_at.replace(tzinfo=timezone.utc) if event.created_at.tzinfo is None else event.created_at
            prior = (
                db.query(LoginEvent.created_at)
                .filter(LoginEvent.user_id == event.user_id, LoginEvent.success.is_(True), LoginEvent.id != event.id, LoginEvent.created_at < event.created_at)
                .order_by(LoginEvent.created_at).all()
            )
            prior_ts = [(p.replace(tzinfo=timezone.utc) if p.tzinfo is None else p).timestamp() for (p,) in prior]
            prior_hours = [round(hour_of_day(t), 2) for t in prior_ts]
            ev = (alert.explanation or {}).get("evidence", {})
            current = hour_of_day(ts.timestamp())
            center = ev.get("usual_hour_center")
            group, why = classify(current, prior_hours, center if center is not None else 12.0)
            rows.append({
                "account": event.attempted_username,
                "simulated_role": simulated_role(event.attempted_username),
                "timestamp": ts.isoformat(),
                "current_hour": round(current, 2),
                "historical_successful_login_hours": prior_hours,
                "historical_hour_histogram": _hour_histogram(prior_hours),
                "profile_sample_count": len(prior_hours),
                "profile_age_days": round((ts.timestamp() - prior_ts[0]) / 86_400, 1) if prior_ts else 0.0,
                "detector_center": center,
                "dispersion_hours": ev.get("spread_hours"),
                "concentration": ev.get("concentration"),
                "threshold_hours": ev.get("threshold_hours"),
                "deviation_hours": ev.get("hour_deviation"),
                "nearest_prior_success_hours_away": round(min(circular_hour_distance(current, h) for h in prior_hours), 2),
                "detector_evidence": ev,
                "occurrence_count": alert.occurrence_count,
                "reason_detector_fired": alert.message,
                "group": group,
                "group_reason": why,
            })
        return rows
    finally:
        db.close()


# ------------------------------------------------------------------------------------------------ chạy

def run(detector: str, seed: int) -> dict:
    install(detector)
    import scripts.behavior_verification as bv
    from verification.harness import VerificationEnv
    from verification.normal_traffic import generate

    traffic = generate(seed)
    env = VerificationEnv()
    bv._setup(env, traffic.accounts, traffic.history)
    for step in traffic.steps:
        env.login(step.username, success=step.success, ip=step.ip, ts=bv.T0 + timedelta(seconds=step.offset_s), user_agent=step.user_agent)
    fps = analyse_false_positives(env)
    firing_attempts = sum(1 for v in env.verdicts if RULE in v.matched_rules)
    result = bv.evaluate_behavior(RULE, seed, len(fps))
    return {
        "detector": detector,
        "seed": seed,
        "normal_traffic": {"users": traffic.profile_counts["users"], "total_steps": traffic.profile_counts["total_steps"], "history_logins": traffic.profile_counts["history_logins"]},
        "metrics": {k: result[k] for k in ("status", "failed_criteria", "tp", "fn", "fp", "tn", "precision", "recall", "f1", "attribution_accuracy", "normal_traffic_false_alerts")},
        "normal_traffic_firing_attempts": firing_attempts,
        "false_positive_groups": dict(Counter(r["group"] for r in fps)),
        "false_positives_by_role": dict(Counter(r["simulated_role"] for r in fps)),
        "false_positives": fps,
        "scenarios": result["scenarios"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--detector", choices=DETECTORS, required=True)
    parser.add_argument("--seed", type=int, default=20260302)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    logging.disable(logging.WARNING)
    import scripts.behavior_verification as bv

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    data = {"generated_at": datetime.now(timezone.utc).isoformat(), "git": bv._git_commit(), **run(args.detector, args.seed)}
    (out / f"{args.detector}.json").write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    m = data["metrics"]
    print(f"{args.detector}: TP {m['tp']} FN {m['fn']} FP {m['fp']} TN {m['tn']} recall {m['recall']} attr {m['attribution_accuracy']} normal FP {m['normal_traffic_false_alerts']}")
    print(f"  nhóm báo nhầm: {data['false_positive_groups']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
