"""Thí nghiệm LUẬT vs ML (Phase 4.1 — ML4) trên CÙNG harness kiểm chứng của Phase 3.

    cd backend && python -m verification.rule_ml_experiment     # -> artifacts/ml/rule_ml_overlap.{json,md}

Chạy LẠI toàn bộ 21 hành vi × (20 dương tính + 20 âm tính) và lưu lượng bình thường v3 (seed harness 20260302 — dataset huấn
luyện ML dùng seed khác) qua pipeline /login thật, lần này VỚI model bất thường đã nạp (artifact `ml/artifacts/anomaly_iforest`).

Định nghĩa (chốt TRƯỚC khi chạy lần đầu; không đổi dataset/ngưỡng sau khi xem kết quả):
  - RULE phát hiện: ít nhất một lần thử của kịch bản có luật ĐỦ TƯ CÁCH TỰ CẢNH BÁO khớp (enforce + verified — 20 detector
    VERIFIED; `unusual_hour` là experimental nên không tính) — đọc từ verdict thật của pipeline.
  - ML phát hiện: ít nhất một lần thử của kịch bản được model gắn cờ bất thường (`login_events.ml_is_anomaly`).
  - A = cả hai · B = chỉ luật · C = chỉ ML · D = không bên nào. Tính theo KỊCH BẢN cho kịch bản tấn công (dương tính); theo
    TỪNG LẦN THỬ cho lưu lượng bình thường (mọi cờ ở đó là báo nhầm).
  - Model chỉ chấm lần thành công của hồ sơ trưởng thành: kịch bản chỉ gồm lần thất bại hoặc tài khoản mới nằm ngoài tầm nhìn
    của ML theo thiết kế (cột `ml_in_scope`).
Kèm kiểm tra hồi quy: 20 hành vi VERIFIED có còn đạt tiêu chí khi BẬT ML không (cùng công thức chấm của runner Phase 3)."""

from __future__ import annotations

import argparse
import json
import logging
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import scripts.behavior_verification as bv
from verification.harness import VerificationEnv

REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = REPO_ROOT / "artifacts" / "ml"


def _quadrant(rule: bool, ml: bool) -> str:
    return "A" if rule and ml else "B" if rule else "C" if ml else "D"


HARNESS_SEED = 20260302  # = seed mặc định của scripts/behavior_verification.py (Phase 3)


def run(model_dir: Path, seed: int = HARNESS_SEED, behaviors: list[str] | None = None) -> dict:
    from ml.anomaly_model import AnomalyModel

    model = AnomalyModel.load(model_dir)  # thiếu artifact thì dừng ngay, không chạy thí nghiệm "ML" khi không có ML

    def env_factory():
        return VerificationEnv(ml_model_dir=model_dir)

    print("Lưu lượng bình thường (có ML)...", flush=True)
    normal = bv.run_normal_traffic(seed, env_factory)
    events = normal.pop("events")
    successes = [e for e in events if e["success"]]
    normal_quadrants = Counter(_quadrant(e["rule_detected"], e["ml_detected"]) for e in events)

    rows, per_behavior, regression = [], {}, {}
    for behavior in behaviors or list(bv.ALL_BEHAVIORS):
        result = bv.evaluate_behavior(behavior, seed, normal["hybrid_alerts_by_detector"].get(behavior, 0), env_factory)
        regression[behavior] = {k: result[k] for k in ("status", "failed_criteria", "tp", "fp", "fn", "recall", "attribution_accuracy", "normal_traffic_false_alerts")}
        positives = [s for s in result["scenarios"] if s["kind"] == "positive"]
        negatives = [s for s in result["scenarios"] if s["kind"] == "negative"]
        q = Counter(_quadrant(s["ml"]["rule_detected"], s["ml"]["ml_detected"]) for s in positives)
        per_behavior[behavior] = {
            "positives": dict(sorted(q.items())),
            "ml_in_scope_positives": sum(1 for s in positives if s["ml"]["ml_scored_events"]),
            "negatives_ml_flagged": sum(1 for s in negatives if s["ml"]["ml_detected"]),
            "negatives_rule_detected": sum(1 for s in negatives if s["ml"]["rule_detected"]),
        }
        for s in positives:
            m = s["ml"]
            rows.append({
                "behavior": behavior, "scenario": s["variant"], "rule_detected": m["rule_detected"], "ml_detected": m["ml_detected"],
                "ml_in_scope": m["ml_scored_events"] > 0, "ml_max_score": None if m["ml_max_score"] is None else round(m["ml_max_score"], 4),
                "primary_detectors": m["primary_detectors"], "risk_engine_action": m["final_action"], "final_decision": m["final_decision"], "quadrant": _quadrant(m["rule_detected"], m["ml_detected"]),
            })
        print(f"  {behavior:28} {result['status']:16} A/B/C/D = {dict(sorted(q.items()))}", flush=True)

    totals = Counter(r["quadrant"] for r in rows)
    ml_only = [r for r in rows if r["quadrant"] == "C"]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(), "git": bv._git_commit(), "seed": seed,
        "model": {"name": model.model_name, "version": model.model_version, "threshold": model.threshold, "artifact_dir": str(model_dir)},
        "definitions": __doc__,
        "attack_scenarios": {"total": len(rows), "quadrants": {k: totals.get(k, 0) for k in "ABCD"},
                             "ml_in_scope": sum(r["ml_in_scope"] for r in rows), "ml_only_detections": len(ml_only)},
        "ml_only_scenarios": ml_only,
        "per_behavior": per_behavior,
        "normal_traffic": {
            "events": len(events), "successful_events": len(successes), "ml_scored_events": sum(e["ml_scored"] for e in events),
            "ml_flagged_events": sum(e["ml_detected"] for e in events), "rule_detected_events": sum(e["rule_detected"] for e in events),
            "per_event_quadrants": {k: normal_quadrants.get(k, 0) for k in "ABCD"},
            "ml_false_alarm_rate_on_scored": round(sum(e["ml_detected"] for e in events) / max(1, sum(e["ml_scored"] for e in events)), 4),
            "detection_alerts_by_detector": normal["hybrid_alerts_by_detector"], "legacy_alerts": normal["legacy_alerts_by_type"],
        },
        "verified_behaviors_with_ml_on": regression,
        "all_verified_still_verified": all(v["status"] == "VERIFIED" for b, v in regression.items() if b != "unusual_hour"),
        "rows": rows,
    }


def write(result: dict, out_dir: Path = OUT_DIR) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "rule_ml_overlap.json").write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    a, n = result["attack_scenarios"], result["normal_traffic"]
    lines = [
        "# Luật vs ML trên harness Phase 3 (TỰ SINH bởi `python -m verification.rule_ml_experiment` — đừng sửa tay)", "",
        f"Model `{result['model']['name']}` {result['model']['version']} (ngưỡng {result['model']['threshold']:.4f}), commit `{result['git']['commit']}`.", "",
        f"Kịch bản tấn công: {a['total']} · A (cả hai) {a['quadrants']['A']} · B (chỉ luật) {a['quadrants']['B']} · **C (chỉ ML) {a['quadrants']['C']}** · "
        f"D (không bên nào) {a['quadrants']['D']} · ML có thể chấm {a['ml_in_scope']}/{a['total']}.", "",
        f"Lưu lượng bình thường: {n['events']} lần thử, ML chấm {n['ml_scored_events']}, ML gắn cờ (báo nhầm) {n['ml_flagged_events']} "
        f"({n['ml_false_alarm_rate_on_scored']:.2%} lần được chấm), luật gắn cờ {n['rule_detected_events']}.", "",
        "| Hành vi | Kịch bản | Luật? | ML? | ML trong phạm vi? | Điểm ML (max) | Detector chính | Quyết định cuối | Nhóm |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in result["rows"]:
        lines.append(
            f"| {r['behavior']} | {r['scenario']} | {'có' if r['rule_detected'] else 'không'} | {'có' if r['ml_detected'] else 'không'} | "
            f"{'có' if r['ml_in_scope'] else 'không'} | {'' if r['ml_max_score'] is None else r['ml_max_score']} | {', '.join(r['primary_detectors'])} | "
            f"{r['final_decision']} | {r['quadrant']} |"
        )
    (out_dir / "rule_ml_overlap.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    from ml.anomaly_model import ARTIFACT_DIR

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model-dir", default=str(ARTIFACT_DIR))
    parser.add_argument("--only", default="")
    parser.add_argument("--out-dir", default=str(OUT_DIR))
    args = parser.parse_args(argv)
    logging.disable(logging.WARNING)
    result = run(Path(args.model_dir), behaviors=[b for b in args.only.split(",") if b] or None)
    write(result, Path(args.out_dir))
    a, n = result["attack_scenarios"], result["normal_traffic"]
    print(f"\nKịch bản tấn công {a['total']}: A {a['quadrants']['A']} B {a['quadrants']['B']} C {a['quadrants']['C']} D {a['quadrants']['D']}")
    print(f"Bình thường: ML gắn cờ {n['ml_flagged_events']}/{n['ml_scored_events']} lần được chấm; luật {n['rule_detected_events']}")
    print(f"20 hành vi VERIFIED vẫn đạt khi bật ML: {result['all_verified_still_verified']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
