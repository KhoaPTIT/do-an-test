"""Verification runner (Phase 3, Milestone A): đo từng hành vi qua PIPELINE THẬT theo QUY KẾT, sinh bằng chứng máy đọc.

Với mỗi hành vi: 20 kịch bản dương tính + 20 âm tính (`verification/scenarios.py`, seed cố định), mỗi kịch bản một môi
trường mới (SQLite in-memory + fakeredis + GeoIP/threat intel TEST FIXTURE, `verification/harness.py`). Chạy thêm một
bộ lưu lượng BÌNH THƯỜNG chung (`verification/normal_traffic.py`, 50 người dùng × 30 ngày) để tìm detector quá nhạy.

Chấm điểm (không dùng nhãn trong phát hiện — nhãn chỉ để chấm):
  - TP: kịch bản dương tính có ≥1 alert `hybrid_risk` với `rule_id` == detector kỳ vọng; FN: không có.
  - FP: kịch bản âm tính có alert của detector đó; TN: không có. Alert của detector KHÁC không bao giờ được tính.
  - Quy kết đúng (theo kịch bản dương tính đã phát hiện): MỌI lần thử mà detector kỳ vọng khớp ở chế độ enforce đều có
    `primary_detector` == detector kỳ vọng (đọc từ verdict THẬT pipeline đã tính cho lần thử đó).
  - Báo nhầm trên lưu lượng bình thường: số alert quy kết cho detector đó.
  - VERIFIED ⇔ dương tính ≥ 20, recall ≥ 0,90, FP âm tính ≤ 1/20, 0 báo nhầm trên lưu lượng bình thường, quy kết đúng ≥ 0,90.

Đầu ra (runner TỰ SINH, không sửa tay): `artifacts/behavior_verification/<behavior>.json`, `normal_traffic.json`,
`summary.json` ở gốc repo.

Chạy: cd backend && python -m scripts.behavior_verification [--only brute_force,tor_exit] [--seed 20260302]
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import subprocess
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from verification.harness import VerificationEnv
from verification.normal_traffic import generate as generate_normal_traffic
from verification.scenarios import GENERATORS, T0, Scenario

REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = REPO_ROOT / "artifacts" / "behavior_verification"
N_PER_KIND = 20
CRITERIA = {"min_positive": 20, "min_recall": 0.90, "max_negative_fp": 1, "max_normal_fp": 0, "min_attribution": 0.90}
MILESTONE_A = tuple(GENERATORS)


def _git_commit() -> dict:
    def run(*args):
        return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False).stdout.strip()

    return {"commit": run("rev-parse", "HEAD") or None, "dirty": bool(run("status", "--porcelain", "--untracked-files=no"))}


def _setup(env: VerificationEnv, accounts, history, blocks=()) -> None:
    for name in dict.fromkeys(accounts):
        env.add_user(name)
    for h in history:
        env.add_history(h.username, ip=h.ip, ts=T0 + timedelta(seconds=h.offset_s), user_agent=h.user_agent, success=h.success)
    for b in blocks:
        env.add_block(b.kind, b.value, expires_at=None if b.expires_offset_s is None else T0 + timedelta(seconds=b.expires_offset_s))


def run_scenario(sc: Scenario) -> dict:
    env = VerificationEnv()
    _setup(env, sc.accounts, sc.history, sc.blocks)
    for step in sc.steps:
        env.login(step.username, success=step.success, ip=step.ip, ts=T0 + timedelta(seconds=step.offset_s), user_agent=step.user_agent)

    alerts = env.alerts()
    hits = [a for a in alerts if a.alert_type == "hybrid_risk" and a.rule_id == sc.behavior]
    matching = [v for v in env.verdicts if sc.behavior in v.enforced_rules]
    misattributed = [v.primary_detector for v in matching if v.primary_detector != sc.behavior]
    return {
        "kind": sc.kind, "variant": sc.variant, "steps": len(sc.steps),
        "detected": bool(hits),
        "attribution_events": len(matching), "misattributed_to": misattributed,
        "alerts_by_detector": dict(Counter(a.rule_id or a.alert_type for a in alerts if a.alert_type == "hybrid_risk")),
        "legacy_alerts": dict(Counter(a.alert_type for a in alerts if a.alert_type != "hybrid_risk")),
        "example_alert": hits[0].as_dict() if hits else None,
    }


def evaluate_behavior(behavior: str, seed: int, normal_fp: int) -> dict:
    positive_gen, negative_gen = GENERATORS[behavior]
    rng = random.Random(f"{seed}:{behavior}")
    positives = [run_scenario(positive_gen(rng, i)) for i in range(N_PER_KIND)]
    negatives = [run_scenario(negative_gen(rng, i)) for i in range(N_PER_KIND)]

    tp = sum(r["detected"] for r in positives)
    fn = len(positives) - tp
    fp = sum(r["detected"] for r in negatives)
    tn = len(negatives) - fp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / len(positives) if positives else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    detected = [r for r in positives if r["detected"]]
    attributed_ok = sum(1 for r in detected if r["attribution_events"] > 0 and not r["misattributed_to"])
    attribution = attributed_ok / len(detected) if detected else 0.0

    failures = []
    if len(positives) < CRITERIA["min_positive"]:
        failures.append(f"chỉ {len(positives)} kịch bản dương tính")
    if recall < CRITERIA["min_recall"]:
        failures.append(f"recall {recall:.2f} < {CRITERIA['min_recall']}")
    if fp > CRITERIA["max_negative_fp"]:
        failures.append(f"FP âm tính {fp}/{len(negatives)} > {CRITERIA['max_negative_fp']}")
    if normal_fp > CRITERIA["max_normal_fp"]:
        failures.append(f"{normal_fp} báo nhầm trên lưu lượng bình thường")
    if attribution < CRITERIA["min_attribution"]:
        failures.append(f"quy kết đúng {attribution:.2f} < {CRITERIA['min_attribution']}")

    return {
        "behavior": behavior, "detector": behavior,
        "status": "VERIFIED" if not failures else "FAILED_CRITERIA", "failed_criteria": failures,
        "scenario_count": {"positive": len(positives), "negative": len(negatives)},
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
        "attribution_accuracy": round(attribution, 4), "attribution_correct": attributed_ok, "attribution_total": len(detected),
        "normal_traffic_false_alerts": normal_fp,
        "cross_detector_alerts_in_positives": dict(sum((Counter(r["alerts_by_detector"]) for r in positives), Counter())),
        "example_alert": next((r["example_alert"] for r in positives if r["example_alert"]), None),
        "scenarios": [{k: v for k, v in r.items() if k != "example_alert"} for r in positives + negatives],
    }


def run_normal_traffic(seed: int) -> dict:
    traffic = generate_normal_traffic(seed)
    env = VerificationEnv()
    _setup(env, traffic.accounts, traffic.history)
    for step in traffic.steps:
        env.login(step.username, success=step.success, ip=step.ip, ts=T0 + timedelta(seconds=step.offset_s), user_agent=step.user_agent)
    alerts = env.alerts()
    by_detector = Counter(a.rule_id or "hybrid_ml" for a in alerts if a.alert_type == "hybrid_risk")
    return {
        "seed": seed, "profile": dict(traffic.profile_counts),
        "hybrid_alerts_by_detector": dict(by_detector),
        "legacy_alerts_by_type": dict(Counter(a.alert_type for a in alerts if a.alert_type != "hybrid_risk")),
        "examples": [a.as_dict() for a in alerts if a.alert_type == "hybrid_risk"][:10],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only", default="", help="danh sách hành vi, phân tách bằng dấu phẩy (mặc định: toàn bộ Milestone A)")
    parser.add_argument("--seed", type=int, default=20260302)
    args = parser.parse_args(argv)
    logging.disable(logging.WARNING)  # log cảnh báo "thiếu model ML" lặp lại mỗi kịch bản — không liên quan kết quả

    behaviors = [b for b in args.only.split(",") if b] or list(MILESTONE_A)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    meta = {"generated_at": datetime.now(timezone.utc).isoformat(), "git": _git_commit(), "seed": args.seed, "criteria": CRITERIA,
            "environment": "SQLite in-memory + fakeredis; GeoIP/threat intel = TEST FIXTURE (RFC 5737); hybrid ML component disabled (fallback profile)"}

    print("Chạy lưu lượng bình thường (50 người dùng × 30 ngày)...", flush=True)
    normal = run_normal_traffic(args.seed)
    (OUT_DIR / "normal_traffic.json").write_text(json.dumps({**meta, **normal}, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print(f"  alert quy kết theo detector: {normal['hybrid_alerts_by_detector'] or 'không có'}")

    summary = []
    for behavior in behaviors:
        result = evaluate_behavior(behavior, args.seed, normal["hybrid_alerts_by_detector"].get(behavior, 0))
        (OUT_DIR / f"{behavior}.json").write_text(json.dumps({**meta, **result}, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        summary.append({k: result[k] for k in ("behavior", "status", "failed_criteria", "tp", "fp", "tn", "fn", "precision", "recall", "f1", "attribution_accuracy", "normal_traffic_false_alerts")})
        print(
            f"\n{'=' * 40}\n{behavior.upper()}\n{'=' * 40}\n"
            f"Positive scenarios: {result['scenario_count']['positive']}  Detected correctly: {result['tp']}\n"
            f"TP: {result['tp']}  FN: {result['fn']}\n"
            f"Negative scenarios: {result['scenario_count']['negative']}  FP: {result['fp']}  TN: {result['tn']}\n"
            f"Precision: {result['precision']:.2f}  Recall: {result['recall']:.2f}  F1: {result['f1']:.3f}\n"
            f"Correct attribution: {result['attribution_correct']}/{result['attribution_total']}\n"
            f"Normal-traffic false alerts: {result['normal_traffic_false_alerts']}\n"
            f"STATUS: {result['status']}" + (f"  ({'; '.join(result['failed_criteria'])})" if result["failed_criteria"] else ""),
            flush=True,
        )

    (OUT_DIR / "summary.json").write_text(json.dumps({**meta, "behaviors": summary, "verified": sum(s["status"] == "VERIFIED" for s in summary)}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nVERIFIED: {sum(s['status'] == 'VERIFIED' for s in summary)}/{len(summary)} — bằng chứng: {OUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
