"""Verification runner (Phase 3, Milestone A): đo từng hành vi qua PIPELINE THẬT theo QUY KẾT, sinh bằng chứng máy đọc.

Với mỗi hành vi: 20 kịch bản dương tính + 20 âm tính (`verification/scenarios.py`, seed cố định), mỗi kịch bản một môi
trường mới (SQLite in-memory + fakeredis + GeoIP/threat intel TEST FIXTURE, `verification/harness.py`). Chạy thêm một
bộ lưu lượng BÌNH THƯỜNG chung (`verification/normal_traffic.py`, 63 người dùng × 30 ngày) để tìm detector quá nhạy.

Chấm điểm (không dùng nhãn trong phát hiện — nhãn chỉ để chấm):
  - TP: kịch bản dương tính có ≥1 alert `hybrid_risk` với `rule_id` == detector kỳ vọng; FN: không có.
  - FP: kịch bản âm tính có alert của detector đó; TN: không có. Alert của detector KHÁC không bao giờ được tính.
  - Quy kết đúng (theo kịch bản dương tính đã phát hiện): MỌI lần thử mà detector kỳ vọng khớp ở chế độ enforce đều có
    `primary_detector` == detector kỳ vọng (đọc từ verdict THẬT pipeline đã tính cho lần thử đó).
  - Báo nhầm trên lưu lượng bình thường: số alert quy kết cho detector đó.
  - VERIFIED ⇔ dương tính ≥ 20, recall ≥ 0,90, FP âm tính ≤ 1/20, 0 báo nhầm trên lưu lượng bình thường, quy kết đúng ≥ 0,90.

Đầu ra (runner TỰ SINH, không sửa tay): `artifacts/behavior_verification/<behavior>.json`, `normal_traffic.json`,
`summary.json` ở gốc repo. Lần chạy đầy đủ sinh thêm `cross_behavior_results.json`, `alert_noise_*.json`,
`milestone_cplus_summary.json` (tổng hợp cuối: 17 hành vi baseline, 3 hành vi Milestone C+, mức thử thách của lưu lượng
bình thường), `unusual_hour_comparison.json` và `unusual_hour_fp_analysis.json` (Milestone C.1: detector
unusual_hour cũ 3σ và hiện tại, ở trạng thái ứng viên, trên cùng bộ đánh giá).

Detector ỨNG VIÊN (`--candidates`, Milestone B): luật chưa `verified` không tự tạo cảnh báo ở runtime (B0.1), nên để đo
được nó, runner chạy nó ở ĐÚNG trạng thái nó sẽ có nếu được nâng cấp (enforce + verified) — CHỈ trong tiến trình runner,
không ghi gì vào registry. Mọi kịch bản VÀ lưu lượng bình thường chạy với toàn bộ ứng viên cùng bật (trường hợp nhiễu
nhất). Registry (`verification=` trên luật) chỉ được sửa tay SAU KHI runner báo VERIFIED — test
`test_registry_verified_status_matches_committed_verification_evidence` chặn việc nâng trạng thái không có bằng chứng.

Đo nhiễu cảnh báo (B9), trên các kịch bản dương tính: tổng số hàng alert (gồm alert tầng 1/2/3 cũ), số cảnh báo phát
hiện có quy kết, số tín hiệu phụ, số lần thử bị gộp vào cảnh báo sẵn có (`duplicate_suppressed` = Σ(occurrence_count−1)),
số cảnh báo trung bình mỗi chiến dịch tấn công.

Chạy: cd backend && python -m scripts.behavior_verification [--only brute_force,tor_exit] [--candidates country_hop] [--seed 20260302]
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

from verification.harness import DETECTION_ALERT_TYPES, VerificationEnv
from verification.normal_traffic import generate as generate_normal_traffic
from verification.scenarios import GENERATORS, T0, Scenario

REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = REPO_ROOT / "artifacts" / "behavior_verification"
N_PER_KIND = 20
CRITERIA = {"min_positive": 20, "min_recall": 0.90, "max_negative_fp": 1, "max_normal_fp": 0, "min_attribution": 0.90}
ALL_BEHAVIORS = tuple(GENERATORS)  # Milestone A + các hành vi Milestone B đã có bộ sinh


def _git_commit() -> dict:
    def run(*args):
        return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False).stdout.strip()

    # thư mục bằng chứng (artifacts/) bị loại khỏi kiểm tra: runner tự ghi đè nó, không phải mã phát hiện
    return {"commit": run("rev-parse", "HEAD") or None, "dirty": bool(run("status", "--porcelain", "--untracked-files=no", "--", ".", ":!artifacts"))}


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
    detection = [a for a in alerts if a.alert_type in DETECTION_ALERT_TYPES]
    hits = [a for a in detection if a.rule_id == sc.behavior]
    # verdict THẬT từng lần thử mà detector kỳ vọng đủ tư cách tự cảnh báo (enforce + verified/ứng viên)
    matching = [v for v in env.verdicts if sc.behavior in getattr(v, "standalone_rules", v.enforced_rules)]
    misattributed = [v.primary_detector for v in matching if v.primary_detector != sc.behavior]
    return {
        "kind": sc.kind, "variant": sc.variant, "steps": len(sc.steps),
        "detected": bool(hits),
        "attribution_events": len(matching), "misattributed_to": misattributed,
        "alerts_by_detector": dict(Counter(a.rule_id or "hybrid_ml" for a in detection)),
        "legacy_alerts": dict(Counter(a.alert_type for a in alerts if a.alert_type not in DETECTION_ALERT_TYPES)),
        "noise": {
            "total_alerts": len(alerts),
            "detection_alerts": len(detection),
            "legacy_alerts": len(alerts) - len(detection),
            "secondary_signals": sum(len((a.explanation or {}).get("secondary_signals", [])) for a in detection),
            "duplicate_suppressed": sum(a.occurrence_count - 1 for a in detection),
            "superseded_detectors": sum(len((a.explanation or {}).get("superseded_detectors", [])) for a in detection),
        },
        "example_alert": hits[0].as_dict() if hits else None,
    }


def _noise_summary(results: list[dict]) -> dict:
    keys = ("total_alerts", "detection_alerts", "legacy_alerts", "secondary_signals", "duplicate_suppressed", "superseded_detectors")
    totals = {k: sum(r["noise"][k] for r in results) for k in keys}
    n = len(results) or 1
    totals["campaigns"] = len(results)
    totals["alerts_per_attack_campaign"] = round(totals["detection_alerts"] / n, 3)
    totals["all_alert_rows_per_attack_campaign"] = round(totals["total_alerts"] / n, 3)
    return totals


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
        "alert_noise_positive_scenarios": _noise_summary(positives),
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
    detection = [a for a in alerts if a.alert_type in DETECTION_ALERT_TYPES]
    by_detector = Counter(a.rule_id or "hybrid_ml" for a in detection)
    return {
        "seed": seed, "profile": dict(traffic.profile_counts),
        "hybrid_alerts_by_detector": dict(by_detector),
        "legacy_alerts_by_type": dict(Counter(a.alert_type for a in alerts if a.alert_type not in DETECTION_ALERT_TYPES)),
        "examples": [a.as_dict() for a in detection][:10],
    }


BASELINE_VERIFIED = (
    "brute_force", "credential_stuffing", "blocklist_hit", "impossible_travel", "username_enumeration",
    "password_spray_slow", "distributed_bruteforce", "success_after_failures", "dormant_account_login", "tor_exit",
)  # 10 hành vi VERIFIED sau Milestone A (đã được người dùng xác nhận)
MILESTONE_B = ("country_hop", "ua_rotation", "scripted_client", "bot_user_agent", "unusual_device")
BASELINE_AFTER_B = BASELINE_VERIFIED + MILESTONE_B  # 15 hành vi VERIFIED sau Milestone B (đã được người dùng xác nhận)
MILESTONE_C = ("unusual_location", "unusual_hour", "login_velocity_spike")
BASELINE_AFTER_C = BASELINE_AFTER_B + ("unusual_location", "login_velocity_spike")  # 17 hành vi VERIFIED sau Milestone C (đã được người dùng xác nhận)
MILESTONE_CPLUS = ("regular_rhythm", "rare_network_login", "multi_context_simultaneous")  # milestone bổ sung hành vi CUỐI CÙNG
NOISE_BASELINE_DIR = REPO_ROOT / "artifacts" / "noise_baselines"  # summary.json do CHÍNH runner này sinh ở hai mốc trước (xem README ở đó)


def run_cross_behavior() -> list[dict]:
    from verification.cross_behavior import CASES, evaluate

    return [evaluate(case, VerificationEnv()) for case in CASES]


def noise_comparison(final_summary: list[dict]) -> dict:
    """So sánh nhiễu cảnh báo trên CÙNG bộ kịch bản dương tính (cùng seed) ở ba mốc: trước B0 (mã Milestone A), sau B0, và
    lần chạy hiện tại. Hai mốc đầu đọc từ summary.json runner đã sinh lúc đó (`artifacts/noise_baselines/`)."""
    def load(name):
        path = NOISE_BASELINE_DIR / f"{name}_summary.json"
        if not path.is_file():
            return None, {}
        data = json.loads(path.read_text(encoding="utf-8"))
        return {"git": data.get("git"), "generated_at": data.get("generated_at")}, {b["behavior"]: b.get("alert_noise_positive_scenarios") for b in data.get("behaviors", [])}

    before_meta, before = load("before_b0")
    after_meta, after = load("after_b0")
    final = {b["behavior"]: b.get("alert_noise_positive_scenarios") for b in final_summary}
    rows = {name: {"before_b0": before.get(name), "after_b0": after.get(name), "current": final.get(name)} for name in final}
    keys = ("total_alerts", "detection_alerts", "legacy_alerts", "secondary_signals", "duplicate_suppressed")

    def total(stage, names):
        vals = [rows[n][stage] for n in names if rows[n][stage]]
        return {k: sum(v[k] for v in vals) for k in keys} | {"behaviors_counted": len(vals)} if vals else None

    common = [n for n in BASELINE_VERIFIED if n in rows]
    return {
        "note": "kịch bản dương tính, cùng seed; alert_per_campaign = detection_alerts / số kịch bản. legacy = alert tầng 1/2/3 cũ (không qua gộp chiến dịch).",
        "stages": {"before_b0": before_meta, "after_b0": after_meta},
        "baseline_10_totals": {"before_b0": total("before_b0", common), "after_b0": total("after_b0", common), "current": total("current", common)},
        "per_behavior": rows,
    }


def normal_traffic_exposure(seed: int) -> dict:
    """Lưu lượng bình thường THỬ THÁCH các detector Milestone C+ tới đâu — tính thẳng từ dữ liệu sinh ra (không qua detector),
    để biết "0 báo nhầm" là bằng chứng mạnh hay chỉ vì không có tình huống nào gần ngưỡng."""
    import statistics
    from collections import defaultdict

    from verification.fixtures import fixture_lookup_asn, fixture_lookup_ip

    traffic = generate_normal_traffic(seed)
    steps = sorted(traffic.steps, key=lambda st: st.offset_s)
    # regular_rhythm: khoảng cách trung bình nhỏ nhất trên 10 lần sai liên tiếp của một IP
    fails = defaultdict(list)
    for st in steps:
        if not st.success:
            fails[st.ip].append(st.offset_s)
    means = [statistics.fmean([b - a for a, b in zip(ts[k - 9:k], ts[k - 8:k + 1])]) for ts in fails.values() for k in range(9, len(ts))]
    # rare_network_login: lần thành công của tài khoản trưởng thành từ ASN mới với chính nó (WARM), kèm tỉ lệ toàn hệ thống
    events = sorted([(h.offset_s, h.username, h.ip) for h in traffic.history if h.success] + [(st.offset_s, st.username, st.ip) for st in steps if st.success])
    known, count, first, by_asn, total, new_asn_shares = defaultdict(set), defaultdict(int), {}, defaultdict(int), 0, []
    for ts, user, ip in events:
        a = fixture_lookup_asn(ip)
        asn = a.asn if a else None
        if ts >= 0 and asn is not None and total >= 500 and count[user] >= 10 and ts - first[user] >= 7 * 86_400 and asn not in known[user]:
            new_asn_shares.append(round(by_asn[asn] / total, 4))
        if asn is not None:
            known[user].add(asn)
            by_asn[asn] += 1
        count[user] += 1
        first.setdefault(user, ts)
        total += 1
    # multi_context_simultaneous: cặp đăng nhập thành công của cùng tài khoản ở hai quốc gia cách nhau ≤ 1 giờ
    recent, pairs = defaultdict(list), []
    for st in (st for st in steps if st.success):
        g = fixture_lookup_ip(st.ip)
        country = g.country if g else None
        recent[st.username] = [(t, c) for t, c in recent[st.username] if st.offset_s - t <= 3600]
        pairs += [round(st.offset_s - t) for t, c in recent[st.username] if country and c and c != country]
        recent[st.username].append((st.offset_s, country))
    return {
        "regular_rhythm": {"ips_with_10plus_failures": sum(1 for ts in fails.values() if len(ts) >= 10),
                           "min_mean_interval_over_10_failures_s": round(min(means), 1) if means else None, "threshold_s": 30},
        "rare_network_login": {"mature_account_logins_from_asn_new_to_account": len(new_asn_shares), "their_global_shares": sorted(new_asn_shares), "warm_threshold": 0.01},
        "multi_context_simultaneous": {"success_pairs_two_countries_within_1h": len(pairs), "gaps_s": sorted(pairs)[:10], "window_s": 600},
    }


def run_unusual_hour_study(seed: int) -> dict[str, dict]:
    """Milestone C.1: detector unusual_hour CŨ (3σ) và HIỆN TẠI ở trạng thái ứng viên, trên CÙNG bộ đánh giá — mỗi detector
    một tiến trình riêng (`verification/unusual_hour_study.py`: detector được cài trước khi dựng bất kỳ pipeline nào)."""
    import tempfile

    results = {}
    with tempfile.TemporaryDirectory() as tmp:
        for detector in ("legacy_sigma", "current"):
            print(f"Nghiên cứu unusual_hour: detector {detector}...", flush=True)
            subprocess.run([sys.executable, "-m", "verification.unusual_hour_study", "--detector", detector, "--seed", str(seed), "--out", tmp],
                           cwd=Path(__file__).resolve().parents[1], check=True)
            results[detector] = json.loads((Path(tmp) / f"{detector}.json").read_text(encoding="utf-8"))
    return results


def write_unusual_hour_study(out_dir: Path, meta: dict, study: dict[str, dict]) -> dict:
    from verification.unusual_hour_study import classify

    rows = ("tp", "fn", "recall", "fp", "normal_traffic_false_alerts", "attribution_accuracy", "status", "failed_criteria")
    label = {"tp": "TP", "fn": "FN", "recall": "Recall", "fp": "Scenario FP", "normal_traffic_false_alerts": "Normal Traffic FP", "attribution_accuracy": "Attribution", "status": "Status", "failed_criteria": "Failed criteria"}
    comparison = {
        **meta,
        "dataset": "CÙNG bộ đánh giá cho cả hai: 20 kịch bản dương tính + 20 âm tính của unusual_hour (seed cố định) và lưu lượng bình thường v3 (63 người dùng × 30 ngày); cả hai chạy ở trạng thái ứng viên (enforce + verified) chỉ trong tiến trình đo",
        "old_detector": "3σ vòng tròn quanh giờ trung tâm (Milestone C, a58bc12) — verification.unusual_hour_study.legacy_sigma_unusual_hour",
        "new_detector": "histogram 24 giờ làm mượt vòng tròn (app/detection/engine/rules_behavior.py::unusual_hour)",
        "table": {label[k]: {"OLD": study["legacy_sigma"]["metrics"][k], "NEW": study["current"]["metrics"][k]} for k in rows},
        "normal_traffic_false_positive_groups": {"OLD": study["legacy_sigma"]["false_positive_groups"], "NEW": study["current"]["false_positive_groups"]},
        "studies_git": {d: study[d]["git"] for d in study},
    }
    (out_dir / "unusual_hour_comparison.json").write_text(json.dumps(comparison, ensure_ascii=False, indent=2), encoding="utf-8")
    keys = ("detector", "metrics", "normal_traffic_firing_attempts", "false_positive_groups", "false_positives_by_role", "false_positives")
    (out_dir / "unusual_hour_fp_analysis.json").write_text(json.dumps({
        **meta, "group_definitions": classify.__doc__, **{d: {k: study[d][k] for k in keys} for d in study},
    }, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return comparison


def promote_candidates(candidates: list[str]) -> None:
    """Bật detector ứng viên ở trạng thái như SAU khi được nâng cấp (enforce + verified) — chỉ trong tiến trình này."""
    import dataclasses

    from app.detection.engine.registry import REGISTRY

    for rule_id in candidates:
        REGISTRY[rule_id] = dataclasses.replace(REGISTRY[rule_id], verification="verified", default_mode="enforce")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only", default="", help="danh sách hành vi, phân tách bằng dấu phẩy (mặc định: mọi hành vi có bộ sinh)")
    parser.add_argument("--seed", type=int, default=20260302)
    parser.add_argument("--out-dir", default=str(OUT_DIR), help="thư mục ghi bằng chứng (mặc định artifacts/behavior_verification)")
    parser.add_argument("--candidates", default="", help="detector ứng viên chạy ở trạng thái enforce+verified trong runner (xem docstring)")
    args = parser.parse_args(argv)
    candidates = [c for c in args.candidates.split(",") if c]
    promote_candidates(candidates)
    out_dir = Path(args.out_dir)
    logging.disable(logging.WARNING)  # log cảnh báo "thiếu model ML" lặp lại mỗi kịch bản — không liên quan kết quả

    behaviors = [b for b in args.only.split(",") if b] or list(ALL_BEHAVIORS)
    out_dir.mkdir(parents=True, exist_ok=True)
    meta = {"generated_at": datetime.now(timezone.utc).isoformat(), "git": _git_commit(), "seed": args.seed, "criteria": CRITERIA, "candidates_promoted_in_runner": candidates,
            "environment": "SQLite in-memory + fakeredis; GeoIP/threat intel = TEST FIXTURE (RFC 5737); hybrid ML component disabled (fallback profile)"}

    print("Chạy lưu lượng bình thường (63 người dùng × 30 ngày)...", flush=True)
    normal = run_normal_traffic(args.seed)
    (out_dir / "normal_traffic.json").write_text(json.dumps({**meta, **normal}, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print(f"  alert quy kết theo detector: {normal['hybrid_alerts_by_detector'] or 'không có'}")

    summary = []
    for behavior in behaviors:
        result = evaluate_behavior(behavior, args.seed, normal["hybrid_alerts_by_detector"].get(behavior, 0))
        (out_dir / f"{behavior}.json").write_text(json.dumps({**meta, **result}, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        summary.append({k: result[k] for k in ("behavior", "status", "failed_criteria", "tp", "fp", "tn", "fn", "precision", "recall", "f1", "attribution_accuracy", "normal_traffic_false_alerts", "alert_noise_positive_scenarios")})
        print(
            f"\n{'=' * 40}\n{behavior.upper()}\n{'=' * 40}\n"
            f"Positive scenarios: {result['scenario_count']['positive']}  Detected correctly: {result['tp']}\n"
            f"TP: {result['tp']}  FN: {result['fn']}\n"
            f"Negative scenarios: {result['scenario_count']['negative']}  FP: {result['fp']}  TN: {result['tn']}\n"
            f"Precision: {result['precision']:.2f}  Recall: {result['recall']:.2f}  F1: {result['f1']:.3f}\n"
            f"Correct attribution: {result['attribution_correct']}/{result['attribution_total']}\n"
            f"Normal-traffic false alerts: {result['normal_traffic_false_alerts']}\n"
            f"Noise (positives): {result['alert_noise_positive_scenarios']}\n"
            f"STATUS: {result['status']}" + (f"  ({'; '.join(result['failed_criteria'])})" if result["failed_criteria"] else ""),
            flush=True,
        )

    if args.only:  # chạy một phần: gộp vào summary sẵn có thay vì ghi đè kết quả các hành vi khác
        previous = out_dir / "summary.json"
        if previous.is_file():
            kept = [b for b in json.loads(previous.read_text(encoding="utf-8")).get("behaviors", []) if b["behavior"] not in behaviors]
            summary = kept + summary
    (out_dir / "summary.json").write_text(json.dumps({**meta, "behaviors": summary, "verified": sum(s["status"] == "VERIFIED" for s in summary)}, ensure_ascii=False, indent=2), encoding="utf-8")

    if not args.only:  # chỉ lần chạy ĐẦY ĐỦ mới sinh báo cáo tổng hợp (milestone, cross-behavior, nhiễu, nghiên cứu unusual_hour)
        cross = run_cross_behavior()
        (out_dir / "cross_behavior_results.json").write_text(json.dumps({**meta, "cases": cross, "passed": sum(c["passed"] for c in cross), "total": len(cross)}, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nCross-behavior: {sum(c['passed'] for c in cross)}/{len(cross)} ca đúng quy kết")
        by_name = {s["behavior"]: s for s in summary}
        verified = sorted(s["behavior"] for s in summary if s["status"] == "VERIFIED")
        fields = ("status", "failed_criteria", "tp", "fp", "tn", "fn", "precision", "recall", "f1", "attribution_accuracy", "normal_traffic_false_alerts")
        study = run_unusual_hour_study(args.seed) if "unusual_hour" in behaviors else None
        hour_comparison = write_unusual_hour_study(out_dir, meta, study) if study else None
        from app.detection.engine.registry import REGISTRY

        new_hour = study["current"]["metrics"] if study else None
        official_hour = by_name.get("unusual_hour", {})
        (out_dir / "milestone_cplus_summary.json").write_text(json.dumps({
            **meta,
            "baseline_verified": list(BASELINE_AFTER_C),
            "baseline_still_verified": {b: by_name.get(b, {}).get("status") == "VERIFIED" for b in BASELINE_AFTER_C},
            "all_baseline_still_verified": all(by_name.get(b, {}).get("status") == "VERIFIED" for b in BASELINE_AFTER_C),
            "milestone_cplus": {b: {"registry_verification": REGISTRY[b].verification, "default_mode": REGISTRY[b].default_mode,
                                    **({k: by_name[b][k] for k in fields} if b in by_name else {"status": "NOT_RUN"})} for b in MILESTONE_CPLUS},
            "normal_traffic_exposure": normal_traffic_exposure(args.seed),
            "unusual_hour": {
                "registry_verification": REGISTRY["unusual_hour"].verification,
                "official_run": {k: official_hour[k] for k in fields} if official_hour else {"status": "NOT_RUN"},
                "candidate_old_3sigma": study["legacy_sigma"]["metrics"] if study else None,
                "candidate_new_histogram": new_hour,
                "candidate_new_meets_verified_criteria": bool(new_hour and new_hour["status"] == "VERIFIED"),
                "status": "VERIFIED" if official_hour.get("status") == "VERIFIED" else "PARTIAL",
                "comparison_table": hour_comparison["table"] if hour_comparison else None,
            },
            "verified_count": len(verified), "verified": verified,
            "not_verified": sorted(s["behavior"] for s in summary if s["status"] != "VERIFIED"),
            "cross_behavior_passed": f"{sum(c['passed'] for c in cross)}/{len(cross)}",
            "normal_traffic": {"total_steps": normal["profile"].get("total_steps"), "history_logins": normal["profile"].get("history_logins"), "users": normal["profile"].get("users"),
                               "detector_false_alerts": normal["hybrid_alerts_by_detector"], "legacy_alerts": normal["legacy_alerts_by_type"]},
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        comparison = noise_comparison(summary)
        (out_dir / "alert_noise_comparison.json").write_text(json.dumps({**meta, **comparison}, ensure_ascii=False, indent=2), encoding="utf-8")
        keys = ("total_alerts", "detection_alerts", "legacy_alerts", "secondary_signals", "duplicate_suppressed")
        all_rows = [s["alert_noise_positive_scenarios"] for s in summary if s.get("alert_noise_positive_scenarios")]
        (out_dir / "alert_noise_final.json").write_text(json.dumps({
            **meta,
            "note": "Đo trên kịch bản dương tính của MỌI hành vi trong lần chạy này. legacy = alert tầng 1/2/3 cũ (không qua gộp chiến dịch) — chỉ đo, không refactor (Milestone C — C12, C.1 §15).",
            "all_behaviors_positive_totals": {k: sum(r[k] for r in all_rows) for k in keys} | {"campaigns": sum(r["campaigns"] for r in all_rows)},
            "baseline_10_comparison": comparison["baseline_10_totals"],
            "per_behavior": {s["behavior"]: s.get("alert_noise_positive_scenarios") for s in summary},
            "normal_traffic": {"detection_alerts": normal["hybrid_alerts_by_detector"], "legacy_alerts": normal["legacy_alerts_by_type"]},
        }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nVERIFIED: {sum(s['status'] == 'VERIFIED' for s in summary)}/{len(summary)} — bằng chứng: {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
