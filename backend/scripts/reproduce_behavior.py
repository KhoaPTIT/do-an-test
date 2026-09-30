"""Tái hiện MỘT hành vi qua pipeline thật và in kết quả dễ đọc (bổ trợ cho `scripts/behavior_verification.py`).

Chạy 1 kịch bản dương tính + 1 kịch bản âm tính (seed cố định, cùng bộ sinh với runner) rồi in:

    [EXPECTED] password_spray_slow
    [DETECTED] password_spray_slow
    Risk Score: 5   Alert: YES   Reason: rule_enforced
    Evidence: {...}
    PASS

Chạy: cd backend && python -m scripts.reproduce_behavior password_spray_slow [--seed 1] [--index 0]
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
from datetime import timedelta

from scripts.behavior_verification import _setup
from verification.harness import VerificationEnv
from verification.scenarios import GENERATORS, T0


def _run(sc) -> list:
    env = VerificationEnv()
    _setup(env, sc.accounts, sc.history, sc.blocks)
    for step in sc.steps:
        env.login(step.username, success=step.success, ip=step.ip, ts=T0 + timedelta(seconds=step.offset_s), user_agent=step.user_agent)
    return [a for a in env.alerts() if a.alert_type == "hybrid_risk"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("behavior", choices=sorted(GENERATORS))
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--index", type=int, default=0, help="biến thể thứ mấy của bộ sinh")
    args = parser.parse_args(argv)
    logging.disable(logging.WARNING)

    positive_gen, negative_gen = GENERATORS[args.behavior]
    ok = True
    for label, gen, expect_alert in (("TẤN CÔNG", positive_gen, True), ("BÌNH THƯỜNG / SÁT NGƯỠNG", negative_gen, False)):
        sc = gen(random.Random(args.seed), args.index)
        alerts = _run(sc)
        own = [a for a in alerts if a.rule_id == args.behavior]
        others = sorted({a.rule_id or "hybrid_ml" for a in alerts if a.rule_id != args.behavior})
        print(f"\n--- {label}: {sc.variant} ({len(sc.steps)} lần thử) ---")
        print(f"[EXPECTED] {args.behavior if expect_alert else f'KHÔNG có alert {args.behavior}'}")
        print(f"[DETECTED] {', '.join(a.rule_id for a in own[:1]) or '(không có alert của detector này)'}")
        if own:
            exp = own[0].explanation
            print(f"Risk Score: {exp['risk_score']}   Alert: YES   Reason: {exp['alert_reason']}   Severity: {own[0].severity}")
            print(f"Matched rules: {exp['matched_rules']}")
            print(f"Evidence: {json.dumps(exp['evidence'], ensure_ascii=False)}")
        if others:
            print(f"Alert của detector KHÁC (không tính): {others}")
        passed = bool(own) == expect_alert
        ok &= passed
        print("PASS" if passed else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
