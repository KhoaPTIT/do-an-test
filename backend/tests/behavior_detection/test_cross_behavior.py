"""Milestone B — B8: ma trận cross-behavior (định nghĩa ở verification/cross_behavior.py). Mỗi ca: đúng MỘT cảnh báo
chiến dịch, quy cho detector cụ thể nhất, các detector còn lại nằm trong secondary_signals."""

import pytest

from verification.cross_behavior import CASES, evaluate

CANDIDATES = ()  # mọi detector trong ma trận đều đã verified trong registry


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_cross_behavior_attribution(env, as_candidate, case):
    as_candidate(*CANDIDATES)
    result = evaluate(case, env)
    assert result["detection_alerts"] == [case.expected_primary], result
    assert result["missing_secondary"] == [], result
    assert result["passed"]
