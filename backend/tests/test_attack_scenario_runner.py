"""MR18 — kiểm tra phần THUẦN (tổng hợp số đo, viết báo cáo) của scripts/attack_scenario_runner.py bằng ScenarioOutcome
tự dựng, KHÔNG gọi `run_scenario()`/`_wire()` thật — CÙNG lý do `tests/test_alert_intelligence_sim.py` (MR13) không gọi
`run_simulation()` thật: `_wire()` trỏ thẳng state DÙNG CHUNG cho cả tiến trình, chạy trong pytest sẽ rò rỉ sang test
khác. Chạy scorecard thật: `python -m scripts.attack_scenario_runner` (độc lập, xem docs/attack-scenarios-v2.md)."""

from scripts.attack_scenario_runner import ScenarioOutcome, build_payload, render


def _o(id_, *, expect_detectable=True, detected, first_step=None, total_steps=5, alerts=0, mechanisms=()) -> ScenarioOutcome:
    return ScenarioOutcome(
        id=id_, title=f"kịch bản {id_}", rule_hint="some_rule", expect_detectable=expect_detectable,
        total_attack_steps=total_steps, detected=detected, first_detected_step=first_step, total_alerts=alerts, mechanisms=list(mechanisms),
    )


def test_summary_counts_only_expected_detectable_scenarios():
    outcomes = [
        _o("a", detected=True, first_step=1, alerts=2, mechanisms=["brute_force"]),
        _o("b", detected=False),
        _o("c", expect_detectable=False, detected=False),  # cố ý khó — KHÔNG tính vào mẫu số
    ]
    payload = build_payload(outcomes)
    report = render(payload)

    assert "1/2" in report  # 1 trong 2 kịch bản (a, b) kỳ vọng phát hiện được đã thực sự có alert; c không tính
    assert "kịch bản b" in report  # bị liệt kê là bỏ sót NGOÀI dự kiến


def test_no_unexpected_misses_renders_a_reassuring_line_not_a_warning():
    outcomes = [_o("a", detected=True, first_step=1, alerts=1), _o("b", expect_detectable=False, detected=False)]
    report = render(build_payload(outcomes))

    assert "Không có kịch bản nào bị bỏ sót NGOÀI dự kiến" in report
    assert "⚠️" not in report.split("## Scorecard")[0]  # không có cảnh báo giả trong phần "Kết quả chính"


def test_scorecard_table_marks_detected_missed_and_intentionally_hard_differently():
    outcomes = [
        _o("caught", detected=True, first_step=3, total_steps=10, alerts=4, mechanisms=["brute_force", "brute_force"]),
        _o("missed", detected=False),
        _o("hard", expect_detectable=False, detected=False),
    ]
    report = render(build_payload(outcomes))

    assert "| kịch bản caught | `some_rule` | ✅ | 3/10 | 4 | brute_force |" in report  # mechanisms trùng -> gộp (set)
    assert "| kịch bản missed | `some_rule` | ❌ | — | 0 | — |" in report
    assert "| kịch bản hard | `some_rule` | ➖ (cố ý khó) | — | 0 | — |" in report
