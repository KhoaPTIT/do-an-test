"""MR15 — kiểm tra phần THUẦN (tính toán số đo, viết báo cáo) của scripts/feedback_loop_sim.py bằng RoundResult tự
dựng, KHÔNG gọi `run_simulation()` thật: hàm đó trỏ thẳng `app.detection.pipeline.SessionLocal` và
`app.detection.rate_counter.redis_client` vào state DÙNG CHUNG cho cả tiến trình (không qua fixture `monkeypatch` nên
KHÔNG tự hoàn tác) — cùng lý do đã áp dụng cho tests/test_alert_intelligence_sim.py (MR13). Chạy mô phỏng thật:
`python -m scripts.feedback_loop_sim` (độc lập, xem docs/feedback-loop.md kết quả đã ghi)."""

from scripts.feedback_loop_sim import RoundResult, SimReport, build_payload, render


def _round(n, *, fp_alerted, delta=0.0, feedback=0, attacker_alerted=True, attacker_action="lock") -> RoundResult:
    return RoundResult(round=n, fp_user_alerted=fp_alerted, fp_user_delta_after_retrain=delta, fp_user_feedback_count_after=feedback, attacker_alerted=attacker_alerted, attacker_action=attacker_action)


def test_fp_user_alert_rounds_lists_only_the_rounds_that_alerted():
    report = SimReport([_round(1, fp_alerted=True), _round(2, fp_alerted=False), _round(3, fp_alerted=True)])
    assert report.fp_user_alert_rounds == [1, 3]


def test_suppressed_from_round_finds_the_first_round_that_stays_quiet_until_the_end():
    report = SimReport([_round(1, fp_alerted=True), _round(2, fp_alerted=True), _round(3, fp_alerted=False), _round(4, fp_alerted=False)])
    assert report.suppressed_from_round == 3


def test_suppressed_from_round_is_none_if_it_alerts_again_later():
    """Vòng 3 im lặng nhưng vòng 4 lại báo -> vòng 3 KHÔNG được tính là "đã ngừng hẳn" — suppressed_from_round phải
    tìm điểm IM LẶNG ĐẾN HẾT, không phải điểm im lặng đầu tiên bất kỳ."""
    report = SimReport([_round(1, fp_alerted=True), _round(2, fp_alerted=False), _round(3, fp_alerted=True)])
    assert report.suppressed_from_round is None


def test_suppressed_from_round_is_none_when_it_never_stops_alerting():
    report = SimReport([_round(1, fp_alerted=True), _round(2, fp_alerted=True)])
    assert report.suppressed_from_round is None


def test_attacker_always_detected_requires_lock_in_every_single_round():
    all_locked = SimReport([_round(1, fp_alerted=False, attacker_action="lock"), _round(2, fp_alerted=False, attacker_action="lock")])
    assert all_locked.attacker_always_detected is True

    one_missed = SimReport([_round(1, fp_alerted=False, attacker_action="lock"), _round(2, fp_alerted=False, attacker_alerted=False, attacker_action=None)])
    assert one_missed.attacker_always_detected is False


def test_payload_and_render_round_trip_without_crashing_and_mention_key_numbers():
    report = SimReport(
        [
            _round(1, fp_alerted=True, delta=0.0, feedback=1),
            _round(2, fp_alerted=True, delta=0.0, feedback=2),
            _round(3, fp_alerted=True, delta=12.0, feedback=3),
            _round(4, fp_alerted=False, delta=12.0, feedback=3),
        ]
    )
    payload = build_payload(report)
    assert payload["k_rounds"] == 4 and payload["fp_user_alert_rounds"] == [1, 2, 3] and payload["suppressed_from_round"] == 4
    assert payload["attacker_always_detected"] is True

    markdown = render(payload)
    assert "Vòng phản hồi (MR15)" in markdown and "4" in markdown and "12.0" in markdown
