"""MR13 — kiểm tra phần THUẦN (tính toán số đo, viết báo cáo) của scripts/alert_intelligence_sim.py bằng ScenarioResult
tự dựng, KHÔNG gọi `run_simulation()`/`_wire()` thật: `_wire()` trỏ thẳng `app.detection.pipeline.SessionLocal` và
`app.detection.rate_counter.redis_client` vào state DÙNG CHUNG cho cả tiến trình (không qua fixture `monkeypatch` nên
KHÔNG tự hoàn tác) — chạy trong cùng tiến trình pytest với các test khác sẽ làm rò rỉ state đó sang test chạy SAU. Chạy
kịch bản thật: `python -m scripts.alert_intelligence_sim` (độc lập, xem docs/alert-intelligence-v2.md kết quả đã ghi)."""

from scripts.alert_intelligence_sim import ScenarioResult, SimReport, build_payload, render


def _r(name, expected_family, raw, alerts_created, predicted_families) -> ScenarioResult:
    return ScenarioResult(name, f"mô tả {name}", expected_family, raw, alerts_created, predicted_families)


def test_reduction_and_accuracy_are_computed_only_from_scenarios_that_actually_alerted():
    report = SimReport(
        [
            _r("khong_vuot_nguong", "Đoán và dò mật khẩu", raw=0, alerts_created=0, predicted_families=[]),  # không tính vào family_accuracy
            _r("dung", "Ngữ cảnh tài khoản", raw=1, alerts_created=1, predicted_families=["Ngữ cảnh tài khoản"]),
            _r("gop_5_con_1", "Danh tiếng hạ tầng", raw=5, alerts_created=1, predicted_families=["Danh tiếng hạ tầng"]),
            _r("doi_chung_am", None, raw=0, alerts_created=0, predicted_families=[]),
        ]
    )

    assert report.total_raw_incidents == 6 and report.total_alerts_created == 2
    assert report.alert_reduction_pct == 100.0 * (1 - 2 / 6)
    assert len(report.family_scenarios) == 3  # 3 kịch bản CÓ nhãn (không tính đối chứng âm)
    assert len(report.alerted_family_scenarios) == 2  # nhưng chỉ 2 trong số đó THỰC SỰ có alert
    assert report.detection_rate_pct == 100.0 * 2 / 3
    assert report.family_accuracy_pct == 100.0  # cả 2 kịch bản CÓ alert đều gán đúng — "khong_vuot_nguong" không kéo tụt số này
    assert report.false_positive_scenarios == []


def test_a_wrong_family_on_an_alerted_scenario_lowers_accuracy_but_not_detection_rate():
    report = SimReport(
        [
            _r("dung", "Ngữ cảnh tài khoản", raw=1, alerts_created=1, predicted_families=["Ngữ cảnh tài khoản"]),
            _r("sai_ho", "Đoán và dò mật khẩu", raw=1, alerts_created=1, predicted_families=["Danh tiếng hạ tầng"]),  # có alert nhưng SAI họ
        ]
    )
    assert report.detection_rate_pct == 100.0  # cả 2 đều vượt ngưỡng
    assert report.family_accuracy_pct == 50.0  # nhưng chỉ 1/2 đúng họ


def test_a_false_positive_on_a_benign_scenario_is_reported_separately_not_folded_into_family_accuracy():
    report = SimReport(
        [
            _r("dung", "Ngữ cảnh tài khoản", raw=1, alerts_created=1, predicted_families=["Ngữ cảnh tài khoản"]),
            _r("binh_thuong_nhung_bao_nham", None, raw=1, alerts_created=1, predicted_families=["đăng nhập bất thường"]),
        ]
    )
    assert report.family_accuracy_pct == 100.0  # đối chứng âm KHÔNG có expected_family nên không lẫn vào mẫu này
    assert [s.name for s in report.false_positive_scenarios] == ["binh_thuong_nhung_bao_nham"]


def test_no_scenarios_at_all_returns_zero_everywhere_without_dividing_by_zero():
    report = SimReport([])
    assert report.alert_reduction_pct == 0.0 and report.detection_rate_pct == 0.0 and report.family_accuracy_pct == 0.0


def test_payload_and_render_round_trip_without_crashing_and_mention_false_positives():
    report = SimReport(
        [
            _r("gop_5_con_1", "Danh tiếng hạ tầng", raw=5, alerts_created=1, predicted_families=["Danh tiếng hạ tầng"]),
            _r("binh_thuong_nhung_bao_nham", None, raw=1, alerts_created=1, predicted_families=["đăng nhập bất thường"]),
        ]
    )
    payload = build_payload(report)
    assert payload["total_raw_incidents"] == 6 and payload["total_alerts_created"] == 2
    assert payload["false_positives"] == ["binh_thuong_nhung_bao_nham"]

    markdown = render(payload)
    assert "gop_5_con_1" in markdown and "binh_thuong_nhung_bao_nham" in markdown and "Cảnh báo thông minh v2" in markdown
