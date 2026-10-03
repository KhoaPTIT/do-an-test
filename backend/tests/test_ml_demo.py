"""Kịch bản demo bảo vệ (Phase 4.1K) chạy qua ứng dụng FastAPI THẬT: POST /login -> pipeline -> API. Kiểm các bất biến không phụ
thuộc chất lượng model (luật vẫn bắt, ML ngoài phạm vi với lần sai mật khẩu, thiếu model thì rơi về luật, API trả trường ML)."""

import logging

from scripts import ml_demo


def test_demo_runs_end_to_end_through_the_real_app(monkeypatch, trained_ml_model_dir):
    _, evidence = ml_demo.run(trained_ml_model_dir, monkeypatch.setattr)
    logging.getLogger("ml_runtime").handlers.clear()
    logging.getLogger("model_registry").handlers.clear()

    status = evidence["ml_status_at_startup"]
    assert status["ml_available"] is True and status["can_lock"] is False and status["artifact_dir"] == str(trained_ml_model_dir)
    assert any("đã nạp model bất thường" in line for line in evidence["startup_load_log"])

    demos = evidence["demos"]
    normal = demos["demo1_normal_login"]["summary"]
    assert normal["rule_detected"] is False and normal["ml_score"] is not None and normal["final_action"] == "allow"

    brute = demos["demo2_rule_attack_brute_force"]["summary"]
    assert "brute_force" in brute["rule_detectors"] and brute["ml_score"] is None and brute["ml_reason"] == "out_of_scope"

    both = demos["demo5_rule_and_ml"]["summary"]
    assert "unusual_location" in both["rule_detectors"] and both["ml_score"] is not None
    assert both["final_action"] != "lock" and demos["demo5_rule_and_ml"]["login"]["http_status"] == 200

    fallback = demos["demo4_ml_unavailable"]
    assert fallback["ml_status"]["ml_available"] is False and fallback["ml_status"]["last_load_error"]
    assert fallback["summary"]["ml_reason"] == "model_not_loaded" and "scripted_client" in fallback["summary"]["rule_detectors"]
    assert fallback["login"]["http_status"] == 200
