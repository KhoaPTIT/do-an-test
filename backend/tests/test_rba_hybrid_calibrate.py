"""MR11 — hiệu chỉnh hybrid risk engine trên RBA: khớp theo luật, cầu nối với combine_risk, trọng số, ngưỡng, chuyển miền."""

import json

import numpy as np
import pandas as pd
import pytest

from app.detection.engine import REGISTRY, RuleHit
from app.detection.hybrid.calibration import ActionBands, HybridProfile, RuleWeightEntry, RuleWeights
from app.detection.hybrid.combine import combine_risk
from ml.rba import hybrid_calibrate as HC
from ml.rba import models
from ml.rba.eval_tasks import ATTACKERS_PARQUET
from ml.rba.rule_tuning import LADDERS, LEVELS_PARQUET


def make_weights(seed=0) -> RuleWeights:
    rng = np.random.default_rng(seed)
    entries = {rule_id: RuleWeightEntry(float(rng.uniform(0.02, 0.9)), True, 100) for rule_id in REGISTRY}
    return RuleWeights(entries)


# ------------------------------------------------------------------------------------------------ fired_by_rule


def test_fired_by_rule_unions_the_ladders_of_a_multi_scope_rule():
    ip_ladder, asn_ladder = next(l for l in LADDERS if l.name == "credential_stuffing/ip"), next(l for l in LADDERS if l.name == "credential_stuffing/asn")
    frame = pd.DataFrame({"row_id": [1, 2, 3, 4], ip_ladder.column: [0, ip_ladder.default_rung, 0, 0], asn_ladder.column: [0, 0, asn_ladder.default_rung, 0]})
    for ladder in LADDERS:
        if ladder.name not in (ip_ladder.name, asn_ladder.name):
            frame[ladder.column] = 0
    fired = HC.fired_by_rule(frame)
    assert fired["credential_stuffing"].tolist() == [False, True, True, False]
    assert list(fired.index) == [1, 2, 3, 4] and fired.index.name == "row_id"


def test_fired_by_rule_uses_the_default_rung_not_the_loosest_one():
    ladder = next(l for l in LADDERS if l.name == "brute_force")
    frame = pd.DataFrame({"row_id": [1, 2, 3], ladder.column: [1, ladder.default_rung - 1, ladder.default_rung]})
    for other in LADDERS:
        if other.name != "brute_force":
            frame[other.column] = 0
    assert HC.fired_by_rule(frame)["brute_force"].tolist() == [False, False, True]


# ------------------------------------------------------------------------------------------------ cầu nối với combine_risk (quan trọng: hai cách tính phải khớp)


def test_rule_probability_of_matches_combine_risk_row_by_row():
    weights = make_weights()
    rule_ids = list(REGISTRY)
    rng = np.random.default_rng(1)
    row_ids = np.arange(200)
    fired = pd.DataFrame({rid: rng.random(len(row_ids)) < 0.15 for rid in rule_ids}, index=pd.Index(row_ids, name="row_id"))
    rule_prob, reputation_prob = HC.rule_probability_of(row_ids, fired, weights)

    for i, row_id in enumerate(row_ids[:40]):  # 40 dòng đủ để so mà không quá chậm
        hits = [RuleHit(rule_id=rid, severity="high", message="x", evidence={}, mode="enforce", techniques=()) for rid in rule_ids if fired.loc[row_id, rid]]
        expected = combine_risk(ml_probability=None, hits=hits, weights=weights, bands=ActionBands(20, 50, 85))
        assert rule_prob[i] == pytest.approx(expected.rule_probability, abs=1e-9), row_id
        assert reputation_prob[i] == pytest.approx(expected.reputation_probability, abs=1e-9), row_id


def test_rule_probability_of_treats_missing_rows_as_no_evidence():
    weights = make_weights()
    fired = pd.DataFrame({"brute_force": [True]}, index=pd.Index([10], name="row_id"))
    for rid in REGISTRY:
        if rid != "brute_force":
            fired[rid] = False
    rule_prob, reputation_prob = HC.rule_probability_of(np.array([10, 999]), fired, weights)
    assert rule_prob[0] > 0.0 and rule_prob[1] == 0.0 and reputation_prob[1] == 0.0  # row_id 999 không có trong `fired`: coi như không luật nào khớp


def test_combined_probability_matches_the_manual_noisy_or():
    ml, rule, reputation = np.array([0.3, 0.0]), np.array([0.5, 0.2]), np.array([0.0, 0.1])
    combined = HC.combined_probability(ml, rule, reputation)
    assert combined[0] == pytest.approx(1 - 0.7 * 0.5 * 1.0) and combined[1] == pytest.approx(1 - 1.0 * 0.8 * 0.9)


# ------------------------------------------------------------------------------------------------ trọng số luật


def synthetic_master(n: int = 20_000, seed: int = 0) -> pd.DataFrame:
    """Khung nhỏ mô phỏng bảng đã ghép (build_master_frame): mỗi luật có bậc thang khớp thường xuyên hơn trên dòng tấn công."""
    rng = np.random.default_rng(seed)
    attack = rng.random(n) < 0.05
    frame = pd.DataFrame({
        "row_id": np.arange(n), "partition": np.where(rng.random(n) < 0.5, "val", "train"), "in_warmup": False, "is_attack_ip": attack, "is_ato": False,
        "cur_success": (rng.random(n) < 0.6).astype(int), "pop_weight": rng.choice([1.0, 3.0], n), "ip": rng.integers(0, 500, n).astype(str), "ts": pd.Timestamp("2020-05-01"),
    })
    for ladder in LADDERS:
        p = np.where(attack, 0.3, 0.02)  # luật khớp trên tấn công thường xuyên hơn nhiều -> trọng số đo được phải cao hơn DEFAULT_WEIGHT
        frame[ladder.column] = np.where(rng.random(n) < p, ladder.default_rung, 0)
    return frame


def test_calibrated_weights_are_higher_than_default_for_a_rule_that_correlates_with_attacks():
    weights = HC.calibrate_rule_weights(synthetic_master(), n_boot=50)
    laddered_ids = {l.rule_id for l in LADDERS}
    for rule_id in laddered_ids:
        entry = weights[rule_id]
        assert entry.calibrated and entry.n > 0 and entry.weight > HC.DEFAULT_WEIGHT and entry.ci95[0] <= entry.weight <= entry.ci95[1]
    for rule_id in set(REGISTRY) - laddered_ids:
        assert weights[rule_id] == RuleWeightEntry(HC.DEFAULT_WEIGHT, False, 0, None)
    assert set(weights) == set(REGISTRY)


def test_a_rule_that_never_fires_on_val_gets_the_default_weight_uncalibrated():
    frame = synthetic_master(n=2_000)
    silent = next(l for l in LADDERS if l.name == "brute_force").column
    frame[silent] = 0
    weights = HC.calibrate_rule_weights(frame, n_boot=10)
    assert weights["brute_force"] == RuleWeightEntry(HC.DEFAULT_WEIGHT, False, 0, None)


def test_weight_calibration_only_reads_the_val_partition():
    frame = synthetic_master(n=3_000)
    only_train = frame.copy()
    only_train.loc[only_train["partition"] == "val", "partition"] = "train"  # không còn dòng val nào
    weights = HC.calibrate_rule_weights(only_train, n_boot=10)
    assert all(entry == RuleWeightEntry(HC.DEFAULT_WEIGHT, False, 0, None) for entry in weights.values())  # không có val -> mọi luật rơi về mặc định


# ------------------------------------------------------------------------------------------------ ngưỡng hành động


@pytest.mark.parametrize(
    "raw,expected",
    [
        ([10.0, 40.0, 90.0], [10, 40, 90]),
        ([10.2, 10.6, 11.1], [11, 12, 13]),  # ba mức sát nhau -> đẩy dần lên để tăng ngặt
        ([-5.0, 3.0, 200.0], [0, 3, 100]),  # ngoài khoảng bị kẹp
        ([98.0, 99.4, 99.9], [98, 99, 100]),  # sát trần 100 vẫn tăng ngặt và không vượt 100
    ],
)
def test_strictly_increasing_rounds_up_and_enforces_strict_order_within_bounds(raw, expected):
    out = HC._strictly_increasing(raw)
    assert out == expected and out[0] < out[1] < out[2] and 0 <= out[0] and out[2] <= 100


def test_calibrate_bands_hits_close_to_the_target_false_alert_rates():
    n = 60_000
    rng = np.random.default_rng(4)
    legit = rng.random(n) < 0.995
    combined = np.where(legit, rng.beta(1, 30, n), rng.beta(3, 2, n))  # hợp lệ: điểm thấp; tấn công: điểm cao
    frame = pd.DataFrame({
        "partition": "val", "in_warmup": False, "cur_success": 1, "is_attack_ip": ~legit, "is_ato": False, "pop_weight": np.ones(n),
    })
    bands = HC.calibrate_bands(frame, combined, target_fpr={"alert_at": 0.05, "step_up_at": 0.01, "lock_at": 0.001})
    legit_scores = combined[legit] * 100
    for name, target in (("alert_at", 0.05), ("step_up_at", 0.01), ("lock_at", 0.001)):
        cut = getattr(bands, name)
        fpr = float((legit_scores >= cut).mean())
        assert fpr <= target * 1.5, (name, fpr, target)  # làm tròn lên nên có thể chặt hơn một chút, không được lỏng hơn nhiều
    assert bands.alert_at < bands.step_up_at < bands.lock_at


def test_calibrate_bands_ignores_rows_outside_legit_successful_val():
    n = 5_000
    rng = np.random.default_rng(6)
    combined = rng.random(n)
    frame = pd.DataFrame({"partition": "val", "in_warmup": False, "cur_success": 1, "is_attack_ip": False, "is_ato": False, "pop_weight": np.ones(n)})
    baseline = HC.calibrate_bands(frame, combined)
    tampered = frame.copy()
    tampered["partition"] = "test"  # không còn dòng val nào thoả điều kiện -> tập âm tính rỗng
    with pytest.raises(Exception):
        HC.calibrate_bands(tampered, combined)
    assert baseline.alert_at < baseline.step_up_at  # (chỉ để chắc phần "trước" chạy được; phần chính là dòng trên raise)


# ------------------------------------------------------------------------------------------------ render / run (giả lập, không cần dữ liệu RBA thật)


def fake_payload() -> dict:
    weights = {"brute_force": RuleWeightEntry(0.31, True, 812, (0.20, 0.45)), "tor_exit": RuleWeightEntry(HC.DEFAULT_WEIGHT, False, 0, None)}
    bands = ActionBands(22, 55, 90)
    quality = {"n_val": 1000, "base_rate": 0.02, "brier_calibrated": 0.01, "brier_constant": 0.05, "reliability": []}

    def band_block(a, s, l):
        return {"alert": {"recall": a, "ci95": (max(a - 0.05, 0), min(a + 0.05, 1))}, "step_up": {"recall": s, "ci95": None}, "lock": {"recall": l, "ci95": None}}

    transfer = {
        "tasks": {name: {"n_pos": 40, "combined": band_block(0.5, 0.3, 0.1), "ml_only": band_block(0.4, 0.2, 0.05)} for name in HC.TRANSFER_TASKS},
        "attacker_lower_bound": {"naive": {"n": 100, "by_band": {"allow": 0.2, "alert": 0.3, "step_up": 0.3, "lock": 0.2}}},
    }
    profile = HybridProfile(RuleWeights(weights), bands, None).to_dict()
    return {
        "rule_weights": weights, "ml_quality": quality, "bands": bands.to_dict(), "ml_only_bands": ActionBands(18, 60, 95).to_dict(),
        "target_fpr": HC.TARGET_FPR, "transfer": transfer, "profile": profile,
    }


def test_render_covers_every_section_and_the_document_reads_the_payload_not_the_registry():
    text = HC.render(fake_payload())
    for expected in (
        "# Hybrid risk engine", "## 1. Cách làm", "## 2. Trọng số từng luật", "`brute_force`", "`tor_exit`", "KHÔNG (giá trị đặt trước)",
        "## 3. Chuyển miền", "attack_ip/test", "ato/all", "Vì sao khác kết luận của MR10", "## 4. Kẻ tấn công mô phỏng", "`naive`", "CẬN DƯỚI", "## 5. Giới hạn", "MR12",
    ):
        assert expected in text, expected


def test_render_uses_the_ml_only_matched_budget_bands_not_the_deployed_ones_in_section_3():
    """Bảo vệ khỏi lỗi đã sửa: cột "Chỉ ML" ở mục 3 phải nêu ngưỡng RIÊNG (ml_only_bands), khác ngưỡng triển khai thật."""
    payload = fake_payload()
    text = HC.render(payload)
    assert "`alert_at`=18" in text and "`step_up_at`=60" in text and "`lock_at`=95" in text  # ba số của ml_only_bands, không phải bands (22/55/90)
    assert "khác ngưỡng triển khai thật" in text


def test_run_writes_the_profile_document_and_json(tmp_path, monkeypatch):
    payload = fake_payload()
    monkeypatch.setattr(HC, "build_payload", lambda: payload)
    monkeypatch.setattr(HC, "ARTIFACT_DIR", tmp_path / "artifacts")
    monkeypatch.setattr(HC, "CALIBRATION_JSON", tmp_path / "artifacts" / "calibration.json")
    monkeypatch.setattr(HC, "PROFILE_PATH", tmp_path / "profiles" / "p.json")
    monkeypatch.setattr(HC, "DOC_PATH", tmp_path / "doc.md")
    assert HC.run() == 0
    assert json.loads((tmp_path / "artifacts" / "calibration.json").read_text(encoding="utf-8"))["bands"] == payload["bands"]
    profile = HybridProfile.from_file(tmp_path / "profiles" / "p.json")
    assert profile.bands == ActionBands(22, 55, 90) and profile.ml_calibration is None
    assert (tmp_path / "doc.md").read_text(encoding="utf-8").startswith("# Hybrid risk engine")


# ------------------------------------------------------------------------------------------------ trên dữ liệu RBA thật (nếu đã chạy MR10 collect + có hybrid_cp2)


_HYBRID_JOBLIB = models.ARTIFACT_DIR / "hybrid_cp2.joblib"


@pytest.mark.skipif(not (LEVELS_PARQUET.is_file() and _HYBRID_JOBLIB.is_file() and ATTACKERS_PARQUET.is_file()), reason="cần rule_tuning collect + hybrid_cp2 + attackers test (xem docstring hybrid_calibrate.py)")
def test_build_payload_on_real_rba_data_gives_a_loadable_profile_with_sane_bands():
    payload = HC.build_payload()
    profile = HybridProfile.from_dict(payload["profile"])
    assert set(profile.weights.entries) == set(REGISTRY)
    assert profile.bands.alert_at < profile.bands.step_up_at < profile.bands.lock_at
    assert profile.ml_calibration is not None and all(0.0 <= y <= 1.0 for y in profile.ml_calibration.ys)
    laddered_counts = {rid: e.n for rid, e in payload["rule_weights"].items() if rid in {l.rule_id for l in LADDERS}}
    assert sum(1 for n in laddered_counts.values() if n > 0) >= 8, laddered_counts  # đa số phải khớp >=1 lần trên val; vài luật cực hiếm (bot_user_agent, ua_rotation...) có thể là 0
    for name in HC.TRANSFER_TASKS:
        assert payload["transfer"]["tasks"][name]["n_pos"] > 0
    text = HC.render(payload)
    assert text.startswith("# Hybrid risk engine")
