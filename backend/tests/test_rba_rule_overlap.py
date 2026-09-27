"""MR10 — bảng chồng lấn luật/mô hình: phân rã dương tính, so công bằng ở cùng tổng báo nhầm, luật nào bắt phần mô hình bỏ sót, định dạng."""

import json

import numpy as np
import pandas as pd
import pytest

from ml.rba import rule_overlap as OV
from ml.rba import rule_tuning as RT
from ml.rba.eval_tasks import Task


def toy():
    """4 dương tính (trọng số 1) và 6 âm tính; mô hình báo dương tính 0, 1 và âm tính 0; luật báo dương tính 1, 2 và âm tính 1."""
    y = np.array([1, 1, 1, 1, 0, 0, 0, 0, 0, 0], dtype=bool)
    weight = np.ones(10)
    ml_score = np.array([5, 5, 1, 1, 5, 1, 1, 1, 1, 1], dtype=float)
    rule = np.array([0, 1, 1, 0, 0, 1, 0, 0, 0, 0], dtype=bool)
    cluster = np.array(["a", "a", "b", "b", "c", "c", "d", "d", "e", "e"])
    return y, weight, ml_score, rule, cluster


def test_the_four_way_split_the_false_alerts_and_the_matched_budget_are_computed_by_hand():
    y, w, s, rule, cluster = toy()
    b = OV.analyse_block(y, w, s, 3.0, rule, cluster, n_boot=50)
    assert b["positives"] == {"both": 0.25, "ml_only": 0.25, "rules_only": 0.25, "neither": 0.25}
    assert b["counts"] == {"both": 1, "ml_only": 1, "rules_only": 1, "neither": 1} and (b["n_pos"], b["n_neg"]) == (4, 6)
    assert b["fpr"] == pytest.approx({"ml": 1 / 6, "rules": 1 / 6, "union": 2 / 6, "both": 0.0, "ml_only": 1 / 6, "rules_only": 1 / 6})
    r = b["recall"]
    assert (r["ml"], r["rules"], r["union"]) == (0.5, 0.5, 0.75)
    # nới ngưỡng mô hình đến đúng 2/6 báo nhầm: các âm tính còn lại đều điểm 1 nên chỉ nới được tới điểm 1 (không tính "lớn hơn 1") -> recall vẫn 0,5
    assert r["ml_matched_to_union"] == 0.5 and r["ml_matched_to_rules"] == 0.5 and r["gain_over_matched_ml"] == pytest.approx(0.25)
    assert set(b["recall_ci"]) == {"ml", "rules", "union", "ml_matched_to_union", "ml_matched_to_rules", "gain_over_matched_ml"}
    lo, hi = b["recall_ci"]["union"]
    assert 0.0 <= lo <= 0.75 <= hi <= 1.0


def test_matching_the_budget_lets_the_model_catch_more_when_the_scores_allow_it():
    y = np.array([1, 1, 1, 1, 0, 0, 0, 0, 0, 0], dtype=bool)
    ml_score = np.array([9, 8, 6, 5, 7, 4, 3, 2, 1, 0], dtype=float)  # âm tính điểm cao nhất 7, rồi 4...
    rule = np.array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0], dtype=bool)
    rule[3], rule[9] = True, True  # luật bắt ca thứ 4 (điểm 5), báo nhầm một dòng điểm 0
    cluster = np.arange(10).astype(str)
    b = OV.analyse_block(y, np.ones(10), ml_score, 7.5, rule, cluster, n_boot=50)
    assert b["recall"]["ml"] == 0.5 and b["recall"]["union"] == 0.75
    assert b["fpr"]["ml"] == 0.0 and b["fpr"]["union"] == pytest.approx(1 / 6)
    # tổng báo nhầm của bộ gộp = 1/6: nới ngưỡng mô hình được phép báo nhầm đúng 1 dòng (điểm 7) nên hạ ngưỡng xuống 4 và bắt cả 4 ca (điểm 9, 8, 6, 5)
    # -> ở ví dụ này chỉ nới ngưỡng mô hình TỐT HƠN bộ gộp: "hơn" âm, và bảng phải nói thẳng điều đó
    assert b["recall"]["ml_matched_to_union"] == 1.0 and b["recall"]["gain_over_matched_ml"] == pytest.approx(-0.25)


def test_weights_scale_the_fractions():
    y, _, s, rule, cluster = toy()
    weight = np.array([3, 1, 1, 1, 1, 1, 1, 1, 1, 1], dtype=float)  # ca dương tính 0 (chỉ mô hình bắt) nặng gấp ba
    b = OV.analyse_block(y, weight, s, 3.0, rule, cluster, n_boot=20)
    assert b["positives"]["ml_only"] == pytest.approx(3 / 6) and b["positives"]["both"] == pytest.approx(1 / 6) and b["counts"]["ml_only"] == 1


def test_the_bootstrap_is_reproducible_and_widens_with_fewer_clusters():
    y, w, s, rule, _ = toy()
    many = OV.cluster_bootstrap(np.arange(4).astype(str), w[y], {"x": rule[y]}, 200, seed=1)
    again = OV.cluster_bootstrap(np.arange(4).astype(str), w[y], {"x": rule[y]}, 200, seed=1)
    one = OV.cluster_bootstrap(np.array(["a"] * 4), w[y], {"x": rule[y]}, 200, seed=1)
    assert (many == again).all() and many.shape == (200, 1)
    assert np.ptp(one) == 0.0 and np.ptp(many) > 0.0  # một cụm duy nhất: lấy mẫu lại không đổi gì


def test_attribution_names_the_rules_that_catch_what_the_model_misses():
    y, w, s, _, _ = toy()
    per = {"brute_force": np.array([0, 0, 1, 0, 0, 0, 0, 0, 0, 0], dtype=bool), "ua_rotation": np.array([0, 1, 1, 1, 0, 0, 0, 0, 0, 0], dtype=bool), "quiet": np.zeros(10, dtype=bool)}
    rows = OV.rule_attribution(y, w, s, 3.0, per)  # mô hình bỏ sót ca 2 và 3
    assert rows[0] == {"ladder": "ua_rotation", "share": 1.0, "count": 2}  # bắt cả hai ca bị bỏ sót (ca 1 mô hình đã bắt nên không tính)
    assert rows[1] == {"ladder": "brute_force", "share": 0.5, "count": 1} and rows[2]["count"] == 0


def test_rule_flags_join_levels_by_row_id_and_ignore_unknown_rows():
    levels = pd.DataFrame({"L__brute_force": np.array([0, 2, 5], dtype=np.uint8), "L__ua_rotation": np.array([0, 0, 3], dtype=np.uint8)}, index=pd.Index([10, 20, 30], name="row_id"))
    frame = pd.DataFrame({"row_id": [30, 10, 20, 99]})
    union, per = OV.rule_flags(frame, levels, {"brute_force": 3, "ua_rotation": 3})
    assert per["brute_force"].tolist() == [True, False, False, False] and per["ua_rotation"].tolist() == [True, False, False, False]
    assert union.tolist() == [True, False, False, False]
    union, _ = OV.rule_flags(frame, levels, {"brute_force": 1})
    assert union.tolist() == [True, False, True, False]
    assert OV.rule_flags(frame, levels, {})[0].tolist() == [False] * 4


def _task(name, n=400, seed=0):
    rng = np.random.default_rng(seed)
    y = rng.random(n) < 0.15
    frame = pd.DataFrame({"row_id": np.arange(n) + (1000 if name.startswith("ato") else 0), "y": y, "pop_weight": rng.choice([1.0, 4.0], n), "cluster": rng.integers(0, 40, n).astype(str)})
    score = np.where(y, rng.normal(3, 1, n), rng.normal(0, 1, n))
    return Task(name, f"bài thử {name}", frame), score


def test_payload_and_document_cover_every_task_set_and_level(tmp_path):
    tasks, scores = {}, {}
    for name in OV.TASKS:
        tasks[name], scores[name] = _task(name, seed=len(name))
    all_ids = np.concatenate([t.frame["row_id"].to_numpy() for t in tasks.values()])
    rng = np.random.default_rng(5)
    levels = pd.DataFrame({l.column: rng.integers(0, len(l.rungs) + 1, len(all_ids)).astype(np.uint8) for l in RT.LADDERS}, index=pd.Index(all_ids, name="row_id"))
    levels = levels[~levels.index.duplicated()]
    sets = {"default_enforce": {"brute_force": 3}, "tuned_enforce": {"brute_force": 5, "ua_rotation": 3}, "tuned_all": {"brute_force": 5, "ua_rotation": 3, "rare_network_login": 8}}
    payload = OV.build_payload(tasks, scores, {0.01: 2.5, 0.001: 3.5}, levels, sets, n_boot=30)
    json.dumps(payload)  # tuần tự hoá được
    assert set(payload["tasks"]) == set(OV.TASKS) and set(payload["tasks"]["ato/future"]["blocks"]) == {f"{s}@{lvl:g}" for s in sets for lvl in OV.FPR_LEVELS}
    block = payload["tasks"]["attack_ip/test"]["blocks"]["tuned_enforce@0.01"]
    assert sum(block["positives"].values()) == pytest.approx(1.0) and "missed_by_ml" in block and "missed_by_ml" not in payload["tasks"]["attack_ip/test"]["blocks"]["tuned_all@0.01"]

    text = OV.render(payload)
    for expected in ("# Chồng lấn giữa luật và mô hình (MR10)", "## Bài `attack_ip/test`", "## Bài `ato/all`", "## 2. Tóm tắt", "### Chồng lấn", "### Bằng chứng cho hybrid", "### Luật nào bắt phần mô hình bỏ sót", "`tuned_enforce`", "**", "## Giới hạn", "điểm ["):
        assert expected in text, expected


def test_signed_gains_are_shown_in_points_with_a_flag_when_the_interval_excludes_zero():
    assert OV._points(0.031, [0.01, 0.052]) == "+3.1 điểm [+1.0; +5.2] — khác 0"
    assert OV._points(-0.13, [-0.153, -0.105]) == "-13.0 điểm [-15.3; -10.5] — khác 0"
    assert OV._points(0.004, [-0.002, 0.01]) == "+0.4 điểm [-0.2; +1.0]"  # khoảng chứa 0: không cờ


def test_render_only_rebuilds_the_document_from_the_saved_numbers(tmp_path):
    tasks, scores = {}, {}
    for name in OV.TASKS:
        tasks[name], scores[name] = _task(name, seed=3)
    levels = pd.DataFrame({l.column: np.zeros(1400, dtype=np.uint8) for l in RT.LADDERS}, index=pd.Index(np.arange(1400), name="row_id"))
    payload = OV.build_payload(tasks, scores, {0.01: 2.5, 0.001: 3.5}, levels, {"tuned_enforce": {"brute_force": 5}, "default_enforce": {"brute_force": 3}}, n_boot=10)
    data, doc = tmp_path / "overlap.json", tmp_path / "doc.md"
    data.write_text(json.dumps(payload), encoding="utf-8")
    assert OV.render_only(data, doc) == 0 and doc.read_text(encoding="utf-8") == OV.render(json.loads(data.read_text(encoding="utf-8")))
    assert doc.read_text(encoding="utf-8").startswith("# Chồng lấn giữa luật và mô hình (MR10)")


def test_load_chosen_reads_the_member_ladders_of_each_set(tmp_path):
    path = tmp_path / "tuning.json"
    path.write_text(json.dumps({"sets": {"tuned_enforce": {"members": {"brute_force": 5, "ua_rotation": 3}}, "default_enforce": {"members": {}}}}), encoding="utf-8")
    assert OV.load_chosen(path) == {"tuned_enforce": {"brute_force": 5, "ua_rotation": 3}, "default_enforce": {}}
