"""MR8 — đo chất lượng giải thích: xoá/giữ yếu tố, SHAP toàn cục, ví dụ có ngữ cảnh, ngưỡng vận hành (dữ liệu tổng hợp nhỏ)."""

import numpy as np
import pandas as pd
import pytest

from ml.rba import baselines as B
from ml.rba import ensemble as En
from ml.rba import eval_tasks, splits, train
from ml.rba import explain as Ex
from ml.rba import explain_eval as Ev
from ml.rba import models as Mo
from ml.rba.features import FEATURE_NAMES
from tests.test_rba_explain import make_table

PARAMS = {"num_threads": 2, "num_leaves": 15, "min_data_in_leaf": 20}


def make_frame(n=14000, seed=0):
    """Bảng đăng nhập theo thời gian: IP tấn công (tín hiệu ở ip_distinct_users_24h, rare_asn) và 40 ATO ở giai đoạn test (rare_country/rare_asn rất cao)."""
    df = make_table(n, seed)
    rng = np.random.default_rng(seed + 1)
    df["ts"] = pd.Timestamp("2020-03-01") + pd.to_timedelta(rng.integers(0, 320 * 24 * 3600, n), unit="s")
    df["partition"] = splits.assign_time_split(df["ts"])
    df["ip"] = [f"ip-{i % 3000}" for i in range(n)]
    df["weight"] = 1.0
    candidates = df[(df["partition"] == "test") & (df["cur_success"] == 1) & ~df["is_attack_ip"]].index.to_numpy()
    picks = rng.choice(candidates, 40, replace=False)
    df.loc[picks, ["is_ato", "partition"]] = [True, "ato"]
    df.loc[picks, "rare_country"] += 12.0
    df.loc[picks, "rare_asn"] += 12.0
    df.loc[picks, "u_n_success"] = 6.0
    return df


def make_attackers(df, partitions, n, seed):
    """Kẻ tấn công mô phỏng: đăng nhập hợp lệ có lịch sử với IP mới rất lạ với tài khoản."""
    rng = np.random.default_rng(seed)
    base = df[df["partition"].isin(partitions) & (df["cur_success"] == 1) & ~df["is_attack_ip"] & ~df["is_ato"] & (df["u_n_success"] >= 1)]
    rows = base.sample(n, random_state=seed).copy()
    rows["row_id"] = 10**9 + seed * 10**6 + np.arange(n)
    rows["new_ip"], rows["llr_ip"], rows["llr_sum"] = 1.0, rows["llr_ip"] + 6.0, rows["llr_sum"] + 6.0
    rows["period"] = np.where(rows["partition"] == "train", "train", np.where(rows["partition"] == "val", "val", "test"))
    rows["attacker_type"] = rng.choice(["naive", "vpn", "targeted"], n)
    rows["partition"] = "attacker"
    rows["pop_weight"] = 1.0
    return rows.reset_index(drop=True)


@pytest.fixture(scope="module")
def world():
    df = make_frame()
    test_attackers = make_attackers(df, ("test",), 300, seed=2)
    trainval = make_attackers(df, ("train", "val"), 600, seed=3)
    ip_train, ip_val = Mo.attack_ip_sets(df)
    gbm_ip = Mo.train_gbm("ip", FEATURE_NAMES, ip_train, ip_val, params=PARAMS, rounds=60, early_stopping=10)
    sim_train, sim_val = Mo.simulated_attacker_sets(df, trainval)
    gbm_sim = Mo.train_gbm("sim", FEATURE_NAMES, sim_train, sim_val, params=PARAMS, rounds=60, early_stopping=10)
    forest = B.IsolationForestScorer(n_estimators=40, max_samples=256, sample_rows=3000).fit(df)
    hybrid = train.build_hybrid(
        eval_tasks.add_population_weights(df),
        [("ip_tan_cong", gbm_ip, None), ("chiem_tai_khoan", gbm_sim, En.gate_success_with_history), ("bat_thuong", forest, En.gate_success)],
    )
    return Ev.World(eval_tasks.add_population_weights(df), test_attackers, hybrid, Ex.ExplainReference.fit(df))


# ------------------------------------------------------------------------------------------------ xoá yếu tố


def test_neutralize_resets_only_the_chosen_concepts_and_keeps_llr_sum_consistent():
    df = make_table(200)
    reference = Ex.ExplainReference.fit(df)
    frame = df.head(4).copy()
    frame.loc[frame.index[3], "llr_sum"] = np.nan  # tài khoản không tồn tại: đặc trưng theo user thiếu
    out = Ev.neutralize(frame, [["quoc_gia"], [], ["nha_mang", "ip"], ["quoc_gia"]], reference)

    country = Ex.CONCEPTS["quoc_gia"]
    assert np.allclose(out.loc[frame.index[0], country], [reference.typical[f] for f in country])
    assert (out.loc[frame.index[1], FEATURE_NAMES] == frame.loc[frame.index[1], FEATURE_NAMES]).all()  # tập rỗng: giữ nguyên, kể cả llr_sum
    untouched = [f for f in FEATURE_NAMES if Ex.CONCEPT_OF[f] not in ("quoc_gia", "tong_the")]
    assert (out.loc[frame.index[0], untouched] == frame.loc[frame.index[0], untouched]).all()  # yếu tố khác không đổi
    parts = [f"llr_{a}" for a in ("ip", "country", "asn", "ua", "browser", "os", "device")]
    assert out.loc[frame.index[0], "llr_sum"] == pytest.approx(out.loc[frame.index[0], parts].sum())  # llr_sum tính lại từ các llr_* đã xoá
    assert np.isnan(out.loc[frame.index[3], "llr_sum"])  # thiếu thì vẫn thiếu
    assert frame.loc[frame.index[0], "rare_country"] != out.loc[frame.index[0], "rare_country"]  # bảng gốc không bị sửa tại chỗ hay ngược lại
    assert out.loc[frame.index[2], "new_asn"] == reference.typical["new_asn"] and out.loc[frame.index[2], "new_ip"] == reference.typical["new_ip"]


def test_deleting_the_named_factors_removes_the_alert_and_keeping_only_them_preserves_it(world):
    for name in ("IP tấn công (test)", "ATO thật (cả 141 ca)"):
        frame = Ev.evaluation_sets(world)[name]
        flagged = world.flagged(frame)
        explanations = world.explainer.explain(flagged)
        results = Ev.deletion_test(world.explainer, flagged, explanations)
        assert results and sum(r["n"] for r in results) == len(flagged)
        for r in results:
            if r["n"] < 15:
                continue
            for key in ("necessity_k", "necessity_1", "sufficiency_k", "retention_k"):
                assert set(r[key]) == {"explanation", "random", "global"} and all(0.0 <= v <= 1.0 for v in r[key].values())
            assert r["necessity_k"]["explanation"] >= 0.9, (name, r["component"], r["necessity_k"])
            assert r["necessity_k"]["explanation"] > r["necessity_k"]["random"]  # hơn xoá ngẫu nhiên
            assert r["sufficiency_k"]["explanation"] > r["sufficiency_k"]["random"] + 0.2  # giữ lại đúng yếu tố nêu ra thì cảnh báo còn
            assert r["drop_k"]["explanation"] > r["drop_k"]["random"] > 0
            assert r["retention_k"]["explanation"] > r["retention_k"]["random"] and r["retention_k"]["explanation"] > 0.4  # chỉ giữ yếu tố nêu ra vẫn còn phần lớn điểm
            assert 0 < r["mean_factors"] <= Ex.TOP_N


def test_an_empty_explanation_changes_nothing_so_it_can_never_pass_the_test(world):
    frame = Ev.evaluation_sets(world)["ATO thật (cả 141 ca)"]
    flagged = world.flagged(frame)
    empty = [Ex.Explanation(e.component, e.method, e.score, []) for e in world.explainer.explain(flagged)]
    for r in Ev.deletion_test(world.explainer, flagged, empty):
        assert r["empty"] == r["n"] and r["mean_factors"] == 0
        assert r["necessity_k"]["explanation"] == 0.0 and r["sufficiency_k"]["explanation"] == 0.0 and r["drop_k"]["explanation"] == pytest.approx(0.0)
        assert r["retention_k"]["explanation"] < 0.7  # xoá hết: điểm tụt về mức của đăng nhập bình thường


def test_component_score_ignores_the_gate_and_matches_the_hybrid_when_the_component_wins(world):
    frame = world.flagged(Ev.evaluation_sets(world)["IP tấn công (test)"])
    tails = world.hybrid._tails(frame)
    for k, component in enumerate(world.hybrid.components):
        won = tails.argmin(axis=1) == k
        if won.any():
            assert np.allclose(Ev.component_score(component, frame[won]), world.hybrid(frame[won]))


def test_concept_frequency_shares_are_relative_to_each_components_alerts():
    mk = lambda component, concepts: Ex.Explanation(component, "shap", 3.0, [Ex.Factor(c, "f", 1.0, "t") for c in concepts])
    freq = Ev.concept_frequency([mk("a", ["ip", "quoc_gia"]), mk("a", ["ip"]), mk("b", ["nha_mang"])])
    assert freq["a"] == {"n": 2, "ip": 1.0, "quoc_gia": 0.5} and freq["b"] == {"n": 1, "nha_mang": 1.0}


# ------------------------------------------------------------------------------------------------ toàn cục


def test_global_shap_table_puts_the_planted_signal_first_and_shares_sum_to_one(world):
    result = Ev.run_global(world, sample=2000)
    assert set(result) == {"ip_tan_cong", "chiem_tai_khoan"}
    ip_table = result["ip_tan_cong"]
    assert ip_table[0]["concept"] in {"hoat_dong_ip", "nha_mang"}  # tín hiệu đã cài
    assert sum(r["share"] for r in ip_table) == pytest.approx(1.0)
    assert [r["mean_abs"] for r in ip_table] == sorted((r["mean_abs"] for r in ip_table), reverse=True)
    assert result["chiem_tai_khoan"][0]["concept"] == "ip"  # kẻ tấn công mô phỏng có IP mới rất lạ
    assert all(0.0 <= r["pushes_up"] <= 1.0 for table in result.values() for r in table)


# ------------------------------------------------------------------------------------------------ ví dụ có ngữ cảnh


def test_pick_examples_are_spread_over_the_score_range_without_duplicates():
    picks = Ev.pick_examples(np.arange(100.0), 3)
    assert len(picks) == 3 and picks == sorted(picks) and picks[0] < 25 and 40 < picks[1] < 60 and picks[2] > 75
    assert Ev.pick_examples(np.array([1.0, 2.0]), 3) == [0, 1] and Ev.pick_examples(np.array([]), 3) == []


def test_examples_carry_the_accounts_usual_values_when_context_exists(world, monkeypatch):
    context = Ex.Context(today={"country": "RU", "asn": "AS2"}, usual={"country": "VN", "asn": "AS1"})
    monkeypatch.setattr(Ev, "contexts_for", lambda frame: [context] * len(frame))
    rows = Ev.run_examples(world, per_set=2)
    assert rows and {r["set"] for r in rows} <= {"ATO thật bị báo", "IP tấn công bị báo", "Đăng nhập hợp lệ bị báo nhầm"}
    ato = [r for r in rows if r["set"] == "ATO thật bị báo"]
    assert ato and all(r["has_context"] for r in rows)
    assert all("thường VN → nay RU" in r["with_context"] for r in ato if "quốc gia" in r["no_context"])
    assert all("→" not in r["no_context"] for r in rows)

    monkeypatch.setattr(Ev, "contexts_for", lambda frame: [None] * len(frame))
    plain = Ev.run_examples(world, per_set=2)
    assert not any(r["has_context"] for r in plain) and all(r["with_context"] == r["no_context"] for r in plain)
    assert "| — |" in Ev.examples_markdown(plain)


def test_contexts_are_built_from_the_raw_history_and_skipped_for_huge_or_missing_users(tmp_path, monkeypatch):
    def record(row_id, user, day, country="VN", asn=100, browser="Chrome 90.0.4430", os_="Windows 10", device="desktop", success=True):
        return dict(row_id=row_id, ts=pd.Timestamp("2020-06-01") + pd.Timedelta(days=day), user_id=user, ip="1.1.1.1", asn=asn, country=country, ua="ua",
                    browser=browser, os=os_, device_type=device, success=success)

    events = [record(i, 1, i) for i in range(1, 7)]  # user 1: sáu lần thành công ở VN
    events.append(record(100, 1, 10, country="RU", asn=200, browser="Firefox 80.0", os_="Linux", device="mobile"))  # lần đang xét
    events += [record(200 + i, 2, i) for i in range(12)]  # user 2: 12 sự kiện — vượt giới hạn giả lập (8)
    events += [record(300 + i, Ev.RBA_CATCHALL_USER_ID, i) for i in range(3)]  # "tài khoản không tồn tại"
    path = tmp_path / "rba_full.parquet"
    pd.DataFrame(events).astype({"asn": "Int32"}).to_parquet(path)
    monkeypatch.setattr(Ev.etl, "FULL_PARQUET", path)
    monkeypatch.setattr(Ev, "MAX_HISTORY_EVENTS", 8)

    frame = pd.DataFrame({"row_id": [100, 205, 300, 999], "user_id": [1, 2, Ev.RBA_CATCHALL_USER_ID, 7]})
    contexts = Ev.contexts_for(frame)
    assert contexts[0].pair("country") == ("VN", "RU") and contexts[0].pair("asn") == ("AS100", "AS200")
    assert contexts[0].usual["browser"] == "Chrome" and contexts[0].today["os"] == "Linux"
    assert contexts[0].usual_gap_secs == pytest.approx(86400.0)
    assert contexts[1] is None and contexts[3] is None  # user quá lớn; dòng không có trong file
    assert contexts[2].usual == {} and contexts[2].today["country"] == "VN"  # "tài khoản không tồn tại": không nạp 14 triệu sự kiện, chỉ có giá trị lần này


# ------------------------------------------------------------------------------------------------ ngưỡng vận hành


def test_precision_follows_bayes_rule_and_collapses_as_attacks_get_rarer():
    assert Ev.precision_at(0.5, 0.01, 0.001) == pytest.approx(0.0005 / (0.0005 + 0.01 * 0.999))
    assert Ev.precision_at(1.0, 0.0, 0.001) == 1.0 and Ev.precision_at(0.0, 0.0, 0.0) == 0.0
    values = [Ev.precision_at(0.3, 0.01, p) for p in (1e-2, 1e-3, 1e-4)]
    assert values == sorted(values, reverse=True) and values[0] > 0.2 > values[2]


def test_operating_points_hit_their_targets_on_validation_and_get_stricter(world):
    result = Ev.run_operating(world)
    loose, strict = result["levels"]
    assert (loose["target_fpr"], strict["target_fpr"]) == (0.01, 0.001) and strict["threshold"] > loose["threshold"]
    for level in result["levels"]:
        assert level["fpr"]["val"] == pytest.approx(level["target_fpr"], abs=level["target_fpr"] * 0.6 + 0.002)
        assert level["false_alerts_per_10k"] == pytest.approx(level["fpr"]["test"] * 10_000)
    assert strict["recall"]["ATO thật tương lai (38)"] <= loose["recall"]["ATO thật tương lai (38)"]
    text = Ev.operating_markdown(result)
    assert "1 trên 1,000" in text and "| 1.0% |" in text and "| 0.1% |" in text


def test_markdown_tables_render_every_group_and_component(world):
    result = Ev.run_faithfulness(world, log=lambda message: None)
    assert set(result) == {"IP tấn công (test)", "Kẻ tấn công mô phỏng (test)", "ATO thật (cả 141 ca)", "Đăng nhập hợp lệ (test)"}
    text = Ev.faithfulness_markdown(result)
    for phrase in ("BIẾN MẤT", "ĐỨNG ĐẦU", "CÒN", "điểm còn lại", "`bat_thuong`", "ATO thật (cả 141 ca)"):
        assert phrase in text
    lengths = Ev.length_markdown(result)
    assert "| Nhóm cảnh báo | Số cảnh báo | Độ dài trung vị" in lengths and all(0 < info["length"]["median"] < 220 for info in result.values() if info["n_flagged"])
    frequency = Ev.frequency_markdown(result)
    assert "| Nhóm cảnh báo | Thành phần |" in frequency and "%" in frequency
    assert "| Yếu tố |" in Ev.global_markdown(Ev.run_global(world, sample=1500))


def test_latency_report_is_ordered_and_explanation_is_cheaper_than_rescoring(world):
    result = Ev.run_latency(world, n=25)
    assert 0 < result["n"] <= 25
    for key in ("total_ms", "explain_ms"):
        assert 0 < result[key]["p50"] <= result[key]["p95"] <= result[key]["p99"]
    assert result["explain_ms"]["p50"] < result["total_ms"]["p50"] * 1.5  # giải thích không đắt hơn cả chấm điểm lại ba thành phần
    text = Ev.latency_markdown(result)
    assert "| p50 | p95 | p99 |" in text and "toàn bộ" in text and "chỉ phần giải thích" in text
