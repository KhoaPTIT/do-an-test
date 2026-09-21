"""MR8 — giải thích cảnh báo: SHAP cho LightGBM, z-score fallback cho không giám sát, gộp yếu tố, câu tiếng Việt, ngữ cảnh "thường … nay …"."""

import math

import numpy as np
import pandas as pd
import pytest

from ml.rba import baselines as B
from ml.rba import ensemble as En
from ml.rba import explain as Ex
from ml.rba import models as Mo
from ml.rba import train
from ml.rba.features import FEATURE_NAMES, EventRecord

FLAGS = [f"new_{a}" for a in ("country", "asn", "ip", "ua", "browser", "os", "device", "browser_family", "os_family")]


def make_table(n=6000, seed=0):
    """Đăng nhập tổng hợp: IP tấn công (8%) có ip_distinct_users_24h và rare_asn cao — tín hiệu đã biết để kiểm tra giải thích."""
    rng = np.random.default_rng(seed)
    df = pd.DataFrame({name: rng.gamma(2.0, 1.0, n) for name in FEATURE_NAMES})
    for name in FLAGS:
        df[name] = (rng.random(n) < 0.1).astype(float)
    df["llr_sum"] = df[[f"llr_{a}" for a in ("ip", "country", "asn", "ua", "browser", "os", "device")]].sum(axis=1)  # đúng như đặc trưng thật
    df["cur_success"] = (rng.random(n) < 0.8).astype(float)
    df["cur_device_code"] = rng.integers(0, 4, n).astype(float)
    df["u_n_success"] = rng.integers(1, 20, n).astype(float)
    df["row_id"] = np.arange(n)
    df["user_id"] = rng.integers(0, 900, n)
    df["is_attack_ip"] = rng.random(n) < 0.08
    df["is_ato"] = False
    df["in_warmup"] = False
    df["partition"] = rng.choice(["train", "val", "test"], n, p=[0.6, 0.2, 0.2])
    df["pop_weight"] = 1.0
    attack = df["is_attack_ip"].to_numpy()
    df.loc[attack, "ip_distinct_users_24h"] += 15.0
    df.loc[attack, "rare_asn"] += 6.0
    return df


@pytest.fixture(scope="module")
def table():
    return make_table()


@pytest.fixture(scope="module")
def reference(table):
    return Ex.ExplainReference.fit(table)


@pytest.fixture(scope="module")
def gbm(table):
    train_set, val_set = Mo.attack_ip_sets(table)
    return Mo.train_gbm("demo", FEATURE_NAMES, train_set, val_set, params={"num_threads": 2, "num_leaves": 15, "min_data_in_leaf": 20}, rounds=80, early_stopping=10)


@pytest.fixture(scope="module")
def forest(table):
    return B.IsolationForestScorer(n_estimators=40, max_samples=256, sample_rows=3000).fit(table)


def typical_row(reference):
    return dict(reference.typical)


# ------------------------------------------------------------------------------------------------ yếu tố và câu chữ


def test_every_feature_belongs_to_exactly_one_concept_and_has_a_sentence(reference):
    assert sorted(Ex.CONCEPT_OF) == sorted(FEATURE_NAMES)
    assert sum(len(f) for f in Ex.CONCEPTS.values()) == len(FEATURE_NAMES)  # không đặc trưng nào nằm ở hai yếu tố
    for feature in FEATURE_NAMES:
        if feature == "llr_sum":  # tổng của bảy llr_*: được chia lại, không tự có câu
            continue
        row = typical_row(reference)
        row[feature] = reference.typical[feature] + 3.0
        text = Ex.describe(feature, row, reference)
        assert text and "nan" not in text.lower() and "{" not in text and "}" not in text, (feature, text)


def test_missing_values_get_an_honest_sentence_instead_of_nan(reference):
    row = typical_row(reference) | {"ip_fail_ratio_24h": math.nan, "u_secs_since_last_success": math.nan, "asn_unknown_share_24h": math.nan}
    assert Ex.describe("ip_fail_ratio_24h", row, reference) == "IP chưa có lượt thử nào khác trong 24h"
    assert Ex.describe("u_secs_since_last_success", row, reference) == "tài khoản chưa từng đăng nhập thành công"
    assert Ex.describe("asn_unknown_share_24h", row, reference) == "chưa rõ nhà mạng"


def test_sentence_combines_new_rare_and_usual_vs_today(reference):
    row = typical_row(reference) | {"new_country": 1.0, "rare_country": -math.log(0.0003), "llr_country": 3.0}
    assert Ex.describe("new_country", row, reference) == "quốc gia mới (hiếm 0.03%, thường " + Ex._share(math.exp(-reference.typical["rare_country"])) + ")"
    context = Ex.Context(today={"country": "RU"}, usual={"country": "VN"})
    assert Ex.describe("llr_country", row, reference, context) == "quốc gia: thường VN → nay RU (hiếm 0.03%)"
    assert Ex.describe("rare_country", row, reference, context).startswith("quốc gia: thường VN → nay RU")  # cùng câu dù đặc trưng dẫn đầu khác
    only_today = Ex.Context(today={"country": "RU"}, usual={})  # tài khoản chưa có lịch sử: không có "thường"
    assert Ex.describe("new_country", row, reference, only_today).startswith("quốc gia mới: RU")


def test_familiar_value_is_not_called_new_or_strange(reference):
    """SHAP có thể coi chính sự quen thuộc làm bằng chứng (kẻ tấn công cùng nhà mạng nạn nhân): câu phải nói đúng như vậy."""
    row = typical_row(reference) | {"new_asn": 0.0, "llr_asn": -1.0, "rare_asn": reference.typical["rare_asn"]}
    assert Ex.describe("llr_asn", row, reference) == "nhà mạng quen thuộc với tài khoản"
    row["llr_asn"] = 2.0
    assert Ex.describe("llr_asn", row, reference) == "nhà mạng lạ với tài khoản"


def test_rare_but_not_new_value_uses_rare_or_uncommon_wording(reference):
    common = typical_row(reference) | {"new_os_family": 0.0, "rare_os": -math.log(0.3)}
    rare = typical_row(reference) | {"new_os_family": 0.0, "rare_os": -math.log(0.002)}
    assert Ex.describe("rare_os", common, reference).startswith("hệ điều hành ít gặp: 30%")
    assert Ex.describe("rare_os", rare, reference).startswith("hệ điều hành hiếm: 0.20%")


def test_usual_gap_of_the_account_replaces_the_population_typical(reference):
    row = typical_row(reference) | {"u_secs_since_last_success": 45 * 86400.0}
    without = Ex.describe("u_secs_since_last_success", row, reference)
    with_context = Ex.describe("u_secs_since_last_success", row, reference, Ex.Context(usual_gap_secs=2 * 86400.0))
    assert without.startswith("cách lần thành công trước 45 ngày (thường ") and with_context == "cách lần thành công trước 45 ngày (thường 2 ngày)"


def test_number_and_duration_formatting_stay_short():
    assert [Ex._duration(s) for s in (30, 300, 7200, 50 * 3600, 90 * 86400)] == ["30 giây", "5 phút", "2 giờ", "2 ngày", "90 ngày"]
    assert [Ex._share(p) for p in (0.65, 0.05, 0.0025, 0.00002)] == ["65%", "5.0%", "0.25%", "<0.01%"]
    assert [Ex._int(v) for v in (7, 626.4, 15613)] == ["7", "626", "16k"]
    zero = Ex.ExplainReference({f: 0.0 for f in FEATURE_NAMES}, 1)
    assert Ex.describe("cur_device_code", {**zero.typical, "cur_device_code": 3.0}, zero) == "loại thiết bị bot"


# ------------------------------------------------------------------------------------------------ ngữ cảnh


def event(t_days, country="VN", asn=100, browser="Chrome 90.0.4430", os="Windows 10", device="desktop", success=True):
    return EventRecord(int(t_days * 86400 * 1e6), 7, "1.1.1.1", asn, country, "ua", browser, os, device, success)


def test_context_takes_the_most_common_value_of_past_successes_only():
    history = [event(d) for d in range(1, 7)] + [event(7, country="DE"), event(8, country="RU", success=False), event(50)]  # lần cuối ở tương lai
    today = event(10, country="RU", asn=200, browser="Firefox 80.0", os="Linux", device="mobile")
    context = Ex.build_context(today, history)
    assert context.usual == {"country": "VN", "asn": "AS100", "browser": "Chrome", "os": "Windows", "device": "desktop"}  # bản phiên bản bị bỏ
    assert context.today == {"country": "RU", "asn": "AS200", "browser": "Firefox", "os": "Linux", "device": "mobile"}
    assert context.pair("country") == ("VN", "RU") and context.pair("nope") is None
    assert context.usual_gap_secs == pytest.approx(86400.0)  # trung vị các khoảng cách giữa 7 lần thành công trước đó


def test_context_of_a_new_account_has_no_usual_values_and_missing_attributes_are_skipped():
    fresh = Ex.build_context(event(10), None)
    assert fresh.usual == {} and fresh.usual_gap_secs is None and fresh.pair("country") is None
    only_fails = Ex.build_context(event(10), [event(9, success=False)])
    assert only_fails.usual == {}
    unknown = Ex.build_context(EventRecord(10, 7, "1.1.1.1", None, None, "ua", None, None, None, True), [event(0)] * 0)
    assert unknown.today == {}
    same = Ex.build_context(event(10), [event(d) for d in range(1, 5)])
    assert same.pair("country") is None  # cùng giá trị quen thuộc: không có gì để so sánh


# ------------------------------------------------------------------------------------------------ SHAP


def test_shap_contributions_add_up_to_the_score_and_match_the_shap_library(table, gbm):
    frame = table.sample(300, random_state=1)
    attr = Ex.shap_attribution(gbm, frame)
    assert attr.method == "shap" and attr.features == FEATURE_NAMES and attr.values.shape == (300, 50)
    assert np.allclose(attr.values.sum(axis=1) + attr.base, gbm(frame), atol=1e-9)  # đóng góp + giá trị nền = điểm thô

    shap = pytest.importorskip("shap")
    reference_values = shap.TreeExplainer(gbm.booster).shap_values(Mo.feature_matrix(frame, gbm.features))
    reference_values = reference_values[1] if isinstance(reference_values, list) else reference_values
    assert np.allclose(attr.values, reference_values, atol=1e-6)


def test_shap_explanation_points_at_the_planted_signal(table, gbm, reference):
    positives = table[table["is_attack_ip"] & (table["partition"] == "test")].head(150)
    method, factors = Ex.explain_component(gbm, positives, reference)
    assert method == "shap" and len(factors) == len(positives)
    top = [f[0].concept for f in factors if f]
    assert len(top) > 0.9 * len(positives)
    assert np.mean([c in {"hoat_dong_ip", "nha_mang"} for c in top]) > 0.9  # hai đặc trưng được cài tín hiệu
    assert all(len(f) <= Ex.TOP_N for f in factors)
    assert all(a.contribution >= b.contribution for f in factors for a, b in zip(f, f[1:]))  # giảm dần


def test_llr_sum_credit_flows_to_the_parts_that_make_it_high():
    features = ["llr_sum", "llr_country", "llr_asn", "llr_ip", "llr_ua", "llr_browser", "llr_os", "llr_device", "rare_asn"]
    frame = pd.DataFrame([[9.0, 3.0, 1.0, -2.0, -1.0, 0.0, -0.5, -3.0, 5.0]], columns=features)
    values = np.array([[2.0, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.5]])
    spread = Ex.spread_llr_sum(Ex.Attribution("shap", features, values), frame)
    assert spread[0, features.index("llr_country")] == pytest.approx(0.1 + 2.0 * 0.75)  # 3 / (3 + 1)
    assert spread[0, features.index("llr_asn")] == pytest.approx(2.0 * 0.25)
    assert spread[0, features.index("llr_ip")] == 0.0 and spread[0, features.index("llr_sum")] == 0.0
    assert spread[0, features.index("rare_asn")] == 0.5 and spread.sum() == pytest.approx(values.sum())  # tổng đóng góp giữ nguyên

    quiet = frame.copy()
    quiet[[f for f in features if f.startswith("llr_") and f != "llr_sum"]] = -1.0  # mọi thuộc tính quen thuộc: không có ai nhận phần
    assert Ex.spread_llr_sum(Ex.Attribution("shap", features, values), quiet)[0, 0] == 0.0
    assert Ex.spread_llr_sum(Ex.Attribution("zscore", features, values), frame)[0, 0] == 2.0  # z-score không đụng tới


def test_select_concepts_drops_small_and_negative_contributions():
    scores = np.array([[1.0, 0.05, -2.0, 0.6, 0.0], [0.0, 0.0, 0.0, 0.0, 0.0], [5.0, 0.4, 0.3, 0.2, 0.1]])
    assert Ex.select_concepts(scores, top_n=3, min_value=0.2) == [[0, 3], [], [0, 1, 2]]
    assert Ex.select_concepts(scores, top_n=3, min_value=0.0, min_share=0.1) == [[0, 3], [], [0]]  # dưới 10% tổng dương (6,0 → 0,6) thì bỏ
    assert Ex.select_concepts(scores, top_n=1) == [[0], [], [0]]


# ------------------------------------------------------------------------------------------------ z-score


def test_forest_exposes_its_standardized_space(table, forest):
    z = forest.standardize(table.head(50))
    assert z.shape == (50, 50) and forest.feature_names() == FEATURE_NAMES and np.isfinite(z).all()
    assert np.allclose(forest.standardize(table.head(50)), forest._prepare(table.head(50)))


def test_zscore_points_at_the_feature_that_is_far_from_normal(table, forest, reference):
    base = table[table["partition"] == "test"].head(30).copy()
    for column, shift, expected in (("rare_country", 12.0, "quoc_gia"), ("ip_distinct_users_24h", 40.0, "hoat_dong_ip")):
        frame = base.copy()
        frame[column] += shift
        method, factors = Ex.explain_component(forest, frame, reference)
        assert method == "zscore"
        assert np.mean([f and f[0].concept == expected for f in factors]) > 0.9, column

    few = base.copy()
    few["u_n_success"], few["u_age_days"] = 0.0, 0.0  # ít lịch sử là hướng đáng ngờ; nhiều lịch sử thì không
    assert Ex.zscore_attribution(forest, few).values[:, FEATURE_NAMES.index("u_n_success")].mean() > 0.5
    many = base.copy()
    many["u_n_success"] = 200.0
    assert Ex.zscore_attribution(forest, many).values[:, FEATURE_NAMES.index("u_n_success")].max() == 0.0

    quiet = base.copy()
    quiet["asn_attempts_24h"] = 0.0
    assert Ex.zscore_attribution(forest, quiet).values[:, FEATURE_NAMES.index("asn_attempts_24h")].mean() > 0.5  # nhà mạng lưu lượng cực thấp cũng lạ
    assert (Ex.zscore_attribution(forest, base).values[:, [FEATURE_NAMES.index(f) for f in ("cur_success", "cur_device_code", "llr_sum")]] == 0).all()


def test_zscore_works_for_the_other_unsupervised_models_and_rejects_unknown_scorers(table):
    knn = Mo.KnnDistanceScorer(k=5, reference_rows=1500).fit(table)
    autoencoder = Mo.AutoencoderScorer(sample_rows=2000, max_iter=3).fit(table)
    frame = table[table["partition"] == "test"].head(20)
    for scorer in (knn, autoencoder):
        attr = Ex.zscore_attribution(scorer, frame)
        assert attr.method == "zscore" and attr.features == FEATURE_NAMES and attr.values.shape == (20, 50) and (attr.values >= 0).all()
    with pytest.raises(TypeError):
        Ex.attribute(lambda f: np.zeros(len(f)), frame)


# ------------------------------------------------------------------------------------------------ hybrid


@pytest.fixture(scope="module")
def hybrid(table, gbm, forest):
    return train.build_hybrid(table, [("ip_tan_cong", gbm, None), ("chiem_tai_khoan", gbm, En.gate_success_with_history), ("bat_thuong", forest, En.gate_success)])


def test_hybrid_explainer_uses_the_component_that_fired(table, hybrid, reference):
    val = table[(table["partition"] == "val") & ~table["is_attack_ip"] & (table["cur_success"] == 1)]
    threshold = En.threshold_for_fpr(hybrid(val), val["pop_weight"].to_numpy(), 0.01)
    explainer = Ex.HybridExplainer(hybrid, reference, threshold)

    attack = table[table["is_attack_ip"] & (table["partition"] == "test")].head(40)
    strange = table[(table["partition"] == "test") & ~table["is_attack_ip"] & (table["cur_success"] == 1)].head(40).copy()
    strange["rare_country"] += 14.0  # lạ ở đặc trưng mà LightGBM không được cài tín hiệu: chỉ rừng cô lập bắt
    strange["llr_country"] += 8.0
    mixed = pd.concat([attack, strange])
    explanations = explainer.explain(mixed)

    assert len(explanations) == len(mixed) and all(e is not None for e in explanations)
    by_component = pd.Series([e.component for e in explanations[:40]]).value_counts()
    assert by_component.index[0] in {"ip_tan_cong", "chiem_tai_khoan"}  # cùng một LightGBM đứng sau hai thành phần: cả hai đúng
    forest_hits = [e for e in explanations[40:] if e.component == "bat_thuong"]
    assert len(forest_hits) >= 20 and all(e.method == "zscore" for e in forest_hits)
    assert np.mean([e.factors[0].concept == "quoc_gia" for e in forest_hits]) > 0.9
    assert all(e.method == "shap" for e in explanations[:40] if e.component != "bat_thuong")

    # thứ tự dòng được giữ: điểm hybrid của từng giải thích khớp với điểm hybrid tính trực tiếp
    assert np.allclose([e.score for e in explanations], hybrid(mixed))
    sample = forest_hits[0]
    assert sample.label == "đăng nhập bất thường" and sample.headline.startswith("đăng nhập bất thường — ") and sample.text in sample.headline
    assert all(len(e.factors) <= Ex.TOP_N and len(e.text) < 220 for e in explanations)


def test_explanation_lists_other_components_that_also_fired(table, hybrid, reference):
    explainer = Ex.HybridExplainer(hybrid, reference, threshold=0.5)  # ngưỡng thấp: nhiều thành phần cùng vượt
    frame = table[(table["partition"] == "test") & (table["cur_success"] == 1) & (table["u_n_success"] >= 1)].head(60)
    explanations = explainer.explain(frame)
    assert any(e.also for e in explanations)
    assert all(e.component not in e.also for e in explanations)
    assert Ex.Explanation("x", "shap", 3.0, []).text == "không có yếu tố nổi bật"


def test_explainer_passes_each_rows_own_context_through(table, hybrid, reference):
    explainer = Ex.HybridExplainer(hybrid, reference, threshold=2.0)
    frame = table[(table["partition"] == "test") & (table["cur_success"] == 1) & (table["u_n_success"] >= 1)].head(80).copy()
    frame["new_country"], frame["rare_country"], frame["llr_country"] = 1.0, 12.0, 4.0
    contexts = [Ex.Context(today={"country": "RU"}, usual={"country": "VN"}) if i % 2 == 0 else None for i in range(len(frame))]
    explanations = explainer.explain(frame, contexts)
    with_context = [e for i, e in enumerate(explanations) if i % 2 == 0 and any(f.concept == "quoc_gia" for f in e.factors)]
    without = [e for i, e in enumerate(explanations) if i % 2 == 1 and any(f.concept == "quoc_gia" for f in e.factors)]
    assert with_context and without
    assert all("thường VN → nay RU" in e.text for e in with_context) and all("→" not in e.text for e in without)


# ------------------------------------------------------------------------------------------------ bảng "thường thấy"


def test_reference_uses_only_legit_successful_train_logins_and_survives_a_round_trip(table, tmp_path):
    df = table.copy()
    poisoned = df["partition"] == "test"
    df.loc[poisoned, "rare_asn"] = 999.0  # ngoài train: không được lọt vào mức thường thấy
    df.loc[df["is_attack_ip"], "rare_asn"] = 999.0  # IP tấn công: loại
    reference = Ex.ExplainReference.fit(df)
    assert reference.typical["rare_asn"] < 10 and set(reference.typical) == set(FEATURE_NAMES)
    assert reference.n_rows == int(((df["partition"] == "train") & (df["cur_success"] == 1) & ~df["is_attack_ip"]).sum())
    assert np.array_equal(reference.vector(["rare_asn", "new_country"]), [reference.typical["rare_asn"], reference.typical["new_country"]])

    path = reference.save(tmp_path / "ref.json")
    loaded = Ex.ExplainReference.load(path)
    assert loaded.typical == reference.typical and loaded.n_rows == reference.n_rows and loaded.feature_version == "v2"

    import json

    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["signature"] = "khac"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="danh sách đặc trưng khác"):
        Ex.ExplainReference.load(path)


def test_feature_signature_changes_when_the_feature_list_changes(monkeypatch):
    from ml.rba import features

    original = features.feature_signature()
    assert len(original) == 12 and original == features.feature_signature()
    monkeypatch.setattr(features, "FEATURE_NAMES", features.FEATURE_NAMES[:-1])
    assert features.feature_signature() != original
