"""MR6 — mô hình LightGBM / kNN / Autoencoder và dựng tập huấn luyện (dữ liệu tổng hợp nhỏ)."""

import numpy as np
import pandas as pd
import pytest

from ml.rba import baselines as B
from ml.rba import models as Mo
from ml.rba.features import FEATURE_NAMES


def synthetic_table(n=8000, seed=0):
    rng = np.random.default_rng(seed)
    df = pd.DataFrame({name: rng.gamma(2.0, 1.0, n) for name in FEATURE_NAMES})
    for name in [f"new_{a}" for a in ("country", "asn", "ip", "ua", "browser", "os", "device", "browser_family", "os_family")] + ["cur_success"]:
        df[name] = (rng.random(n) < 0.5).astype(float)
    df["cur_device_code"] = rng.integers(0, 6, n).astype(float)
    df["row_id"] = np.arange(n)
    df["user_id"] = rng.integers(0, 900, n)
    df["is_attack_ip"] = rng.random(n) < 0.08
    df["is_ato"] = False
    df["in_warmup"] = False
    df["partition"] = rng.choice(["train", "val", "test"], n, p=[0.6, 0.2, 0.2])
    df["pop_weight"] = np.where(df["is_attack_ip"], 4.0, 2.0)
    attack = df["is_attack_ip"].to_numpy()
    df.loc[attack, "rare_asn"] += 5.0
    df.loc[attack, "ip_distinct_users_24h"] += 8.0
    return df


def synthetic_attackers(df, n=400, seed=1):
    rng = np.random.default_rng(seed)
    rows = df[(df["partition"].isin(["train", "val"])) & ~df["is_attack_ip"]].sample(n, random_state=seed).copy()
    rows["row_id"] = 10**9 + np.arange(n)
    rows["cur_success"] = 1.0
    rows["new_country"] = 1.0
    rows["llr_country"] += 4.0
    rows["period"] = np.where(rows["partition"] == "train", "train", "val")
    rows["attacker_type"] = rng.choice(["naive", "vpn", "targeted"], n)
    rows["pop_weight"] = 1.0
    rows["partition"] = "attacker"
    return rows


@pytest.fixture(scope="module")
def table():
    return synthetic_table()


def test_gbm_learns_the_planted_signal_and_survives_save_and_load(table, tmp_path):
    train, val = Mo.attack_ip_sets(table)
    scorer = Mo.train_gbm(
        "demo", FEATURE_NAMES, train, val, params={"num_threads": 2, "num_leaves": 15, "min_data_in_leaf": 20}, rounds=80, early_stopping=10
    )
    assert scorer.meta["val_average_precision"] > 0.5
    assert {"rare_asn", "ip_distinct_users_24h"} & {f["feature"] for f in scorer.meta["top_features"][:3]}

    scores = scorer(table.head(200))
    assert scores[table["is_attack_ip"].head(200).to_numpy()].mean() > scores[~table["is_attack_ip"].head(200).to_numpy()].mean()

    scorer.save(tmp_path)
    loaded = Mo.GbmScorer.load("demo", tmp_path)
    assert np.allclose(loaded(table.head(200)), scores)
    assert loaded.features == scorer.features


def test_attack_ip_sets_use_population_weights_and_skip_warmup(table):
    warm = table.copy()
    warm.loc[warm.index[:300], "in_warmup"] = True
    (train, y_tr, w_tr), (val, y_va, w_va) = Mo.attack_ip_sets(warm)
    assert set(train["partition"]) == {"train"} and set(val["partition"]) == {"val"}
    assert not train["in_warmup"].any() and not val["in_warmup"].any()
    assert np.allclose(w_tr, train["pop_weight"]) and np.array_equal(y_tr.astype(bool), train["is_attack_ip"])


def test_simulated_attacker_sets_use_legit_successes_and_the_requested_prior(table):
    attackers = synthetic_attackers(table)
    (train, y_tr, w_tr), (val, y_va, w_va) = Mo.simulated_attacker_sets(table, attackers, prior=0.05, negative_cap=10**6)
    negatives = train[y_tr == 0]
    assert (negatives["cur_success"] == 1).all() and not negatives["is_attack_ip"].any()
    assert set(negatives["partition"]) == {"train"}
    positive_weight, negative_weight = w_tr[y_tr == 1].sum(), w_tr[y_tr == 0].sum()
    assert positive_weight / (positive_weight + negative_weight) == pytest.approx(0.05, rel=1e-3)
    assert int(y_tr.sum()) == int((attackers["period"] == "train").sum()) and int(y_va.sum()) == int((attackers["period"] == "val").sum())


def test_simulated_attacker_sets_cap_the_negatives_deterministically(table):
    attackers = synthetic_attackers(table)
    a = Mo.simulated_attacker_sets(table, attackers, negative_cap=500)[0][0]
    b = Mo.simulated_attacker_sets(table, attackers, negative_cap=500)[0][0]
    assert list(a["row_id"]) == list(b["row_id"]) and (a["row_id"] < 10**9).sum() == 500


def test_combined_sets_weight_simulated_attackers_relative_to_attack_ip(table):
    with_ato = table.copy()
    with_ato.loc[with_ato.index[:50], "is_ato"] = True
    attackers = synthetic_attackers(table)
    (train, y, w), _ = Mo.combined_sets(with_ato, attackers, rho=0.5)
    assert not train["is_ato"].any()
    from_ip = y.astype(bool) & (train["row_id"].to_numpy() < 10**9)
    from_sim = train["row_id"].to_numpy() >= 10**9
    assert w[from_sim].sum() == pytest.approx(0.5 * w[from_ip].sum(), rel=1e-4)
    assert y[from_sim].all()


def test_feature_preprocessor_matches_the_isolation_forest_preprocessing(table):
    forest = B.IsolationForestScorer(n_estimators=10, max_samples=64, sample_rows=2000).fit(table.assign(partition="train"))
    sample = Mo._legit_train_sample(table.assign(partition="train"), 2000, B.RANDOM_STATE)
    pre = Mo.FeaturePreprocessor().fit(sample)
    probe = table.head(300)
    assert np.allclose(pre.transform(probe), forest._prepare(probe), atol=1e-4)


def test_knn_distance_ranks_outliers_higher_and_is_chunk_invariant(table):
    data = table.assign(partition="train")
    knn = Mo.KnnDistanceScorer(k=5, reference_rows=1500, chunk=64).fit(data)
    probe = data[~data["is_attack_ip"]].head(200).copy()
    probe.loc[probe.index[:10], FEATURE_NAMES] = probe.loc[probe.index[:10], FEATURE_NAMES] * 30
    scores = knn(probe)
    assert scores[:10].mean() > scores[10:].mean()
    small = Mo.KnnDistanceScorer(k=5, reference_rows=1500, chunk=7).fit(data)
    assert np.allclose(small(probe), scores, rtol=2e-3, atol=1e-3)  # float32: thứ tự cộng của BLAS khác nhau theo cỡ khối


def test_autoencoder_reconstructs_normal_rows_better_than_outliers(table):
    data = table.assign(partition="train")
    ae = Mo.AutoencoderScorer(sample_rows=4000, max_iter=15).fit(data)
    probe = data[~data["is_attack_ip"]].head(200).copy()
    probe.loc[probe.index[:10], FEATURE_NAMES] = probe.loc[probe.index[:10], FEATURE_NAMES] * 30
    scores = ae(probe)
    assert not np.isnan(scores).any() and scores[:10].mean() > scores[10:].mean()
