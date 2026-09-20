"""MR5 — baseline: Freeman, luật Tier 2 hiện tại, luật đã tinh chỉnh, Isolation Forest (dữ liệu tổng hợp nhỏ)."""

import numpy as np
import pandas as pd
import pytest

from ml.rba import baselines as B
from ml.rba.features import FEATURE_NAMES, FREEMAN_ATTRS


def synthetic_table(n=6000, seed=0):
    rng = np.random.default_rng(seed)
    df = pd.DataFrame({name: rng.gamma(2.0, 1.0, n) for name in FEATURE_NAMES})
    for name in [f"new_{a}" for a in ("country", "asn", "ip", "ua", "browser", "os", "device", "browser_family", "os_family")] + ["cur_success"]:
        df[name] = (rng.random(n) < 0.3).astype(float)
    df["u_n_success"] = rng.integers(0, 20, n).astype(float)
    df["u_n_attempts"] = df["u_n_success"] + rng.integers(0, 5, n)
    df["u_fail_streak"] = rng.integers(0, 3, n).astype(float)
    df["is_attack_ip"] = rng.random(n) < 0.08
    df["is_ato"] = False
    df["in_warmup"] = False
    df["partition"] = "train"
    df["weight"] = np.where(df["is_attack_ip"], 5.0, 1.0)
    attack = df["is_attack_ip"].to_numpy()
    df.loc[attack, "rare_asn"] += 4.0  # tín hiệu thật: IP tấn công có ASN hiếm
    df.loc[attack, "ip_distinct_users_24h"] += 6.0
    df.loc[attack, "asn_fail_ratio_24h"] = np.clip(df.loc[attack, "asn_fail_ratio_24h"] / 4 + 0.5, 0, 1)
    df.loc[attack, "new_asn"] = 1.0
    return df


@pytest.fixture(scope="module")
def table():
    return synthetic_table()


def test_freeman_scorer_sums_the_llr_columns_and_can_drop_ip(table):
    full = B.freeman_scorer()(table)
    assert np.allclose(full, table[[f"llr_{a}" for a in FREEMAN_ATTRS]].sum(axis=1))
    no_ip = B.freeman_scorer(tuple(a for a in FREEMAN_ATTRS if a != "ip"))(table)
    assert np.allclose(full - no_ip, table["llr_ip"])


def test_tier2_scorer_matches_the_documented_rules():
    def row(**kw):
        base = dict(u_n_attempts=30.0, u_age_days=40.0, new_country=0.0, cur_success=1.0, u_fail_streak=0.0)
        base.update(kw)
        return base

    frame = pd.DataFrame(
        [
            row(),  # bình thường
            row(new_country=1.0),  # vị trí lạ, không ở chế độ học -> +30
            row(new_country=1.0, u_n_attempts=5.0),  # chế độ học (ít hơn 10 lần) -> 0
            row(new_country=1.0, u_age_days=3.0),  # chế độ học (chưa đủ 7 ngày) -> 0
            row(cur_success=0.0, u_fail_streak=4.0),  # dò mật khẩu -> +40
            row(cur_success=1.0, u_fail_streak=3.0),  # thành công sau chuỗi thất bại -> +50
            row(cur_success=1.0, u_fail_streak=3.0, new_country=1.0),  # 30 + 50
        ]
    )
    assert list(B.tier2_scorer()(frame)) == [0, 30, 0, 0, 40, 50, 80]


def test_tuned_rules_learn_the_signal_and_stay_interpretable(table):
    rules = B.fit_tuned_rules(table)
    described = rules.describe()
    assert len(described) == len(B.RULE_CANDIDATES)
    top_rules = {d["rule"].split(" ")[0] for d in described[:5] if d["weight"] > 0}
    assert {"rare_asn", "ip_distinct_users_24h", "new_asn"} & top_rules  # các đặc trưng thật sự mang tín hiệu
    scores = rules(table)
    assert len(scores) == len(table) and not np.isnan(scores).any()
    assert scores[table["is_attack_ip"]].mean() > scores[~table["is_attack_ip"]].mean()


def test_tuned_rules_thresholds_come_from_train_only():
    train = synthetic_table(seed=1)
    other = train.copy()
    other["partition"] = "test"  # dữ liệu không thuộc train thì bị bỏ qua khi học
    other["rare_asn"] = other["rare_asn"] * 100
    mixed = pd.concat([train, other], ignore_index=True)
    a = B.fit_tuned_rules(train)
    b = B.fit_tuned_rules(mixed)
    assert a.rules == b.rules and np.allclose(a.model.coef_, b.model.coef_)


def test_isolation_forest_ranks_outliers_higher_and_handles_missing_values(table):
    forest = B.IsolationForestScorer(n_estimators=60, max_samples=256, sample_rows=3000).fit(table)
    probe = table.head(300).copy()
    probe.loc[probe.index[:20], FEATURE_NAMES] = probe.loc[probe.index[:20], FEATURE_NAMES] * 50  # 20 dòng cực đoan
    probe.loc[probe.index[100:110], "llr_sum"] = np.nan  # giá trị thiếu không làm hỏng điểm
    scores = forest(probe)
    assert not np.isnan(scores).any()
    assert scores[:20].mean() > scores[20:].mean()


def test_isolation_forest_is_deterministic_and_never_trains_on_known_attacks(table):
    a = B.IsolationForestScorer(n_estimators=40, max_samples=128, sample_rows=2000).fit(table)
    b = B.IsolationForestScorer(n_estimators=40, max_samples=128, sample_rows=2000).fit(table)
    assert np.allclose(a(table.head(200)), b(table.head(200)))

    poisoned = table.copy()
    poisoned.loc[poisoned["is_attack_ip"], FEATURE_NAMES] = 1e6  # nếu học nhầm dòng tấn công, điểm sẽ đổi hẳn
    c = B.IsolationForestScorer(n_estimators=40, max_samples=128, sample_rows=2000).fit(poisoned)
    assert np.allclose(a.medians_, c.medians_)
