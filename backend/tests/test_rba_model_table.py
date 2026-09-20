"""MR3 — bảng đặc trưng THẬT (backend/ml/data/rba/rba_model_table.parquet): các bất biến cơ bản.

Tự bỏ qua nếu chưa chạy `python -m ml.rba.build_features` (mất ~30 phút, file không nằm trong git).
"""

import numpy as np
import pyarrow.parquet as pq
import pytest

from ml.rba import features as F
from ml.rba import splits
from ml.rba.build_features import MODEL_TABLE_PARQUET
from ml.rba.sample import SAMPLE_PARQUET

pytestmark = pytest.mark.skipif(not MODEL_TABLE_PARQUET.is_file(), reason="chưa có rba_model_table.parquet")


@pytest.fixture(scope="module")
def table():
    return pq.read_table(MODEL_TABLE_PARQUET).to_pandas()


def test_table_matches_the_sample_row_for_row(table):
    sample = pq.read_table(SAMPLE_PARQUET, columns=["row_id", "partition", "is_ato", "is_attack_ip"]).to_pandas()
    assert len(table) == len(sample)
    assert table["row_id"].is_unique
    merged = table.merge(sample, on="row_id", suffixes=("", "_sample"))
    assert len(merged) == len(table)
    assert (merged["partition"] == merged["partition_sample"]).all()
    assert (merged["is_ato"] == merged["is_ato_sample"]).all()


def test_all_fifty_features_are_present_and_finite_or_nan(table):
    assert [c for c in F.FEATURE_NAMES if c not in table.columns] == []
    values = table[F.FEATURE_NAMES].to_numpy(dtype="float64")
    assert not np.isinf(values).any()


def test_counts_and_flags_have_sensible_ranges(table):
    for name in F.FEATURE_GROUPS["infra_ip"] + F.FEATURE_GROUPS["infra_asn"] + ["u_n_attempts", "u_n_success", "u_fail_streak"]:
        assert (table[name].dropna() >= 0).all(), name
    assert (table["u_n_success"].dropna() <= table["u_n_attempts"].dropna()).all()
    for name in F.FEATURE_GROUPS["novelty"] + ["cur_success"]:
        assert set(table[name].dropna().unique()) <= {0.0, 1.0}, name
    assert (table[[f"rare_{a}" for a in F.FREEMAN_ATTRS]] >= -1e-6).all().all()
    assert (table["ip_fail_ratio_24h"].dropna().between(0, 1)).all()


def test_user_features_exist_for_every_row_because_the_sample_has_only_real_accounts(table):
    assert table["u_n_attempts"].notna().all()
    assert table["llr_sum"].notna().all()


def test_warmup_rows_are_exactly_the_first_two_weeks(table):
    warm = table[table["in_warmup"]]
    assert warm["ts"].max() < splits.WARMUP_END <= table.loc[~table["in_warmup"], "ts"].min()
    assert 0.02 < len(warm) / len(table) < 0.06


def test_history_grows_with_time_for_each_user(table):
    ordered = table.sort_values(["user_id", "ts", "row_id"])
    grown = ordered.groupby("user_id")["u_n_attempts"].diff().dropna()
    assert (grown >= 0).all()  # số lần thử trước đó của một tài khoản không bao giờ giảm theo thời gian
