"""MR2 — kiểm tra các bất biến trên MẪU RBA THẬT (backend/ml/data/rba/rba_sample.parquet).

Tự bỏ qua nếu chưa chạy `python -m ml.rba.etl` và `python -m ml.rba.sample` (file dữ liệu ~1GB
không nằm trong git). Đây là bằng chứng cho điều kiện "Xong khi" của MR2: không IP tấn công nào
trùng giữa tập huấn luyện và các tập đánh giá.
"""

import pyarrow.parquet as pq
import pytest

from ml.rba import splits
from ml.rba.sample import MEGA_USER_MIN_EVENTS, SAMPLE_PARQUET

pytestmark = pytest.mark.skipif(not SAMPLE_PARQUET.is_file(), reason="chưa có rba_sample.parquet")

_COLUMNS = ["ts", "ip", "user_id", "is_attack_ip", "is_ato", "partition", "weight", "split_time", "stratum"]


@pytest.fixture(scope="module")
def df():
    return pq.read_table(SAMPLE_PARQUET, columns=_COLUMNS).to_pandas()


def _attack_ips(df, partition):
    rows = df[(df["partition"] == partition) & df["is_attack_ip"]]
    return set(rows["ip"])


def test_no_attack_ip_shared_between_training_and_evaluation(df):
    for evaluation in ("val", "test", "late"):
        shared = _attack_ips(df, "train") & _attack_ips(df, evaluation)
        assert not shared, f"{len(shared)} IP tấn công có ở cả train và {evaluation}"
    assert not (_attack_ips(df, "val") & _attack_ips(df, "test"))
    assert not (_attack_ips(df, "val") & _attack_ips(df, "late"))


def test_every_partition_has_attack_rows_to_learn_and_evaluate_on(df):
    for name in splits.PARTITIONS:
        assert len(_attack_ips(df, name)) >= 300, f"tập {name} có quá ít IP tấn công"


def test_partitions_are_ordered_in_time(df):
    ranges = {p: df.loc[df["partition"] == p, "ts"].agg(["min", "max"]) for p in splits.PARTITIONS}
    assert ranges["train"]["max"] < ranges["val"]["min"]
    assert ranges["val"]["max"] < ranges["test"]["min"]
    assert ranges["test"]["max"] < ranges["late"]["min"]


def test_all_141_ato_rows_are_holdout_only_and_38_are_in_the_future_test_window(df):
    ato = df[df["is_ato"]]
    assert len(ato) == 141 and ato["user_id"].nunique() == 138
    assert set(ato["partition"]) == {splits.ATO}
    assert (ato["ts"] >= splits.VAL_END).sum() == 38  # ATO "tương lai" so với train/val


def test_users_keep_their_complete_history_and_giants_are_excluded(df):
    per_user = df.groupby("user_id").size()
    assert per_user.max() < MEGA_USER_MIN_EVENTS
    assert df["user_id"].nunique() > 300_000


def test_weights_restore_a_realistic_attack_share(df):
    test = df[df["partition"] == "test"]
    raw_share = test["is_attack_ip"].mean()
    weighted_share = (test["weight"] * test["is_attack_ip"]).sum() / test["weight"].sum()
    assert weighted_share > 3 * raw_share  # giữ 15% IP tấn công -> trọng số ~6,7 phục hồi tỉ lệ
