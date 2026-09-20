"""MR2 — lấy mẫu theo user và kiểm tra bất biến (dùng dữ liệu tổng hợp nhỏ, không cần file RBA thật)."""

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from ml.rba import sample, splits


def _user_stats(n_regular=2000):
    rows = [{"user_id": i, "n_events": 1 + (i % 12), "n_ato": 0} for i in range(n_regular)]
    rows.append({"user_id": 10_000, "n_events": 500, "n_ato": 0})  # khổng lồ
    rows.append({"user_id": 10_001, "n_events": 3, "n_ato": 2})  # có ATO, ít sự kiện
    return pd.DataFrame(rows)


def test_pick_users_forces_ato_users_and_drops_mega_users():
    rates = {"single": 0.0, "light": 0.0, "heavy": 0.0}  # tỉ lệ 0 -> chỉ user ATO được chọn
    picked = sample.pick_users(_user_stats(), rates=rates, mega_min=100)
    assert list(picked["user_id"]) == [10_001]
    assert bool(picked.loc[0, "forced"]) and picked.loc[0, "sample_rate"] == 1.0

    everything = sample.pick_users(_user_stats(), rates={"single": 1, "light": 1, "heavy": 1}, mega_min=100)
    assert 10_000 not in set(everything["user_id"])


def test_pick_users_is_deterministic_and_respects_rates():
    rates = {"single": 0.5, "light": 0.5, "heavy": 0.5}
    a = sample.pick_users(_user_stats(), rates=rates, mega_min=100, seed=7)
    b = sample.pick_users(_user_stats(), rates=rates, mega_min=100, seed=7)
    c = sample.pick_users(_user_stats(), rates=rates, mega_min=100, seed=8)
    assert a.equals(b)
    assert not a.equals(c)
    assert len(a) == pytest.approx(0.5 * 2001, rel=0.1)


def _full_frame(seed=0):
    """~ vài nghìn dòng trải 4 giai đoạn (train/val/test/late), gồm IP tấn công, 1 user khổng lồ và 2 dòng ATO."""
    rng = np.random.default_rng(seed)
    periods = ["2020-03-10", "2020-08-15", "2020-10-10", "2021-02-10"]  # lần lượt: train / val / test / late
    rows = []
    row_id = 0

    def add(ts, user, ip, attack, ato=False):
        nonlocal row_id
        rows.append(
            dict(
                row_id=row_id, ts=pd.Timestamp(ts) + pd.Timedelta(seconds=row_id), user_id=user, ip=ip, country="NO",
                asn=29695, ua=f"UA-{user % 5}", browser="Chrome 1", os="Windows 10", device_type="desktop",
                success=not attack, is_attack_ip=attack, is_ato=ato, is_private_ip=False, is_fake_asn=False,
                ua_parse_failed=False,
            )
        )
        row_id += 1

    for user in range(60):  # user bình thường, đăng nhập ở cả 4 giai đoạn
        for period in periods:
            add(period, user, f"81.0.0.{user}", False)
    for i in range(400):  # 400 IP tấn công, mỗi IP xuất hiện ở cả 4 giai đoạn
        for period in periods:
            add(period, int(rng.integers(0, 60)), f"185.7.{i // 250}.{i % 250}", True)
    for _ in range(300):  # user khổng lồ
        add("2020-06-01", 999_999, "81.0.1.1", False)
    add("2021-02-20", 3, "81.0.0.3", False, ato=True)
    add("2020-04-01", 4, "81.0.0.4", False, ato=True)
    return pd.DataFrame(rows).assign(ts=lambda d: d["ts"].astype("datetime64[us]"))


@pytest.fixture()
def full_parquet(tmp_path):
    path = tmp_path / "full.parquet"
    pq.write_table(pa.Table.from_pandas(_full_frame(), preserve_index=False), path)
    return path


def test_build_sample_end_to_end_keeps_full_history_and_invariants(full_parquet, tmp_path):
    out = tmp_path / "sample.parquet"
    rates = {"single": 1.0, "light": 1.0, "heavy": 1.0}
    report = sample.build_sample(full_parquet, out, rates=rates, mega_min=200)

    df = pq.read_table(out).to_pandas()
    assert 999_999 not in set(df["user_id"])  # user khổng lồ bị loại
    assert report["ato"]["rows"] == 2 and report["ato"]["users"] == 2
    assert set(df.loc[df["is_ato"], "partition"]) == {splits.ATO}
    assert {"ua_hash", "partition", "split_time", "ip_group", "stratum"} <= set(df.columns)
    assert "ua" not in df.columns
    for name in splits.PARTITIONS:
        assert report["by_partition"][name]["attack_rows"] > 0  # cả 4 tập đều có dòng tấn công

    attack = df[df["is_attack_ip"] & df["partition"].isin(splits.PARTITIONS)]
    for a, b in (("train", "val"), ("train", "test"), ("val", "test"), ("train", "late"), ("val", "late")):
        ips_a = set(attack.loc[attack["partition"] == a, "ip"])
        ips_b = set(attack.loc[attack["partition"] == b, "ip"])
        assert ips_a.isdisjoint(ips_b)


def test_verify_detects_attack_ip_leak_between_partitions(full_parquet, tmp_path):
    out = tmp_path / "sample.parquet"
    sample.build_sample(full_parquet, out, rates={"single": 1.0, "light": 1.0, "heavy": 1.0}, mega_min=200)
    df = pq.read_table(out).to_pandas()

    attack_train = df[(df["partition"] == "train") & df["is_attack_ip"]].iloc[0]
    leaked = df[(df["partition"] == "test") & df["is_attack_ip"]].index[0]
    df.loc[leaked, "ip"] = attack_train["ip"]  # cố tình cho 1 IP tấn công xuất hiện ở cả train và test

    picked = pd.DataFrame({"user_id": df["user_id"].unique()})
    with pytest.raises(AssertionError, match="trùng"):
        sample.verify_and_summarize(df, expected_events=len(df), picked=picked, mega=pd.DataFrame({"user_id": []}))
