"""MR2 — chia train/val/test/late: không rò rỉ IP tấn công giữa các tập, thứ tự thời gian đúng."""

import pandas as pd
import pytest

from ml.rba import splits


def test_time_split_boundaries():
    ts = pd.Series(
        pd.to_datetime(
            [
                "2020-02-03", "2020-07-31 23:59:59",  # train
                "2020-08-01", "2020-08-31",  # val
                "2020-09-01", "2020-11-30",  # test
                "2020-12-01", "2021-02-28",  # late
            ],
            format="mixed",
        )
    )
    expected = ["train", "train", "val", "val", "test", "test", "late", "late"]
    assert list(splits.assign_time_split(ts)) == expected


def test_time_split_rejects_inverted_cutoffs():
    ts = pd.Series(pd.to_datetime(["2020-01-01"]))
    with pytest.raises(ValueError):
        splits.assign_time_split(ts, pd.Timestamp("2021-01-01"), pd.Timestamp("2020-01-01"), pd.Timestamp("2022-01-01"))


def test_ip_group_is_stable_and_roughly_70_15_15():
    ips = [f"203.0.{i // 250}.{i % 250}" for i in range(20000)]
    groups = [splits.ip_group_of(ip) for ip in ips]
    assert groups == [splits.ip_group_of(ip) for ip in ips]  # cùng IP luôn cùng nhóm
    share = {g: groups.count(g) / len(groups) for g in ("train", "val", "test")}
    assert share["train"] == pytest.approx(0.70, abs=0.02)
    assert share["val"] == pytest.approx(0.15, abs=0.02)
    assert share["test"] == pytest.approx(0.15, abs=0.02)


def _frame(rows):
    df = pd.DataFrame(rows, columns=["ts", "ip", "is_attack_ip", "is_ato"])
    df["ts"] = pd.to_datetime(df["ts"])
    df["split_time"] = splits.assign_time_split(df["ts"])
    df["ip_group"] = [splits.ip_group_of(ip) if attack else None for ip, attack in zip(df["ip"], df["is_attack_ip"])]
    df["partition"] = splits.build_partition(df)
    return df


def _ip_in_group(group, prefix):
    return next(f"{prefix}.{i}" for i in range(255) if splits.ip_group_of(f"{prefix}.{i}") == group)


def test_attack_row_is_kept_only_when_ip_group_matches_time_split():
    train_ip = _ip_in_group("train", "9.9.9")
    test_ip = _ip_in_group("test", "9.9.8")
    df = _frame(
        [
            ("2020-03-01", train_ip, True, False),  # nhóm train, thời gian train -> giữ
            ("2020-03-01", test_ip, True, False),  # nhóm test nhưng thời gian train -> loại
            ("2020-10-10", test_ip, True, False),  # nhóm test, thời gian test -> giữ
            ("2020-10-10", train_ip, True, False),  # nhóm train nhưng thời gian test -> loại
            ("2021-02-01", test_ip, True, False),  # "late" dùng nhóm IP của test -> giữ
            ("2021-02-01", train_ip, True, False),  # nhóm train, giai đoạn late -> loại
            ("2020-10-10", "5.5.5.5", False, False),  # bình thường -> chỉ theo thời gian
        ]
    )
    assert list(df["partition"]) == ["train", "excluded", "test", "excluded", "late", "excluded", "test"]


def test_ato_rows_never_enter_any_regular_partition():
    df = _frame([("2020-03-01", "7.7.7.7", False, True), ("2020-10-10", "7.7.7.8", True, True)])
    assert list(df["partition"]) == ["ato", "ato"]


def test_no_attack_ip_is_shared_between_training_and_evaluation_partitions():
    rows = []
    for i in range(3000):
        ip = f"198.51.{i // 250}.{i % 250}"
        for day in ("2020-03-15", "2020-08-15", "2020-10-15", "2021-02-10"):  # mỗi IP tấn công ở cả 4 giai đoạn
            rows.append((day, ip, True, False))
    df = _frame(rows)
    kept = df[df["partition"].isin(splits.PARTITIONS)]
    ips = {p: set(kept.loc[kept["partition"] == p, "ip"]) for p in splits.PARTITIONS}

    for a, b in (("train", "val"), ("train", "test"), ("val", "test"), ("train", "late"), ("val", "late")):
        assert ips[a].isdisjoint(ips[b]), f"IP tấn công trùng giữa {a} và {b}"
    assert all(len(s) > 0 for s in ips.values())
    assert ips["late"] == ips["test"]  # cùng nhóm IP, đều chỉ để đánh giá

    bounds = {p: (kept.loc[kept["partition"] == p, "ts"].min(), kept.loc[kept["partition"] == p, "ts"].max()) for p in splits.PARTITIONS}
    assert bounds["train"][1] < bounds["val"][0] <= bounds["val"][1] < bounds["test"][0] <= bounds["test"][1] < bounds["late"][0]


def test_row_weights_restore_natural_attack_share():
    train_ip = _ip_in_group("train", "9.9.9")
    test_ip = _ip_in_group("test", "9.9.8")
    df = _frame(
        [
            ("2020-03-01", train_ip, True, False),  # tấn công trong train: giữ 70% IP -> trọng số 1/0.7
            ("2020-10-10", test_ip, True, False),  # tấn công trong test: giữ 15% IP -> trọng số 1/0.15
            ("2020-03-01", test_ip, True, False),  # bị loại -> trọng số 1
            ("2020-10-10", "5.5.5.5", False, False),  # bình thường -> 1
        ]
    )
    weights = splits.row_weights(df)
    assert weights.iloc[0] == pytest.approx(1 / 0.70)
    assert weights.iloc[1] == pytest.approx(1 / 0.15)
    assert weights.iloc[2] == 1.0 and weights.iloc[3] == 1.0
