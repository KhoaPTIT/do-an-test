"""Chia train/val/test/late cho bộ RBA (MR2).

Hai trục độc lập, gộp thành cột `partition`:

1. Thời gian (`split_time`): train < TRAIN_END <= val < VAL_END <= test < TEST_END
   <= late. Mô hình chỉ học từ quá khứ và được đánh giá trên tương lai.
   - Cả 141 ca ATO đều nằm trong 02/2020–11/2020 (không có ca nào từ 12/2020), nên
     "test" phải phủ tới hết 11/2020 mới có ATO tương lai để đánh giá (38 ca).
   - Từ 11/2020 phân phối đổi mạnh (tỉ lệ đăng nhập thành công tụt từ ~0,44 xuống
     ~0,30, lưu lượng tấn công tăng) nên 12/2020–02/2021 tách riêng thành "late":
     tập kiểm tra khả năng chịu trôi phân phối (không có ATO).
2. Nhóm IP tấn công (`ip_group`): mỗi IP trong danh sách tấn công thuộc đúng một
   nhóm train/val/test (băm ổn định theo IP). Một dòng tấn công chỉ vào tập huấn
   luyện/đánh giá khi nhóm IP của nó khớp với giai đoạn thời gian — mô hình không
   thể "học thuộc" IP tấn công ở train rồi được chấm điểm trên chính IP đó ở
   test (blocklist ngầm). "late" dùng chung nhóm IP với "test" (cả hai chỉ để
   đánh giá, không huấn luyện).

Dòng ATO (chỉ 141 dòng) không bao giờ vào train/val/test/late: chúng có partition
riêng `ato`, chỉ dùng để đánh giá.
"""

from __future__ import annotations

import hashlib

import pandas as pd

TRAIN_END = pd.Timestamp("2020-08-01")
VAL_END = pd.Timestamp("2020-09-01")
TEST_END = pd.Timestamp("2020-12-01")

IP_GROUP_TRAIN_PERCENT = 70
IP_GROUP_VAL_PERCENT = 15  # phần còn lại (15%) là nhóm test

IP_GROUP_SHARE = {
    "train": IP_GROUP_TRAIN_PERCENT / 100,
    "val": IP_GROUP_VAL_PERCENT / 100,
    "test": 1 - (IP_GROUP_TRAIN_PERCENT + IP_GROUP_VAL_PERCENT) / 100,
}

PARTITIONS = ("train", "val", "test", "late")
EXCLUDED = "excluded"
ATO = "ato"

_IP_GROUP_OF_SPLIT = {"train": "train", "val": "val", "test": "test", "late": "test"}


def assign_time_split(
    ts: pd.Series,
    train_end: pd.Timestamp = TRAIN_END,
    val_end: pd.Timestamp = VAL_END,
    test_end: pd.Timestamp = TEST_END,
) -> pd.Series:
    if not train_end < val_end < test_end:
        raise ValueError("cần train_end < val_end < test_end")
    result = pd.Series("late", index=ts.index, dtype="object")
    result[ts < test_end] = "test"
    result[ts < val_end] = "val"
    result[ts < train_end] = "train"
    return result


def ip_group_of(ip: str) -> str:
    bucket = int(hashlib.md5(ip.encode("utf-8")).hexdigest()[:8], 16) % 100
    if bucket < IP_GROUP_TRAIN_PERCENT:
        return "train"
    if bucket < IP_GROUP_TRAIN_PERCENT + IP_GROUP_VAL_PERCENT:
        return "val"
    return "test"


def build_partition(df: pd.DataFrame) -> pd.Series:
    """Cần các cột: split_time, is_attack_ip, ip_group (chỉ có nghĩa với dòng tấn công), is_ato."""
    partition = df["split_time"].astype("object").copy()
    expected_group = df["split_time"].map(_IP_GROUP_OF_SPLIT)
    attack_group_mismatch = df["is_attack_ip"] & (df["ip_group"] != expected_group)
    partition[attack_group_mismatch] = EXCLUDED
    partition[df["is_ato"]] = ATO
    return partition


def row_weights(df: pd.DataFrame) -> pd.Series:
    """Dòng tấn công chỉ được giữ theo nhóm IP (một phần IP tấn công) nên tỉ lệ tấn công trong
    từng tập bị lệch so với tự nhiên. Trọng số 1/(tỉ lệ nhóm IP) cho dòng tấn công giúp các chỉ
    số có trọng số ước lượng lại tỉ lệ tự nhiên; mọi dòng khác có trọng số 1.
    Cần các cột: is_attack_ip, ip_group, partition."""
    share = df["ip_group"].map(IP_GROUP_SHARE)
    return (1.0 / share).where(df["is_attack_ip"] & df["partition"].isin(PARTITIONS), 1.0)
