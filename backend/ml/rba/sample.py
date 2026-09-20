"""Lấy mẫu theo user + gán phân vùng train/val/test cho bộ RBA (MR2).

Chạy (sau `python -m ml.rba.etl`):
    cd backend
    venv\\Scripts\\python.exe -m ml.rba.sample

Nguyên tắc:
- Lấy mẫu THEO USER và giữ NGUYÊN toàn bộ lịch sử của user được chọn — đặc trưng
  theo user (mới lạ, tần suất) cần lịch sử đầy đủ; cắt bớt sự kiện sẽ làm sai.
- Đủ 100% user có ATO (138 user) — đây là mẫu hiếm nhất, không được bỏ sót.
- Phân tầng theo mức hoạt động vì ~40% user chỉ có 1 lần đăng nhập; lấy ngẫu
  nhiên đều sẽ áp đảo bởi nhóm ít thông tin nhất.
- Hai "user" khổng lồ bị loại khỏi mẫu (không phải người dùng thật): một là "thùng
  chứa" các lần thử vào tài khoản không tồn tại (14 triệu sự kiện, 0% thành công,
  2 triệu IP), một là client tự động thử lại liên tục (70 nghìn sự kiện, 0% thành
  công, 4 IP). Chúng vẫn nằm trong file Parquet đầy đủ để tính đặc trưng cấp
  IP/ASN (MR3).
- `ua` được thay bằng `ua_hash`: chỉ cần biết "cùng/khác chuỗi UA", không cần
  giữ ~150 ký tự × hàng triệu dòng trong bộ nhớ.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import duckdb
import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from ml.rba import splits
from ml.rba.etl import FULL_PARQUET
from ml.rba.paths import RBA_DATA_DIR

SAMPLE_PARQUET = RBA_DATA_DIR / "rba_sample.parquet"
SAMPLE_REPORT_JSON = RBA_DATA_DIR / "sample_report.json"

RANDOM_SEED = 20260920
MEGA_USER_MIN_EVENTS = 50_000
STRATUM_RATES = {"single": 0.05, "light": 0.10, "heavy": 0.25}


def stratum_of(n_events: int) -> str:
    if n_events == 1:
        return "single"
    if n_events <= 9:
        return "light"
    return "heavy"


def pick_users(
    user_stats: pd.DataFrame,
    rates: dict[str, float] = STRATUM_RATES,
    seed: int = RANDOM_SEED,
    mega_min: int = MEGA_USER_MIN_EVENTS,
) -> pd.DataFrame:
    """user_stats cần cột user_id, n_events, n_ato. Trả các user được chọn kèm stratum/sample_rate/forced."""
    stats = user_stats.sort_values("user_id").reset_index(drop=True)
    stats = stats[stats["n_events"] < mega_min].copy()
    stats["stratum"] = stats["n_events"].map(stratum_of)
    stats["forced"] = stats["n_ato"] > 0
    stats["sample_rate"] = np.where(stats["forced"], 1.0, stats["stratum"].map(rates).astype(float))

    draws = np.random.default_rng(seed).random(len(stats))
    keep = stats["forced"].to_numpy() | (draws < stats["sample_rate"].to_numpy())
    return stats.loc[keep, ["user_id", "stratum", "sample_rate", "forced"]].reset_index(drop=True)


def build_sample(
    full_path: Path = FULL_PARQUET,
    out_path: Path = SAMPLE_PARQUET,
    rates: dict[str, float] = STRATUM_RATES,
    mega_min: int = MEGA_USER_MIN_EVENTS,
) -> dict:
    con = duckdb.connect()
    con.execute(f"CREATE VIEW f AS SELECT * FROM read_parquet('{Path(full_path).as_posix()}')")

    user_stats = con.execute(
        "SELECT user_id, COUNT(*) AS n_events, SUM(is_ato::INT) AS n_ato FROM f GROUP BY user_id"
    ).df()
    mega = user_stats[user_stats["n_events"] >= mega_min]
    picked = pick_users(user_stats, rates=rates, mega_min=mega_min)

    attack_ips = con.execute("SELECT DISTINCT ip FROM f WHERE is_attack_ip AND ip IS NOT NULL").df()
    attack_ips["ip_group"] = attack_ips["ip"].map(splits.ip_group_of)

    con.register("picked", picked)
    con.register("ip_groups", attack_ips)
    df = con.execute(
        """
        SELECT f.row_id, f.ts, f.user_id, f.ip, f.country, f.asn, hash(f.ua) AS ua_hash,
               f.browser, f.os, f.device_type, f.success, f.is_attack_ip, f.is_ato,
               f.is_private_ip, f.is_fake_asn, f.ua_parse_failed,
               p.stratum, p.sample_rate, p.forced, g.ip_group
        FROM f
        JOIN picked p USING (user_id)
        LEFT JOIN ip_groups g ON f.ip = g.ip
        ORDER BY f.ts, f.row_id
        """
    ).df()

    df["split_time"] = splits.assign_time_split(df["ts"])
    df["partition"] = splits.build_partition(df)
    df["weight"] = splits.row_weights(df)

    expected_events = int(user_stats[user_stats["user_id"].isin(picked["user_id"])]["n_events"].sum())
    report = verify_and_summarize(df, expected_events=expected_events, picked=picked, mega=mega)
    report["stratum_rates"] = rates
    report["mega_user_min_events"] = mega_min

    out_path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pandas(df, preserve_index=False), out_path, compression="zstd")
    return report


def verify_and_summarize(df: pd.DataFrame, expected_events: int, picked: pd.DataFrame, mega: pd.DataFrame) -> dict:
    """Kiểm tra các bất biến rồi tóm tắt. Vi phạm bất kỳ bất biến nào -> AssertionError."""
    assert len(df) == expected_events, "mẫu thiếu/thừa sự kiện so với lịch sử đầy đủ của các user được chọn"
    assert df["user_id"].nunique() == len(picked), "có user được chọn nhưng không có dòng nào"
    assert df["user_id"].isin(mega["user_id"]).sum() == 0, "user khổng lồ lọt vào mẫu"

    kept = df[df["partition"].isin(splits.PARTITIONS)]
    attack_ips = {p: set(kept.loc[(kept["partition"] == p) & kept["is_attack_ip"], "ip"]) for p in splits.PARTITIONS}
    # "late" dùng chung nhóm IP với "test" nên chỉ so với train/val (cả hai chỉ để đánh giá)
    for a, b in (("train", "val"), ("train", "test"), ("val", "test"), ("train", "late"), ("val", "late")):
        overlap = attack_ips[a] & attack_ips[b]
        assert not overlap, f"IP tấn công trùng giữa {a} và {b}: {len(overlap)} IP"

    bounds = {p: (kept.loc[kept["partition"] == p, "ts"].min(), kept.loc[kept["partition"] == p, "ts"].max()) for p in splits.PARTITIONS}
    assert (
        bounds["train"][1] < bounds["val"][0] <= bounds["val"][1] < bounds["test"][0] <= bounds["test"][1] < bounds["late"][0]
    ), "thứ tự thời gian train/val/test/late sai"
    assert not df.loc[df["is_ato"], "partition"].ne(splits.ATO).any(), "dòng ATO lọt vào tập huấn luyện/đánh giá thường"

    by_partition = {}
    for name in [*splits.PARTITIONS, splits.EXCLUDED, splits.ATO]:
        part = df[df["partition"] == name]
        by_partition[name] = {
            "rows": int(len(part)),
            "users": int(part["user_id"].nunique()),
            "attack_rows": int(part["is_attack_ip"].sum()),
            "distinct_attack_ips": int(part.loc[part["is_attack_ip"], "ip"].nunique()),
            "ato_rows": int(part["is_ato"].sum()),
            "weighted_attack_share": round(float((part["weight"] * part["is_attack_ip"]).sum() / part["weight"].sum()), 4)
            if len(part)
            else None,
            "success_rate": round(float(part["success"].mean()), 4) if len(part) else None,
        }

    ato = df[df["is_ato"]]
    return {
        "seed": RANDOM_SEED,
        "stratum_rates": STRATUM_RATES,
        "mega_user_min_events": MEGA_USER_MIN_EVENTS,
        "mega_users_excluded": [
            {"user_id": int(r.user_id), "n_events": int(r.n_events)} for r in mega.itertuples()
        ],
        "sample_rows": int(len(df)),
        "sample_users": int(len(picked)),
        "users_by_stratum": {k: int(v) for k, v in picked["stratum"].value_counts().items()},
        "rows_by_stratum": {k: int(v) for k, v in df["stratum"].value_counts().items()},
        "cutoffs": {
            "train_end": str(splits.TRAIN_END),
            "val_end": str(splits.VAL_END),
            "test_end": str(splits.TEST_END),
        },
        "by_partition": by_partition,
        "ato": {
            "rows": int(len(ato)),
            "users": int(ato["user_id"].nunique()),
            "by_split_time": {k: int(v) for k, v in ato["split_time"].value_counts().items()},
        },
        "invariants_checked": [
            "sample == toàn bộ lịch sử của các user được chọn",
            "không IP tấn công nào trùng giữa train/val/test (late chỉ so với train/val)",
            "thứ tự thời gian train < val < test < late",
            "ATO không vào train/val/test",
            "user khổng lồ bị loại",
        ],
    }


def main() -> int:
    if not FULL_PARQUET.is_file():
        print(f"Chưa có {FULL_PARQUET} — chạy `python -m ml.rba.etl` trước.")
        return 1
    report = build_sample()
    SAMPLE_REPORT_JSON.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\nĐã ghi {SAMPLE_PARQUET} ({SAMPLE_PARQUET.stat().st_size / 1024**2:.0f} MiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
