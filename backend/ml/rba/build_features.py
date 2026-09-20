"""Dựng bảng đặc trưng v2 cho mẫu RBA (MR3).

Chạy (sau `python -m ml.rba.etl` và `python -m ml.rba.sample`):
    cd backend
    venv\\Scripts\\python.exe -m ml.rba.build_features

Đọc toàn bộ Parquet đầy đủ (31 triệu dòng) để tính đặc trưng cấp IP/ASN và đếm toàn cục, nhưng chỉ
xuất đặc trưng cho các dòng của mẫu. Kết quả `rba_model_table.parquet`: metadata của mẫu
(partition, weight, nhãn...) + 50 đặc trưng (float32) + cờ `in_warmup`.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import duckdb

from ml.rba import splits
from ml.rba.etl import FULL_PARQUET
from ml.rba.features import FEATURE_GROUPS, FEATURE_NAMES, RBA_CATCHALL_USER_ID
from ml.rba.features_sql import compute_features_sql
from ml.rba.paths import RBA_DATA_DIR
from ml.rba.sample import SAMPLE_PARQUET

MODEL_TABLE_PARQUET = RBA_DATA_DIR / "rba_model_table.parquet"
FEATURE_REPORT_JSON = RBA_DATA_DIR / "feature_report.json"

_META_COLUMNS = ["row_id", "ts", "user_id", "stratum", "forced", "split_time", "partition", "weight", "is_attack_ip", "is_ato"]


def events_sql_for_full(full_path: Path) -> str:
    return f"""
        SELECT row_id, epoch_us(ts) AS t,
               CASE WHEN user_id = {RBA_CATCHALL_USER_ID} THEN NULL ELSE user_id END AS uid,
               ip, CAST(asn AS BIGINT) AS asn, country, CAST(hash(ua) AS VARCHAR) AS ua,
               browser, os, device_type, success
        FROM read_parquet('{full_path.as_posix()}')
    """


def build(
    full_path: Path = FULL_PARQUET,
    sample_path: Path = SAMPLE_PARQUET,
    out_path: Path = MODEL_TABLE_PARQUET,
    memory_limit: str = "4GB",
) -> dict:
    started = time.time()
    tmp_dir = RBA_DATA_DIR / "duckdb_tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    con = duckdb.connect()
    con.execute(f"PRAGMA memory_limit='{memory_limit}'")
    con.execute(f"PRAGMA temp_directory='{tmp_dir.as_posix()}'")

    def progress(message: str) -> None:
        print(f"  [{time.time() - started:6.0f}s] {message}", flush=True)

    compute_features_sql(
        con,
        events_sql_for_full(full_path),
        output_ids_sql=f"SELECT row_id FROM read_parquet('{sample_path.as_posix()}')",
        on_stage=progress,
    )

    progress("ghi rba_model_table.parquet")
    meta = ", ".join(f"s.{c}" for c in _META_COLUMNS)
    feature_cols = ", ".join(f"CAST(f.{name} AS FLOAT) AS {name}" for name in FEATURE_NAMES)
    con.execute(
        f"""
        COPY (
          SELECT {meta},
                 (s.ts < TIMESTAMP '{splits.WARMUP_END}') AS in_warmup,
                 {feature_cols}
          FROM read_parquet('{sample_path.as_posix()}') s
          JOIN features f USING (row_id)
          ORDER BY s.ts, s.row_id
        ) TO '{out_path.as_posix()}' (FORMAT PARQUET, COMPRESSION ZSTD)
        """
    )

    stats = con.execute(
        f"""
        SELECT COUNT(*) AS rows, SUM(in_warmup::INT) AS warmup_rows
        FROM read_parquet('{out_path.as_posix()}')
        """
    ).fetchone()
    nan_rates = {}
    for name in FEATURE_NAMES:
        nan_rates[name] = round(
            con.execute(f"SELECT AVG(({name} IS NULL OR isnan({name}))::INT) FROM read_parquet('{out_path.as_posix()}')").fetchone()[0], 4
        )

    return {
        "rows": int(stats[0]),
        "warmup_rows": int(stats[1]),
        "n_features": len(FEATURE_NAMES),
        "groups": {g: len(names) for g, names in FEATURE_GROUPS.items()},
        "nan_rate": nan_rates,
        "seconds": round(time.time() - started),
    }


def main() -> int:
    for path in (FULL_PARQUET, SAMPLE_PARQUET):
        if not path.is_file():
            print(f"Thiếu {path} — chạy `python -m ml.rba.etl` và `python -m ml.rba.sample` trước.")
            return 1
    report = build()
    FEATURE_REPORT_JSON.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "nan_rate"}, ensure_ascii=False, indent=2))
    print(f"\nĐã ghi {MODEL_TABLE_PARQUET} ({MODEL_TABLE_PARQUET.stat().st_size / 1024**2:.0f} MiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
