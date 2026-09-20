"""ETL bộ RBA (MR2): file zip ~8,4GB CSV -> Parquet cột nén, đọc theo chunk.

Chạy:
    cd backend
    venv\\Scripts\\python.exe -m ml.rba.etl              # toàn bộ (~vài phút)
    venv\\Scripts\\python.exe -m ml.rba.etl --max-rows 200000   # thử nhanh

Chỉ giữ các cột dùng được làm đặc trưng hoặc nhãn (xem docs/rba-data-card.md
mục 4): bỏ Region, City, Round-Trip Time vì README nói chúng không phản ánh
quan hệ thật. Kèm thống kê toàn vẹn (đối chiếu cột `index`, thứ tự thời gian)
ghi ra etl_stats.json — để biết chắc không mất dòng khi đọc.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from ml.rba.paths import RBA_CSV_NAME, RBA_DATA_DIR, find_rba_zip

FULL_PARQUET = RBA_DATA_DIR / "rba_full.parquet"
ETL_STATS_JSON = RBA_DATA_DIR / "etl_stats.json"
CHUNK_ROWS = 1_000_000
FAKE_ASN_MIN = 500_000  # README: ASN >= 500000 là giá trị nhân tạo

CSV_TO_INTERNAL = {
    "index": "row_id",
    "Login Timestamp": "ts",
    "User ID": "user_id",
    "IP Address": "ip",
    "Country": "country",
    "ASN": "asn",
    "User Agent String": "ua",
    "Browser Name and Version": "browser",
    "OS Name and Version": "os",
    "Device Type": "device_type",
    "Login Successful": "success",
    "Is Attack IP": "is_attack_ip",
    "Is Account Takeover": "is_ato",
}
_BOOL_COLUMNS = ("success", "is_attack_ip", "is_ato")
_TEXT_COLUMNS = ("ip", "country", "ua", "browser", "os", "device_type")


def transform_chunk(raw: pd.DataFrame) -> pd.DataFrame:
    """Đổi tên cột, ép kiểu, tạo cờ artifact. Hàm thuần, không đụng đĩa."""
    df = raw.rename(columns=CSV_TO_INTERNAL)[list(CSV_TO_INTERNAL.values())].copy()

    df["row_id"] = df["row_id"].astype("int64")
    df["user_id"] = df["user_id"].astype("int64")
    df["ts"] = pd.to_datetime(df["ts"], format="ISO8601").astype("datetime64[us]")
    df["asn"] = pd.to_numeric(df["asn"], errors="coerce").astype("Int32")

    for column in _BOOL_COLUMNS:
        values = df[column]
        unexpected = ~values.isin(["True", "False"])
        if unexpected.any():
            raise ValueError(f"cột {column} có giá trị lạ: {values[unexpected].unique()[:5]}")
        df[column] = values.eq("True")

    for column in _TEXT_COLUMNS:
        df[column] = df[column].where(df[column] != "", None)

    df["is_private_ip"] = df["ip"].str.startswith("10.", na=False)
    df["is_fake_asn"] = (df["asn"] >= FAKE_ASN_MIN).fillna(False).astype(bool)
    df["ua_parse_failed"] = df["device_type"].isna()
    return df


@dataclass
class EtlStats:
    rows: int = 0
    row_id_min: int | None = None
    row_id_max: int | None = None
    row_id_gaps: int = 0
    row_id_first_gaps: list[list[int]] = field(default_factory=list)
    ts_min: str | None = None
    ts_max: str | None = None
    ts_backward_steps: int = 0
    ts_max_backward_seconds: float = 0.0
    success: int = 0
    attack_ip: int = 0
    ato: int = 0
    private_ip: int = 0
    fake_asn: int = 0
    ua_parse_failed: int = 0
    null_country: int = 0
    null_asn: int = 0
    _last_row_id: int | None = None
    _last_ts: np.datetime64 | None = None

    def _record_gap(self, before: int, after: int) -> None:
        self.row_id_gaps += 1
        if len(self.row_id_first_gaps) < 10:
            self.row_id_first_gaps.append([before, after])

    def update(self, df: pd.DataFrame) -> None:
        ids = df["row_id"].to_numpy()
        if self._last_row_id is not None and ids[0] != self._last_row_id + 1:
            self._record_gap(self._last_row_id, int(ids[0]))
        for i in np.flatnonzero(np.diff(ids) != 1):
            self._record_gap(int(ids[i]), int(ids[i + 1]))
        self.row_id_min = int(ids.min()) if self.row_id_min is None else min(self.row_id_min, int(ids.min()))
        self.row_id_max = int(ids.max()) if self.row_id_max is None else max(self.row_id_max, int(ids.max()))
        self._last_row_id = int(ids[-1])

        values = df["ts"].to_numpy()
        self.ts_min = str(values.min()) if self.ts_min is None else min(self.ts_min, str(values.min()))
        self.ts_max = str(values.max()) if self.ts_max is None else max(self.ts_max, str(values.max()))
        chain = values if self._last_ts is None else np.concatenate([[self._last_ts], values])
        deltas_seconds = np.diff(chain).astype("timedelta64[us]").astype("int64") / 1e6
        backward = deltas_seconds[deltas_seconds < 0]
        self.ts_backward_steps += int(len(backward))
        if len(backward):
            self.ts_max_backward_seconds = max(self.ts_max_backward_seconds, float(-backward.min()))
        self._last_ts = values[-1]

        self.rows += len(df)
        self.success += int(df["success"].sum())
        self.attack_ip += int(df["is_attack_ip"].sum())
        self.ato += int(df["is_ato"].sum())
        self.private_ip += int(df["is_private_ip"].sum())
        self.fake_asn += int(df["is_fake_asn"].sum())
        self.ua_parse_failed += int(df["ua_parse_failed"].sum())
        self.null_country += int(df["country"].isna().sum())
        self.null_asn += int(df["asn"].isna().sum())

    def to_dict(self) -> dict:
        data = {k: v for k, v in self.__dict__.items() if not k.startswith("_")}
        data["row_id_contiguous"] = (
            self.row_id_gaps == 0 and self.row_id_min == 0 and self.row_id_max == self.rows - 1
        )
        return data


def convert_zip_to_parquet(
    zip_path: Path,
    out_path: Path = FULL_PARQUET,
    chunk_rows: int = CHUNK_ROWS,
    max_rows: int | None = None,
) -> EtlStats:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_suffix(".parquet.tmp")
    stats = EtlStats()
    writer: pq.ParquetWriter | None = None
    schema: pa.Schema | None = None
    started = time.time()

    try:
        with zipfile.ZipFile(zip_path) as zf, zf.open(RBA_CSV_NAME) as handle:
            reader = pd.read_csv(
                handle,
                usecols=list(CSV_TO_INTERNAL),
                dtype=str,
                keep_default_na=False,  # "NA" là mã quốc gia Namibia, không phải giá trị thiếu
                chunksize=chunk_rows,
            )
            for raw in reader:
                if max_rows is not None and stats.rows >= max_rows:
                    break
                if max_rows is not None:
                    raw = raw.iloc[: max_rows - stats.rows]
                df = transform_chunk(raw)
                stats.update(df)

                if writer is None:
                    table = pa.Table.from_pandas(df, preserve_index=False)
                    schema = table.schema
                    writer = pq.ParquetWriter(tmp_path, schema, compression="zstd")
                else:
                    table = pa.Table.from_pandas(df, schema=schema, preserve_index=False)
                writer.write_table(table)
                print(f"  ... {stats.rows:>11,} dòng, {time.time() - started:5.0f}s", flush=True)
    finally:
        if writer is not None:
            writer.close()

    if writer is None:
        raise ValueError("file CSV trống")
    tmp_path.replace(out_path)
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description="ETL bộ RBA: zip -> Parquet")
    parser.add_argument("--max-rows", type=int, default=None, help="chỉ đọc N dòng đầu (để thử nhanh)")
    parser.add_argument("--out", type=Path, default=FULL_PARQUET)
    args = parser.parse_args()

    zip_path = find_rba_zip()
    if zip_path is None:
        print("Không thấy rba-dataset.zip — chạy `python -m ml.check_env` để biết cách khai báo.")
        return 1

    print(f"Đọc {zip_path} -> {args.out}")
    stats = convert_zip_to_parquet(zip_path, args.out, max_rows=args.max_rows)
    summary = stats.to_dict()
    ETL_STATS_JSON.parent.mkdir(parents=True, exist_ok=True)
    ETL_STATS_JSON.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"\nParquet: {args.out.stat().st_size / 1024**3:.2f} GiB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
