"""MR2 — ETL RBA: ép kiểu đúng, cờ artifact, thống kê toàn vẹn (không cần file dữ liệu thật)."""

import zipfile

import pandas as pd
import pyarrow.parquet as pq

from ml.rba import etl

_HEADER = (
    "index,Login Timestamp,User ID,Round-Trip Time [ms],IP Address,Country,Region,City,ASN,"
    "User Agent String,Browser Name and Version,OS Name and Version,Device Type,"
    "Login Successful,Is Attack IP,Is Account Takeover"
)


def _row(index, ts, user, ip, country, asn, device, success="True", attack="False", ato="False"):
    return (
        f'{index},{ts},{user},,{ip},{country},-,-,{asn},"Mozilla/5.0 (X, Y) test",'
        f"Chrome 1.0,Windows 10,{device},{success},{attack},{ato}"
    )


def _make_zip(tmp_path, rows):
    zip_path = tmp_path / "rba-dataset.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(etl.RBA_CSV_NAME, "\n".join([_HEADER, *rows]) + "\n")
    return zip_path


def test_types_flags_and_namibia_country_code_survive(tmp_path):
    rows = [
        _row(0, "2020-02-03 12:43:30.772", -5, "10.0.0.1", "NO", 29695, "mobile"),
        _row(1, "2020-02-03 12:43:31.000", -5, "8.8.8.8", "NA", 600000, "", attack="True"),
        _row(2, "2020-02-03 12:43:32.500", 7, "1.1.1.1", "US", 13335, "bot", success="False", ato="True"),
    ]
    out = tmp_path / "out.parquet"
    stats = etl.convert_zip_to_parquet(_make_zip(tmp_path, rows), out, chunk_rows=2)

    df = pq.read_table(out).to_pandas()
    assert list(df["row_id"]) == [0, 1, 2]
    assert list(df["country"]) == ["NO", "NA", "US"]  # "NA" (Namibia) không bị coi là giá trị thiếu
    assert list(df["is_private_ip"]) == [True, False, False]
    assert list(df["is_fake_asn"]) == [False, True, False]
    assert list(df["ua_parse_failed"]) == [False, True, False]
    assert df["device_type"].isna().tolist() == [False, True, False]
    assert list(df["success"]) == [True, True, False]
    assert list(df["is_attack_ip"]) == [False, True, False]
    assert list(df["is_ato"]) == [False, False, True]
    assert pd.api.types.is_datetime64_any_dtype(df["ts"])

    assert stats.rows == 3 and stats.ato == 1 and stats.attack_ip == 1
    assert stats.private_ip == 1 and stats.fake_asn == 1 and stats.ua_parse_failed == 1
    assert stats.to_dict()["row_id_contiguous"] is True


def test_stats_detect_row_id_gap_across_chunks_and_time_going_backwards(tmp_path):
    rows = [
        _row(0, "2020-02-03 12:00:10.000", 1, "8.8.8.8", "US", 1, "mobile"),
        _row(1, "2020-02-03 12:00:20.000", 1, "8.8.8.8", "US", 1, "mobile"),
        _row(3, "2020-02-03 12:00:15.000", 1, "8.8.8.8", "US", 1, "mobile"),  # mất index 2, ts lùi 5 giây
        _row(4, "2020-02-03 12:00:40.000", 1, "8.8.8.8", "US", 1, "mobile"),
    ]
    stats = etl.convert_zip_to_parquet(_make_zip(tmp_path, rows), tmp_path / "o.parquet", chunk_rows=2)
    summary = stats.to_dict()

    assert summary["row_id_gaps"] == 1
    assert summary["row_id_first_gaps"] == [[1, 3]]  # khoảng trống rơi đúng ranh giới giữa 2 chunk
    assert summary["row_id_contiguous"] is False
    assert summary["ts_backward_steps"] == 1
    assert summary["ts_max_backward_seconds"] == 5.0


def test_unexpected_boolean_text_raises(tmp_path):
    rows = [_row(0, "2020-02-03 12:00:10.000", 1, "8.8.8.8", "US", 1, "mobile", success="Maybe")]
    try:
        etl.convert_zip_to_parquet(_make_zip(tmp_path, rows), tmp_path / "o.parquet")
    except ValueError as exc:
        assert "success" in str(exc)
    else:
        raise AssertionError("phải báo lỗi khi cột bool có giá trị lạ")
