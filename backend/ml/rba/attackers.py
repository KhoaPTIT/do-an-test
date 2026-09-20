"""Mô phỏng kẻ tấn công Naive / VPN / Targeted (MR4), theo giao thức của Wiefling et al. (2022).

Chỉ 141 ca ATO thật (38 ở tương lai) nên không đủ để đánh giá chắc chắn. Giao thức chuẩn của nghiên cứu RBA
là CHÈN đăng nhập của kẻ tấn công giả định vào lịch sử của user hợp lệ và đo mô hình bắt được bao nhiêu:

| Loại | Kẻ tấn công biết gì | Cách sinh thuộc tính |
|---|---|---|
| naive    | không biết gì về nạn nhân | IP/ASN/quốc gia/UA lấy nguyên từ một đăng nhập thật của người khác (cùng giờ) |
| vpn      | quốc gia của nạn nhân    | như trên nhưng đăng nhập thật được chọn phải cùng quốc gia hay gặp nhất của nạn nhân |
| targeted | quốc gia, nhà mạng (ASN) và thiết bị/trình duyệt của nạn nhân | ASN giữ như nạn nhân, UA/trình duyệt/OS/thiết bị = của nạn nhân, chỉ IP khác (lấy từ đăng nhập thật cùng ASN) |

Mọi đăng nhập giả đều THÀNH CÔNG (đã có mật khẩu), đặt vào một thời điểm ngẫu nhiên 2–72 giờ sau một đăng nhập
thật của nạn nhân trong giai đoạn `test`. Thuộc tính lấy từ đăng nhập thật CÙNG GIỜ nên các đặc trưng hạ tầng
(hoạt động của IP/ASN quanh thời điểm đó) cũng thực tế. Đặc trưng tính bằng ĐÚNG pipeline của MR3 (SQL DuckDB
đã được chứng minh bằng test là bằng đặc tả Python), chỉ lấy đầu ra cho các dòng chèn.

Giới hạn: nạn nhân dùng chung các đăng nhập thật làm "người cho", và vài đăng nhập giả có thể chung IP/ASN/giờ
nên ảnh hưởng nhẹ lên đặc trưng hạ tầng của nhau (6.000 dòng chèn trên 22 triệu sự kiện). Kẻ tấn công không
bao giờ mạnh hơn "targeted"; kẻ tấn công bắt chước hoàn hảo (cùng IP, cùng thiết bị, cùng giờ) nằm ngoài mô hình
này và là giới hạn đã biết của mọi hệ thống chấm điểm rủi ro theo thuộc tính đăng nhập.

Chạy:  cd backend && venv\\Scripts\\python.exe -m ml.rba.attackers   (~25 phút, nên chạy nền)
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass

import duckdb
import numpy as np
import pandas as pd

from ml.rba import splits
from ml.rba.build_features import MODEL_TABLE_PARQUET, events_sql_for_full
from ml.rba.eval_tasks import ATTACKERS_PARQUET
from ml.rba.etl import FULL_PARQUET
from ml.rba.features import FEATURE_NAMES
from ml.rba.features_sql import compute_features_sql
from ml.rba.paths import RBA_DATA_DIR

INJECT_ROW_ID_BASE = 4_000_000_000
HOUR_US = 3_600 * 1_000_000
ATTACKER_TYPES = ("naive", "vpn", "targeted")


@dataclass
class SimulationConfig:
    per_type: int = 2000
    seed: int = 20260921
    min_offset_hours: float = 2.0
    max_offset_hours: float = 72.0


def _to_us(ts: pd.Timestamp) -> int:
    return int(ts.value // 1000)


def select_victims(model_table: pd.DataFrame, cfg: SimulationConfig = SimulationConfig()) -> pd.DataFrame:
    """Mỗi nạn nhân là một user khác nhau; chia đều cho 3 loại kẻ tấn công. Cột: victim_id, attacker_type,
    uid, anchor_us (đăng nhập thật làm mốc), t_inj_us (thời điểm chèn)."""
    candidates = model_table[
        (model_table["partition"] == "test")
        & ~model_table["in_warmup"]
        & (model_table["cur_success"] == 1)
        & ~model_table["is_attack_ip"]
        & ~model_table["is_ato"]
    ]
    rng = np.random.default_rng(cfg.seed)
    users = candidates["user_id"].unique()
    n_total = min(len(users), cfg.per_type * len(ATTACKER_TYPES))
    chosen = rng.choice(users, n_total, replace=False)

    per_user = candidates[candidates["user_id"].isin(chosen)]
    anchors = per_user.groupby("user_id").sample(n=1, random_state=cfg.seed).set_index("user_id").loc[chosen]

    test_end_us = _to_us(splits.TEST_END)
    anchor_us = np.array([_to_us(ts) for ts in anchors["ts"]], dtype=np.int64)
    offset_us = (rng.uniform(cfg.min_offset_hours, cfg.max_offset_hours, n_total) * HOUR_US).astype(np.int64)
    t_inj = np.minimum(anchor_us + offset_us, test_end_us - 1_000_000)
    t_inj = np.maximum(t_inj, anchor_us + 1_000_000)

    return pd.DataFrame(
        {
            "victim_id": np.arange(n_total),
            "attacker_type": [ATTACKER_TYPES[i % len(ATTACKER_TYPES)] for i in range(n_total)],
            "uid": chosen.astype(np.int64),
            "anchor_us": anchor_us,
            "t_inj_us": t_inj,
        }
    )


def simulate_attackers(
    con: duckdb.DuckDBPyConnection, victims: pd.DataFrame, events_relation: str, seed: int = 20260921
) -> pd.DataFrame:
    """`events_relation`: tên view/bảng có cột row_id, t, uid, ip, asn, country, ua, browser, os, device_type, success.
    Trả các dòng chèn (cùng cột + victim_id, attacker_type); nạn nhân không có "người cho" phù hợp bị bỏ."""
    con.register("victims_df", victims)
    con.execute("CREATE OR REPLACE TEMP TABLE victims AS SELECT * FROM victims_df")

    con.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE victim_prior AS
        SELECT v.victim_id, e.ip, e.asn, e.country, e.ua, e.browser, e.os, e.device_type
        FROM victims v JOIN {events_relation} e ON e.uid = v.uid AND e.t < v.t_inj_us AND e.success
        """
    )
    # Giá trị hay gặp nhất, hoà thì lấy giá trị nhỏ nhất (theo thứ tự chuỗi/số): mode() của DuckDB không xác định
    # khi có hai giá trị đồng tần, mà nạn nhân chỉ có 2 lần đăng nhập ở 2 nơi khác nhau là chuyện thường.
    attrs = (("country", "m_country"), ("asn", "m_asn"), ("ua", "m_ua"), ("browser", "m_browser"), ("os", "m_os"), ("device_type", "m_device"))
    for column, alias in attrs:
        con.execute(
            f"""
            CREATE OR REPLACE TEMP TABLE modal_{alias} AS
            SELECT victim_id, arg_min({column}, (-c, {column})) AS {alias}
            FROM (SELECT victim_id, {column}, COUNT(*) AS c FROM victim_prior GROUP BY victim_id, {column})
            GROUP BY victim_id
            """
        )
    joins = " ".join(f"JOIN modal_{alias} USING (victim_id)" for _, alias in attrs)
    con.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE victim_profile AS
        SELECT victim_id, {", ".join(alias for _, alias in attrs)}
        FROM (SELECT DISTINCT victim_id FROM victim_prior) {joins}
        """
    )
    con.execute("CREATE OR REPLACE TEMP TABLE victim_ips AS SELECT DISTINCT victim_id, ip FROM victim_prior")
    con.execute(
        """
        CREATE OR REPLACE TEMP TABLE v AS
        SELECT vic.*, p.m_country, p.m_asn, p.m_ua, p.m_browser, p.m_os, p.m_device
        FROM victims vic JOIN victim_profile p USING (victim_id)
        """
    )

    t_lo, t_hi = con.execute("SELECT MIN(t_inj_us) - 24 * 3600000000, MAX(t_inj_us) FROM v").fetchone()
    con.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE donors AS
        SELECT row_id, t, uid, ip, asn, country, ua, browser, os, device_type
        FROM {events_relation}
        WHERE success AND uid IS NOT NULL AND t >= {t_lo} AND t < {t_hi}
        """
    )

    rules = {
        "naive": "d.uid <> v.uid",
        "vpn": "d.uid <> v.uid AND d.country = v.m_country",
        "targeted": "d.uid <> v.uid AND d.asn = v.m_asn AND NOT EXISTS "
        "(SELECT 1 FROM victim_ips vi WHERE vi.victim_id = v.victim_id AND vi.ip = d.ip)",
    }
    picks = []
    for kind, condition in rules.items():
        done: set[int] = set()
        for window_hours in (1, 24):  # không có người cho trong 1 giờ thì nới ra 24 giờ
            missing = "" if not done else f"AND v.victim_id NOT IN ({','.join(map(str, done))})"
            frame = con.execute(
                f"""
                SELECT * FROM (
                  SELECT v.victim_id, v.attacker_type, v.uid, v.t_inj_us, d.row_id AS donor_row, d.ip AS d_ip, d.asn AS d_asn,
                         d.country AS d_country, d.ua AS d_ua, d.browser AS d_browser, d.os AS d_os, d.device_type AS d_device,
                         v.m_ua, v.m_browser, v.m_os, v.m_device, v.m_asn, v.m_country,
                         ROW_NUMBER() OVER (PARTITION BY v.victim_id ORDER BY hash(v.victim_id, d.row_id, {seed})) AS rn
                  FROM v JOIN donors d ON d.t < v.t_inj_us AND d.t >= v.t_inj_us - {window_hours * HOUR_US}
                  WHERE v.attacker_type = '{kind}' AND {condition} {missing}
                ) WHERE rn = 1
                """
            ).df()
            if kind == "targeted":  # kẻ tấn công biết thiết bị/nhà mạng của nạn nhân: chỉ IP lấy từ người cho
                frame = frame.assign(
                    ua=frame["m_ua"], browser=frame["m_browser"], os=frame["m_os"], device_type=frame["m_device"],
                    asn=frame["m_asn"], country=frame["d_country"],
                )
            else:
                frame = frame.assign(
                    ua=frame["d_ua"], browser=frame["d_browser"], os=frame["d_os"], device_type=frame["d_device"],
                    asn=frame["d_asn"], country=frame["d_country"],
                )
            picks.append(frame.assign(ip=frame["d_ip"]))
            done |= set(frame["victim_id"].tolist())
            if done and len(done) >= int((victims["attacker_type"] == kind).sum()):
                break

    injected = pd.concat(picks, ignore_index=True)
    injected = injected.sort_values(["t_inj_us", "victim_id"]).reset_index(drop=True)
    return pd.DataFrame(
        {
            "row_id": INJECT_ROW_ID_BASE + np.arange(len(injected), dtype=np.int64),
            "t": injected["t_inj_us"].astype("int64"),
            "uid": pd.array(injected["uid"], dtype="Int64"),
            "ip": injected["ip"],
            "asn": pd.array(injected["asn"], dtype="Int64"),
            "country": injected["country"],
            "ua": injected["ua"],
            "browser": injected["browser"],
            "os": injected["os"],
            "device_type": injected["device_type"],
            "success": True,
            "victim_id": injected["victim_id"].astype("int64"),
            "attacker_type": injected["attacker_type"],
        }
    )


def compute_attacker_features(
    con: duckdb.DuckDBPyConnection,
    injected: pd.DataFrame,
    events_sql: str,
    end_us: int,
    infra_chunk_rows: int = 3_000_000,
    on_stage=None,
) -> pd.DataFrame:
    """Đặc trưng của các dòng chèn, tính trên (sự kiện thật trước end_us + các dòng chèn) bằng pipeline MR3."""
    columns = ["row_id", "t", "uid", "ip", "asn", "country", "ua", "browser", "os", "device_type", "success"]
    con.register("injected_df", injected[columns])
    con.execute("CREATE OR REPLACE TEMP TABLE injected AS SELECT * FROM injected_df")
    combined = f"""
        SELECT * FROM ({events_sql}) WHERE t < {end_us}
        UNION ALL
        SELECT {", ".join(columns)} FROM injected
    """
    compute_features_sql(con, combined, "SELECT row_id FROM injected", on_stage=on_stage, infra_chunk_rows=infra_chunk_rows)
    feats = con.execute("SELECT * FROM features").df()
    meta = injected[["row_id", "victim_id", "attacker_type", "uid", "t"]].rename(columns={"uid": "user_id"})
    out = meta.merge(feats, on="row_id")
    out["ts"] = pd.to_datetime(out["t"], unit="us")
    out["weight"] = 1.0
    out["partition"] = "attacker"
    out["is_attack_ip"] = False
    out["is_ato"] = False
    out["in_warmup"] = False
    out["user_id"] = out["user_id"].astype("int64")
    float_cols = {name: out[name].astype("float32") for name in FEATURE_NAMES}
    return out.assign(**float_cols).drop(columns=["t"])


def main() -> int:
    for path in (FULL_PARQUET, MODEL_TABLE_PARQUET):
        if not path.is_file():
            print(f"Thiếu {path} — chạy các bước MR2/MR3 trước.")
            return 1
    started = time.time()

    def say(message: str) -> None:
        print(f"  [{time.time() - started:6.0f}s] {message}", flush=True)

    model_table = pd.read_parquet(MODEL_TABLE_PARQUET, columns=["row_id", "ts", "user_id", "partition", "in_warmup", "cur_success", "is_attack_ip", "is_ato"])
    victims = select_victims(model_table)
    say(f"chọn {len(victims)} nạn nhân ({victims['attacker_type'].value_counts().to_dict()})")

    tmp_dir = RBA_DATA_DIR / "duckdb_tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect()
    con.execute("PRAGMA memory_limit='4GB'")
    con.execute(f"PRAGMA temp_directory='{tmp_dir.as_posix()}'")
    events_sql = events_sql_for_full(FULL_PARQUET)
    con.execute(f"CREATE VIEW full_events AS {events_sql}")

    injected = simulate_attackers(con, victims, "full_events")
    say(f"sinh {len(injected)} đăng nhập giả: {injected['attacker_type'].value_counts().to_dict()}")

    features = compute_attacker_features(con, injected, events_sql, _to_us(splits.TEST_END), on_stage=say)
    features.to_parquet(ATTACKERS_PARQUET, index=False)
    say(f"đã ghi {ATTACKERS_PARQUET} ({len(features)} dòng)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
