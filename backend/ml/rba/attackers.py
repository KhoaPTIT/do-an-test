"""Mô phỏng kẻ tấn công Naive / VPN / Targeted (MR4), theo giao thức của Wiefling et al. (2022).

Chỉ 141 ca ATO thật (38 ở tương lai) nên không đủ để đánh giá chắc chắn. Giao thức chuẩn của nghiên cứu RBA
là CHÈN đăng nhập của kẻ tấn công giả định vào lịch sử của user hợp lệ và đo mô hình bắt được bao nhiêu.

Mỗi đăng nhập giả THÀNH CÔNG (đã có mật khẩu) và THAY THẾ một đăng nhập thật của nạn nhân đúng thời điểm đó (gọi là
"đăng nhập gốc"; khi tính đặc trưng đăng nhập gốc bị bỏ khỏi luồng sự kiện, nên tổng số đếm được bảo toàn). IP lấy từ một "người cho": đăng nhập thật đầu tiên của NGƯỜI KHÁC thoả điều kiện, xảy ra SAU thời điểm chèn.

| Loại | Kẻ tấn công biết gì | Người cho phải | Thuộc tính đăng nhập giả |
|---|---|---|---|
| naive    | không biết gì | user khác | IP, ASN, quốc gia, UA, trình duyệt, OS, thiết bị của người cho |
| vpn      | quốc gia của nạn nhân | user khác, cùng quốc gia với đăng nhập gốc | như naive |
| targeted | toàn bộ hồ sơ phiên của nạn nhân, trừ IP | user khác, cùng ASN với đăng nhập gốc | quốc gia, ASN, UA, trình duyệt, OS, thiết bị ĐÚNG BẰNG đăng nhập gốc; chỉ IP là của người cho |

"Targeted" là kẻ tấn công mạnh nhất có thể theo thuộc tính đăng nhập (cận trên sức mạnh, tức cận dưới của khả năng phát
hiện): mọi đặc trưng liên quan đến hồ sơ của nạn nhân (mới lạ, Freeman, độ hiếm) giống hệt đăng nhập gốc, chỉ còn IP khác.

Vì sao thiết kế như vậy: mô hình học từ kẻ tấn công mô phỏng dễ học CÁCH MÔ PHỎNG thay vì cách tấn công. Sáu phiên bản
đầu của tôi đều để lại dấu vân tay (bảy lỗi, liệt kê dưới đây); mỗi lỗi bị phát hiện nhờ một kết quả tốt quá mức (recall 100% kể cả với Targeted)
rồi `python -m ml.rba.audit` chỉ ra nhóm đặc trưng nào tách được đăng nhập giả khỏi đăng nhập thật:
  1. Chèn 2–72 giờ SAU một đăng nhập thật của nạn nhân: khoảng cách giữa các lần đăng nhập ngắn hơn người thật (nhịp).
     -> nay đăng nhập giả thay thế đúng một đăng nhập thật của nạn nhân (mốc chọn ngẫu nhiên THEO DÒNG, để độ dày
     lịch sử của nạn nhân khớp với đăng nhập hợp lệ dùng làm âm tính).
  2. Mượn IP của đăng nhập người khác NGAY TRƯỚC mốc chèn: đăng nhập của người cho nằm trong cửa sổ "IP hoạt động 1 giờ
     qua" của đăng nhập giả, nên 100% đăng nhập giả có "IP vừa được người khác dùng" (đăng nhập hợp lệ: 43%).
     -> nay người cho lấy SAU mốc; đặc trưng chỉ nhìn sự kiện TRƯỚC thời điểm nên đăng nhập của người cho không nằm trong
     ngữ cảnh của đăng nhập giả.
  3. IP hoàn toàn mới (chưa ai từng dùng): độ hiếm IP cực đại, không có lịch sử hạ tầng; riêng nhóm đặc trưng IP đã tách
     được ~96% (đăng nhập hợp lệ gần như luôn dùng IP đã có hoạt động).
     -> nay IP là IP THẬT của người cho; ngữ cảnh hạ tầng (IP/ASN) của đăng nhập giả là ngữ cảnh của một đăng nhập thật
     bất kỳ. Đặc trưng của đăng nhập giả tính bằng ĐÚNG pipeline MR3, chỉ lấy đầu ra cho các dòng chèn.
  4. Hồ sơ Targeted = giá trị HAY GẶP NHẤT của nạn nhân: quen thuộc tối đa (p_user lớn nhất) — nhóm Freeman/độ hiếm tách
     được 33–39% ở FPR 1%.
  5. Hồ sơ Targeted = lần đăng nhập thành công GẦN NHẤT: trong RBA tổng hợp 52% đăng nhập hợp lệ có UA MỚI (41% trình
     duyệt mới, 22% OS mới) nên lần gần nhất thường là một UA mới xuất hiện một lần: "quen mong manh" (llr_ua trung vị
     −5,1 so với +0,7 của đăng nhập hợp lệ) và vẫn tách 32%. Bất kỳ hồ sơ "quen" nào tôi tự chọn đều lệch phân phối thật.
     -> nay Targeted biết TRỌN hồ sơ phiên: thuộc tính đúng bằng đăng nhập gốc, không có lựa chọn nào của tôi để lệch.
  6. Nạn nhân mỗi user một lần (và bộ val loại các user đã là nạn nhân ở bộ khác): user hoạt động nhiều bị đại diện thiếu
     ở phía dương tính nhưng vẫn có mặt ở phía âm tính; mô hình học giá trị thuộc tính của họ = "hợp lệ" (nhóm độ hiếm tách
     được 95% ở val, kể cả Targeted mimic hoàn hảo). -> nay chọn đăng nhập gốc ĐỀU THEO DÒNG, cho phép cùng user nhiều lần
     (sửa đúng nhưng chưa đủ: val vẫn 0,91–0,94).
  7. CHÈN thay vì THAY THẾ trong luồng sự kiện khi tính đặc trưng: mỗi đăng nhập giả cộng thêm số đếm toàn cục/hạ tầng mà
     đăng nhập thật (đã tính sẵn ở MR3) không có; giá trị độ hiếm/LLR của đăng nhập giả lệch đều vài phần vạn và LightGBM
     (chia thùng theo phân vị, rất mịn ở vùng dày) học được độ lệch ấy. Mức tách tăng theo số đăng nhập giả đã tích luỹ:
     test ~6–9%, train ~15–18%, val 59–64% (val tích luỹ nhiều nhất). -> nay đăng nhập gốc bị BỎ khỏi luồng sự kiện.

Hệ quả cần nhớ: kẻ tấn công mô phỏng HOÀ LẪN với người thật về hạ tầng; chúng chỉ khác ở quan hệ với LỊCH SỬ của nạn nhân
(quốc gia/ASN/thiết bị/IP lạ hoặc quen). Tấn công có dấu hiệu hạ tầng rõ (IP tấn công dò mật khẩu hàng loạt) do nhãn
`Is Attack IP` và mô hình `gbm_attack_ip` phụ trách. Kẻ tấn công bắt chước hoàn hảo cả IP, thiết bị và giờ là giới hạn
đã biết của mọi hệ thống chấm điểm rủi ro theo thuộc tính đăng nhập. Hai đăng nhập giả có thể chung ASN/IP nên ảnh hưởng nhẹ
lên đặc trưng của nhau (vài nghìn dòng chèn trên 22 triệu sự kiện); đặc trưng của các dòng THẬT không bị đổi vì chúng đã
tính sẵn ở MR3 không có dòng chèn.

Chạy:
    cd backend
    venv\\Scripts\\python.exe -m ml.rba.attackers                    # bộ TEST (nạn nhân giai đoạn test), ~10 phút
    venv\\Scripts\\python.exe -m ml.rba.attackers --period trainval  # bộ HUẤN LUYỆN (train) và CHỌN MÔ HÌNH (val), ~10 phút
    venv\\Scripts\\python.exe -m ml.rba.audit                        # KIỂM ĐỊNH dấu vân tay sau mỗi lần sinh

Ba bộ (train, val, test) chọn nạn nhân từ ba giai đoạn khác nhau nên không chung đăng nhập gốc; chúng CÓ THỂ chung user
(user hoạt động nhiều xuất hiện ở cả ba, đúng như khi triển khai). Chỉ user có ATO thật bị loại, để phần đánh giá ngoài trên
ATO thật luôn sạch. Mô hình học từ kẻ tấn công mô phỏng được chấm trên kẻ tấn công mô phỏng KHÁC và trên ATO thật.
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
from ml.rba.eval_tasks import ATTACKERS_PARQUET, ATTACKERS_TRAINVAL_PARQUET
from ml.rba.etl import FULL_PARQUET
from ml.rba.features import FEATURE_NAMES
from ml.rba.features_sql import compute_features_sql
from ml.rba.paths import RBA_DATA_DIR

INJECT_ROW_ID_BASE = 4_000_000_000  # bộ test
INJECT_ROW_ID_BASE_TRAINVAL = 5_000_000_000
HOUR_US = 3_600 * 1_000_000
ATTACKER_TYPES = ("naive", "vpn", "targeted")
DONOR_WINDOWS_HOURS = (1, 24)  # người cho là đăng nhập thoả điều kiện ĐẦU TIÊN sau mốc; không có trong 1 giờ thì tìm tới 24 giờ
PERIOD_END = {"train": splits.TRAIN_END, "val": splits.VAL_END, "test": splits.TEST_END}
_INT64_MAX = int(np.iinfo(np.int64).max)


@dataclass
class SimulationConfig:
    per_type: int = 2000
    seed: int = 20260921


def _to_us(ts: pd.Timestamp) -> int:
    return int(ts.value // 1000)


def select_victims(
    model_table: pd.DataFrame,
    cfg: SimulationConfig = SimulationConfig(),
    partition: str = "test",
    exclude_users=(),
    id_offset: int = 0,
) -> pd.DataFrame:
    """Nạn nhân = một đăng nhập thật ("đăng nhập gốc") chọn NGẪU NHIÊN ĐỀU THEO DÒNG trong số đăng nhập hợp lệ, thành công, của
    tài khoản đã có lịch sử (`u_n_success >= 1`) ở `partition`; chia đều cho 3 loại kẻ tấn công. Một user có thể bị chọn nhiều
    lần, đúng theo tỉ lệ đăng nhập của họ (không user nào chiếm quá ~0,2% số dòng nên không ai áp đảo). Nhờ vậy phân phối của
    đăng nhập gốc — thuộc tính, độ dày lịch sử, thời điểm — KHỚP CHÍNH XÁC đăng nhập hợp lệ dùng làm âm tính khi đánh giá và
    huấn luyện. Chọn mỗi user một lần (kể cả theo dòng) hay loại user đã là nạn nhân ở bộ khác đều làm lệch phân phối này:
    user hoạt động nhiều bị đại diện thiếu ở phía dương tính nhưng vẫn có mặt ở phía âm tính, và mô hình học được giá trị
    thuộc tính đặc trưng của họ (audit: nhóm độ hiếm tách được 95% ở val). Cột: victim_id, attacker_type, uid, anchor_row_id,
    anchor_us, t_inj_us (= anchor_us: đăng nhập giả thay thế đăng nhập gốc đúng thời điểm), period_end_us (người cho phải xảy ra
    trước mốc này). `exclude_users`: user không được làm nạn nhân (dùng cho các user ATO thật, giữ sạch phần đánh giá ngoài)."""
    candidates = model_table[
        (model_table["partition"] == partition)
        & ~model_table["user_id"].isin(list(exclude_users))
        & ~model_table["in_warmup"]
        & (model_table["cur_success"] == 1)
        & ~model_table["is_attack_ip"]
        & ~model_table["is_ato"]
        & (model_table["u_n_success"] >= 1)
    ]
    rng = np.random.default_rng(cfg.seed)
    n_total = min(len(candidates), cfg.per_type * len(ATTACKER_TYPES))
    anchors = candidates.iloc[rng.choice(len(candidates), n_total, replace=False)]
    anchor_us = np.array([_to_us(ts) for ts in anchors["ts"]], dtype=np.int64)

    return pd.DataFrame(
        {
            "victim_id": id_offset + np.arange(n_total),
            "attacker_type": [ATTACKER_TYPES[i % len(ATTACKER_TYPES)] for i in range(n_total)],
            "uid": anchors["user_id"].to_numpy().astype(np.int64),
            "anchor_row_id": anchors["row_id"].to_numpy().astype(np.int64),
            "anchor_us": anchor_us,
            "t_inj_us": anchor_us,
            "period_end_us": np.full(n_total, _to_us(PERIOD_END[partition]), dtype=np.int64),
        }
    )


def _empty_injected() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "row_id": pd.Series(dtype="int64"), "t": pd.Series(dtype="int64"), "uid": pd.Series(dtype="Int64"),
            "ip": pd.Series(dtype="object"), "asn": pd.Series(dtype="Int64"), "country": pd.Series(dtype="object"),
            "ua": pd.Series(dtype="object"), "browser": pd.Series(dtype="object"), "os": pd.Series(dtype="object"),
            "device_type": pd.Series(dtype="object"), "success": pd.Series(dtype="bool"),
            "victim_id": pd.Series(dtype="int64"), "attacker_type": pd.Series(dtype="object"),
        }
    )


def simulate_attackers(
    con: duckdb.DuckDBPyConnection,
    victims: pd.DataFrame,
    events_relation: str,
    row_id_base: int = INJECT_ROW_ID_BASE,
    donor_rows: pd.DataFrame | None = None,
) -> pd.DataFrame:
    """`events_relation`: tên view/bảng có cột row_id, t, uid, ip, asn, country, ua, browser, os, device_type, success.
    `donor_rows`: DataFrame có cột row_id — các đăng nhập thật được phép làm "người cho" (mặc định mọi đăng nhập thành công
    có user). Trả các dòng chèn (cùng cột + victim_id, attacker_type); nạn nhân chưa từng đăng nhập thành công trước
    thời điểm chèn hoặc không có người cho phù hợp (trong 24 giờ sau mốc và trước `period_end_us`) bị bỏ."""
    if "period_end_us" not in victims:
        victims = victims.assign(period_end_us=_INT64_MAX)
    con.register("victims_df", victims)
    con.execute("CREATE OR REPLACE TEMP TABLE victims AS SELECT * FROM victims_df")

    if "anchor_row_id" not in victims:
        raise ValueError("victims cần cột anchor_row_id: đăng nhập thật bị thay thế, nguồn hồ sơ của kẻ tấn công Targeted/VPN")
    # Nạn nhân phải từng đăng nhập thành công TRƯỚC mốc: âm tính khi đánh giá đều là tài khoản đã có lịch sử.
    con.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE victim_history AS
        SELECT DISTINCT v.victim_id FROM victims v JOIN {events_relation} e ON e.uid = v.uid AND e.t < v.t_inj_us AND e.success
        """
    )
    # Hồ sơ = thuộc tính của CHÍNH đăng nhập thành công bị thay thế ("đăng nhập gốc"): kẻ tấn công Targeted biết trọn hồ sơ
    # phiên của nạn nhân. Không chọn "hồ sơ hay gặp nhất" hay "lần gần nhất": trong RBA 52% đăng nhập hợp lệ có UA mới nên
    # mọi hồ sơ "quen" tự chọn đều lệch khỏi phân phối đăng nhập hợp lệ và mô hình học được sự lệch đó (xem docstring).
    con.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE victim_profile AS
        SELECT v.victim_id, e.country AS a_country, e.asn AS a_asn, e.ua AS a_ua, e.browser AS a_browser, e.os AS a_os,
               e.device_type AS a_device
        FROM victims v JOIN {events_relation} e ON e.row_id = v.anchor_row_id AND e.uid = v.uid AND e.success
        WHERE v.victim_id IN (SELECT victim_id FROM victim_history)
        """
    )
    con.execute(
        """
        CREATE OR REPLACE TEMP TABLE v AS
        SELECT vic.*, p.a_country, p.a_asn, p.a_ua, p.a_browser, p.a_os, p.a_device
        FROM victims vic JOIN victim_profile p USING (victim_id)
        """
    )

    t_lo, t_hi = con.execute(
        f"SELECT MIN(t_inj_us), MAX(LEAST(t_inj_us + {DONOR_WINDOWS_HOURS[-1] * HOUR_US}, period_end_us)) FROM v"
    ).fetchone()
    if t_lo is None:
        return _empty_injected()
    pool = ""
    if donor_rows is not None:
        con.register("donor_rows_df", donor_rows[["row_id"]])
        con.execute("CREATE OR REPLACE TEMP TABLE donor_pool AS SELECT DISTINCT row_id FROM donor_rows_df")
        pool = "AND e.row_id IN (SELECT row_id FROM donor_pool)"
    con.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE donors AS
        SELECT e.row_id, e.t, e.uid, e.ip, e.asn, e.country, e.ua, e.browser, e.os, e.device_type
        FROM {events_relation} e
        WHERE e.success AND e.uid IS NOT NULL AND e.t > {t_lo} AND e.t <= {t_hi} {pool}
        """
    )

    conditions = {
        "naive": "d.uid <> v.uid",
        "vpn": "d.uid <> v.uid AND d.country = v.a_country",
        "targeted": "d.uid <> v.uid AND d.asn = v.a_asn",
    }
    picks = []
    for kind, condition in conditions.items():
        done: set[int] = set()
        for window_hours in DONOR_WINDOWS_HOURS:
            con.register("done_df", pd.DataFrame({"victim_id": np.array(sorted(done), dtype=np.int64)}))
            frame = con.execute(
                f"""
                SELECT victim_id, attacker_type, uid, t_inj_us, d_ip, d_asn, d_country, d_ua, d_browser, d_os, d_device,
                       a_country, a_ua, a_browser, a_os, a_device
                FROM (
                  SELECT v.victim_id, v.attacker_type, v.uid, v.t_inj_us, d.ip AS d_ip, d.asn AS d_asn, d.country AS d_country,
                         d.ua AS d_ua, d.browser AS d_browser, d.os AS d_os, d.device_type AS d_device,
                         v.a_country, v.a_ua, v.a_browser, v.a_os, v.a_device,
                         ROW_NUMBER() OVER (PARTITION BY v.victim_id ORDER BY d.t, d.row_id) AS rn
                  FROM v JOIN donors d ON d.t > v.t_inj_us AND d.t <= v.t_inj_us + {window_hours * HOUR_US} AND d.t < v.period_end_us
                  WHERE v.attacker_type = '{kind}' AND {condition} AND v.victim_id NOT IN (SELECT victim_id FROM done_df)
                ) WHERE rn = 1
                """
            ).df()
            picks.append(frame)
            done |= set(frame["victim_id"].tolist())
            if len(done) >= int((victims["attacker_type"] == kind).sum()):
                break

    picked = pd.concat(picks, ignore_index=True)
    if picked.empty:
        return _empty_injected()
    # targeted: thuộc tính đúng bằng đăng nhập gốc (kể cả quốc gia); chỉ IP (và ASN — đã bằng nhau theo điều kiện chọn người
    # cho) là của người cho. naive/vpn: mọi thuộc tính của người cho.
    is_targeted = picked["attacker_type"].eq("targeted")
    injected = picked.assign(
        country=picked["a_country"].where(is_targeted, picked["d_country"]),
        ua=picked["a_ua"].where(is_targeted, picked["d_ua"]),
        browser=picked["a_browser"].where(is_targeted, picked["d_browser"]),
        os=picked["a_os"].where(is_targeted, picked["d_os"]),
        device_type=picked["a_device"].where(is_targeted, picked["d_device"]),
    )
    injected = injected.sort_values(["t_inj_us", "victim_id"]).reset_index(drop=True)
    return pd.DataFrame(
        {
            "row_id": row_id_base + np.arange(len(injected), dtype=np.int64),
            "t": injected["t_inj_us"].astype("int64"),
            "uid": pd.array(injected["uid"], dtype="Int64"),
            "ip": injected["d_ip"],
            "asn": pd.array(injected["d_asn"], dtype="Int64"),
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
    extra_columns: tuple[str, ...] = (),
    replaced_row_ids=None,
) -> pd.DataFrame:
    """Đặc trưng của các dòng chèn, tính trên (sự kiện thật trước end_us + các dòng chèn) bằng pipeline MR3.

    `replaced_row_ids`: row_id của các đăng nhập gốc bị đăng nhập giả THAY THẾ. Chúng bị BỎ khỏi luồng sự kiện: đăng nhập giả
    không được cộng thêm vào số đếm toàn cục/hạ tầng mà đăng nhập thật (đã tính sẵn ở MR3 không có dòng chèn) không có. Nếu
    chỉ CHÈN (không bỏ), mọi giá trị thuộc tính nhận thêm số đếm từ các đăng nhập giả trước đó: độ hiếm/LLR của đăng nhập giả
    lệch đều một chút so với đăng nhập thật, LightGBM (chia thùng theo phân vị nên rất mịn ở vùng dày) học được độ lệch ấy —
    nhóm độ hiếm tách 59–64% ở val, nơi tích luỹ nhiều đăng nhập giả nhất; thay thế thì tổng số đếm được bảo toàn."""
    columns = ["row_id", "t", "uid", "ip", "asn", "country", "ua", "browser", "os", "device_type", "success"]
    con.register("injected_df", injected[columns])
    con.execute("CREATE OR REPLACE TEMP TABLE injected AS SELECT * FROM injected_df")
    skip = ""
    if replaced_row_ids is not None:
        con.register("replaced_df", pd.DataFrame({"row_id": np.asarray(replaced_row_ids, dtype=np.int64)}))
        con.execute("CREATE OR REPLACE TEMP TABLE replaced AS SELECT DISTINCT row_id FROM replaced_df")
        skip = "AND row_id NOT IN (SELECT row_id FROM replaced)"
    combined = f"""
        SELECT * FROM ({events_sql}) WHERE t < {end_us} {skip}
        UNION ALL
        SELECT {", ".join(columns)} FROM injected
    """
    compute_features_sql(con, combined, "SELECT row_id FROM injected", on_stage=on_stage, infra_chunk_rows=infra_chunk_rows)
    feats = con.execute("SELECT * FROM features").df()
    meta = injected[["row_id", "victim_id", "attacker_type", "uid", "t", *extra_columns]].rename(columns={"uid": "user_id"})
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


def _open_connection() -> duckdb.DuckDBPyConnection:
    tmp_dir = RBA_DATA_DIR / "duckdb_tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect()
    con.execute("PRAGMA memory_limit='4GB'")
    con.execute(f"PRAGMA temp_directory='{tmp_dir.as_posix()}'")
    return con


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Mô phỏng kẻ tấn công vào lịch sử user RBA")
    parser.add_argument("--period", choices=("test", "trainval"), default="test")
    args = parser.parse_args()

    for path in (FULL_PARQUET, MODEL_TABLE_PARQUET):
        if not path.is_file():
            print(f"Thiếu {path} — chạy các bước MR2/MR3 trước.")
            return 1
    started = time.time()

    def say(message: str) -> None:
        print(f"  [{time.time() - started:6.0f}s] {message}", flush=True)

    model_table = pd.read_parquet(
        MODEL_TABLE_PARQUET,
        columns=["row_id", "ts", "user_id", "partition", "in_warmup", "cur_success", "is_attack_ip", "is_ato", "u_n_success"],
    )
    # Người cho: đăng nhập thật hợp lệ, thành công, của tài khoản đã có lịch sử — cùng loại dòng với âm tính khi đánh giá,
    # để ngữ cảnh IP/ASN mượn về giống ngữ cảnh của đăng nhập hợp lệ (không mượn từ IP tấn công đã gắn nhãn).
    donor_rows = model_table.loc[
        (model_table["cur_success"] == 1) & ~model_table["is_attack_ip"] & ~model_table["is_ato"] & ~model_table["in_warmup"]
        & (model_table["u_n_success"] >= 1),
        ["row_id"],
    ]
    events_sql = events_sql_for_full(FULL_PARQUET)
    con = _open_connection()
    con.execute(f"CREATE VIEW full_events AS {events_sql}")

    ato_users = set(model_table.loc[model_table["is_ato"], "user_id"])  # user có ATO thật: không làm nạn nhân mô phỏng
    if args.period == "test":
        victims = select_victims(model_table, exclude_users=ato_users)
        out_path, row_base, end_us, extra = ATTACKERS_PARQUET, INJECT_ROW_ID_BASE, _to_us(splits.TEST_END), ()
    else:
        train = select_victims(
            model_table, SimulationConfig(per_type=4000, seed=20260922), "train", ato_users, id_offset=0
        ).assign(period="train")
        val = select_victims(
            model_table, SimulationConfig(per_type=1500, seed=20260923), "val", ato_users, id_offset=1_000_000
        ).assign(period="val")
        victims = pd.concat([train, val], ignore_index=True)
        out_path, row_base, end_us, extra = ATTACKERS_TRAINVAL_PARQUET, INJECT_ROW_ID_BASE_TRAINVAL, _to_us(splits.VAL_END), ("period",)
    say(f"chọn {len(victims)} nạn nhân ({victims['attacker_type'].value_counts().to_dict()})")

    injected = simulate_attackers(con, victims, "full_events", row_id_base=row_base, donor_rows=donor_rows)
    if "period" in victims:
        injected = injected.assign(period=injected["victim_id"].map(victims.set_index("victim_id")["period"]))
    say(f"sinh {len(injected)} đăng nhập giả: {injected['attacker_type'].value_counts().to_dict()}")

    replaced = victims.loc[victims["victim_id"].isin(injected["victim_id"]), "anchor_row_id"]  # chỉ nạn nhân THẬT SỰ có đăng nhập giả
    features = compute_attacker_features(con, injected, events_sql, end_us, on_stage=say, extra_columns=extra, replaced_row_ids=replaced)
    features.to_parquet(out_path, index=False)
    say(f"đã ghi {out_path} ({len(features)} dòng)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
