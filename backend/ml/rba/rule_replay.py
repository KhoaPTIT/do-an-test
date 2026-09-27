"""Bộ chuyển đổi RBA cho replay rule engine v2 (MR9): đọc `rba_full.parquet` theo thứ tự thời gian và sinh `LoginAttempt`.

Chạy replay (báo cáo sinh ra là docs/rule-replay.md):

    cd backend
    venv\\Scripts\\python.exe -m app.detection.engine.replay rba --start 2020-02-03 --end 2020-08-01 --out ../docs/rule-replay.md --json ml/artifacts/rule_replay/train.json

Cách ánh xạ (mọi lựa chọn ở đây ảnh hưởng tới cách hiểu kết quả — xem `rba_notes` và `rba_caveats`, chúng được in vào báo cáo):
  - RBA chỉ có `user_id` (số băm), không có tên đăng nhập: `username = str(user_id)`, `user_key = str(user_id)`.
  - `user_id` "thùng chứa" -4324475583306591935 là MỌI lần thử vào tên không tồn tại (45% số dòng của RBA): `user_key = None`. Không biết tên thật nên `username` là một
    tên GIẢ, và cách đặt tên giả quyết định luật theo tên đăng nhập thấy gì (`unknown_names`): giữ chung MỘT tên cho tất cả thì luật theo tên coi hàng chục triệu lần thử từ
    mọi nơi là dò một tài khoản. Hai lựa chọn còn lại là hai CẬN của sự thật (thực tế nằm giữa): mỗi lần thử một tên riêng (`"attempt"`, mặc định, số tên khác nhau lớn nhất)
    và mỗi IP một tên chung (`"ip"`, số tên khác nhau nhỏ nhất).
  - Nhãn `is_attack_ip`, `is_ato` đi vào `LoginAttempt.labels`, nơi luật không đọc được.
  - Thời gian trong RBA không có múi giờ: coi là UTC (chỉ cần nhất quán, luật chỉ dùng khoảng cách giữa các mốc).
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from app.detection.engine.types import LoginAttempt
from ml.rba.etl import FULL_PARQUET
from ml.rba.features import RBA_CATCHALL_USER_ID
from ml.rba.paths import RBA_DATA_DIR

BATCH_ROWS = 50_000
DUCKDB_MEMORY_LIMIT = "1GB"  # sắp xếp (chỉ khi sort=True) tràn ra đĩa khi cần; phần còn lại của RAM dành cho engine (kho cửa sổ + lịch sử hàng triệu tài khoản)
UNKNOWN_NAME_MODES = ("attempt", "ip")

# Bốn tổ hợp nhãn dùng chung (chỉ đọc) thay vì tạo dict mới cho hàng chục triệu dòng.
_LABELS = {(a, b): {"is_attack_ip": a, "is_ato": b} for a in (False, True) for b in (False, True)}

_COLUMNS = "row_id, epoch_us(ts) AS ts_us, user_id, ip, country, asn, ua, browser, os, device_type, success, is_attack_ip, is_ato"


def rba_notes(unknown_names: str = "attempt") -> tuple[str, ...]:
    """Lưu ý chung của bộ dữ liệu, in ở đầu báo cáo."""
    if unknown_names == "attempt":
        naming = "cho từng lần thử (cận TRÊN của số tên khác nhau)"
    else:
        naming = "chung cho mọi lần thử từ cùng một IP (cận DƯỚI của số tên khác nhau; thử nghiệm độ nhạy, không phải cấu hình mặc định)"
    return (
        "RBA là bộ dữ liệu TỔNG HỢP (Wiefling và cộng sự, CC BY 4.0), không phải log thật: IP, nhà mạng và User-Agent đều là giá trị tổng hợp/ẩn danh. "
        "`is_attack_ip` = IP thuộc danh sách IP tấn công do người tạo bộ dữ liệu gắn; `is_ato` = 141 vụ chiếm đoạt tài khoản do họ gắn. Dòng không nhãn được coi là hợp lệ — "
        "giả định, không chắc chắn: nhà mạng có phần lớn dòng mang nhãn tấn công thì phần còn lại của nó chưa chắc hợp lệ, nên số \"báo nhầm\" của luật theo nhà mạng (phạm vi ASN) là CẬN TRÊN.",
        "RBA không có tên đăng nhập, chỉ có `user_id`; mọi lần thử vào tên KHÔNG tồn tại (user_id -4324475583306591935, chiếm 45% số dòng của toàn bộ RBA) được chuyển thành "
        f"`user_key = None` với tên giả {naming}, vì không biết tên thật. RBA không có toạ độ; có ASN (một phần là ASN nhân tạo ≥ 500000, vẫn dùng như định danh nhà mạng).",
        "Theo thẻ dữ liệu (docs/rba-data-card.md): timestamp có thành phần ngẫu nhiên — thứ tự và cửa sổ thô (giờ, ngày) đáng tin, cửa sổ vài phút và nhịp cách nhau vài giây chỉ là "
        "gần đúng; quốc gia bị gán ngẫu nhiên theo giá trị nên chỉ dùng được \"giống hay khác\", không có khoảng cách. Thời gian được coi là UTC (luật chỉ dùng khoảng cách giữa các mốc).",
    )


def rba_caveats(unknown_names: str = "attempt") -> dict[str, str]:
    """Lưu ý riêng cho từng luật: cái gì KHÔNG đánh giá được hoặc bị méo trên RBA."""
    caveats = {
        "impossible_travel": "Không đánh giá được: RBA không có toạ độ nên luật bị bỏ qua vì thiếu `geo`.",
        "tor_exit": "Không đánh giá được: IP trong RBA là tổng hợp nên danh sách Tor công khai không áp dụng (mặc định chưa nạp danh sách → luật bị bỏ qua).",
        "datacenter_ip": "Không đánh giá được: IP trong RBA là tổng hợp nên danh sách datacenter công khai không áp dụng (mặc định chưa nạp danh sách → luật bị bỏ qua).",
        "vpn_ip": "Không đánh giá được: IP trong RBA là tổng hợp nên danh sách VPN công khai không áp dụng (mặc định chưa nạp danh sách → luật bị bỏ qua).",
        "blocklist_hit": "Không áp dụng: blocklist rỗng trong replay (không có quản trị viên nào đặt mục chặn).",
        "distributed_bruteforce": "Chỉ thấy tài khoản có thật (tên giả của lần thử vào tên không tồn tại không bao giờ trùng giữa các IP).",
        "success_after_failures": "Chỉ áp dụng cho tài khoản có thật; đếm lần sai theo `user_id`.",
        "regular_rhythm": "Nhịp vài giây không đáng tin trên RBA vì timestamp có thành phần ngẫu nhiên (thẻ dữ liệu); luật shadow, kết quả không nói lên hiệu quả với log thật.",
        "multi_context_simultaneous": "Quốc gia của RBA gán ngẫu nhiên theo giá trị (chỉ dùng được \"khác nhau\") và cửa sổ 10 phút chịu thành phần ngẫu nhiên của timestamp.",
        "country_hop": "Quốc gia của RBA gán ngẫu nhiên theo giá trị: chỉ dùng được \"khác nhau\", không phản ánh di chuyển thật.",
        "scripted_client": "User-Agent của RBA gồm chuỗi trình duyệt tổng hợp và một số chuỗi công cụ/bot có thật (python-requests, Java, các bot thu thập) do bộ dữ liệu gắn cho lưu lượng bot; tỉ lệ và cách dùng công cụ trong log thật sẽ khác nên kết quả không suy ra được cho lưu lượng thật.",
        "bot_user_agent": "`device_type = bot` do thư viện phân tích UA của bộ dữ liệu gán (~6,5% số dòng trên toàn bộ RBA); không đồng nghĩa với tấn công.",
        "rare_network_login": "Đánh giá mang tính VÒNG TRÒN: ATO của RBA đến từ nhà mạng hiếm một cách nhân tạo (xem ghi chú luật và docs/rba-data-card.md). Giá trị thật đo bằng mô phỏng ở MR18.",
        "dormant_account_login": "Điều kiện \"thiết bị mới\" gần như luôn đúng trên RBA: User-Agent tổng hợp đổi liên tục (khoảng 52% đăng nhập hợp lệ có UA chưa từng thấy ở tài khoản, docs/rba-evaluation.md) nên số báo nhầm bị THỔI PHỒNG; "
        "luật cần lịch sử ≥ 90 ngày của chính tài khoản trong lần chạy nên chỉ khớp được từ ngày thứ 90 kể từ đầu lần chạy.",
    }
    if unknown_names == "attempt":
        caveats |= {
            "brute_force": "Tên đăng nhập là `user_id`. Lần thử vào tên không tồn tại có tên giả riêng cho từng lần nên không bao giờ chạm ngưỡng theo tên: luật chỉ thấy dò mật khẩu tài khoản CÓ THẬT.",
            "credential_stuffing": "Số tên khác nhau của một IP/ASN bị THỔI PHỒNG: mỗi lần sai vào tên không tồn tại được đếm như một tên mới (RBA gộp các tên đó nên không phân biệt được).",
            "password_spray_slow": "Số tên khác nhau bị thổi phồng như `credential_stuffing` (mỗi lần sai vào tên không tồn tại đếm như một tên mới).",
            "username_enumeration": "Chỉ là cận trên, không kiểm chứng được: RBA gộp mọi tên không tồn tại vào một `user_id`, adapter đặt tên giả riêng cho từng lần thử nên IP có nhiều lần sai vào tên không tồn tại đều trông như đang dò nhiều tên.",
        }
    else:
        caveats |= {
            "brute_force": "Cận trên của số lần khớp: mọi lần thử vào tên không tồn tại từ một IP dùng CHUNG một tên giả nên nhiều lần gõ sai từ một IP trông như dò mật khẩu MỘT tài khoản.",
            "credential_stuffing": "Cận dưới của số tên khác nhau: lần sai vào tên không tồn tại từ một IP chỉ tính là một tên.",
            "password_spray_slow": "Cận dưới của số tên khác nhau (mỗi IP một tên giả cho các lần sai vào tên không tồn tại).",
            "username_enumeration": "Không thể khớp ở cấu hình này: mỗi IP chỉ có một tên giả nên không bao giờ thấy nhiều tên khác nhau.",
        }
    return caveats


RBA_NOTES = rba_notes()
RBA_CAVEATS = rba_caveats()


def rba_attempts(*args, **kwargs) -> Iterator[LoginAttempt]:
    """Như `rba_rows` nhưng chỉ trả `LoginAttempt` (không kèm `row_id`)."""
    for _, attempt in rba_rows(*args, **kwargs):
        yield attempt


def rba_rows(
    parquet: Path | str | None = None,
    *,
    start: str | None = None,
    end: str | None = None,
    limit: int | None = None,
    batch_rows: int = BATCH_ROWS,
    sort: bool = False,
    unknown_names: str = "attempt",
) -> Iterator[tuple[int, LoginAttempt]]:
    """Các lần đăng nhập của RBA trong [`start`, `end`) theo thứ tự thời gian, mỗi lần kèm `row_id` của dòng trong RBA (khoá nối với bảng đặc trưng ML). `start`/`end`: ngày hoặc giờ dạng ISO (UTC).

    Đọc từng lô bằng DuckDB (không nạp cả 31 triệu dòng vào bộ nhớ). Mặc định (`sort=False`) TIN thứ tự vật lý của tệp: `ml.rba.etl` ghi theo `index` gốc và
    kiểm tra không có bước lùi thời gian (etl_stats.json: 0 bước), DuckDB giữ nguyên thứ tự khi quét parquet không có ORDER BY; nhờ đó không phải sắp xếp 13 triệu dòng
    (tốn hàng GB và tràn ra đĩa). `replay()` đếm số lần thử đi ngược thời gian (`out_of_order`) nên nếu giả định sai thì báo cáo nói rõ. `sort=True` sắp theo (thời gian, row_id)
    cho tệp không rõ thứ tự.

    `unknown_names`: cách đặt tên giả cho lần thử vào tên không tồn tại — `"attempt"` (mỗi lần một tên) hoặc `"ip"` (mỗi IP một tên); xem docstring của module."""
    import duckdb
    import pandas as pd

    if unknown_names not in UNKNOWN_NAME_MODES:
        raise ValueError(f"unknown_names phải là một trong {UNKNOWN_NAME_MODES}, nhận {unknown_names!r}")
    path = Path(parquet) if parquet else FULL_PARQUET
    if not path.is_file():
        raise FileNotFoundError(f"không thấy {path} — chạy `python -m ml.rba.etl` trước")

    where, params = [], []
    for column_op, value in (("ts >= ?", start), ("ts < ?", end)):
        if value is not None:
            where.append(column_op)
            params.append(pd.Timestamp(value).to_pydatetime())
    sql = f"SELECT {_COLUMNS} FROM read_parquet('{path.as_posix().replace(chr(39), chr(39) * 2)}')"
    if where:
        sql += " WHERE " + " AND ".join(where)
    if sort:
        sql += " ORDER BY ts, row_id"
    if limit is not None:
        sql += f" LIMIT {int(limit)}"

    per_attempt = unknown_names == "attempt"
    con = duckdb.connect()
    try:
        con.execute(f"SET memory_limit='{DUCKDB_MEMORY_LIMIT}'")
        tmp = RBA_DATA_DIR / "duckdb_tmp"
        tmp.mkdir(parents=True, exist_ok=True)
        con.execute(f"SET temp_directory='{tmp.as_posix()}'")
        result = con.execute(sql, params)
        while True:
            rows = result.fetchmany(batch_rows)
            if not rows:
                return
            for row_id, ts_us, user_id, ip, country, asn, ua, browser, os_name, device_type, success, is_attack_ip, is_ato in rows:
                known = user_id != RBA_CATCHALL_USER_ID
                yield row_id, LoginAttempt(
                    ts=ts_us / 1_000_000,
                    username=str(user_id) if known else (f"?{row_id}" if per_attempt else f"?{ip}"),
                    success=bool(success),
                    ip=ip,
                    user_key=str(user_id) if known else None,
                    asn=asn,
                    country=country,
                    user_agent=ua,
                    browser=browser,
                    os=os_name,
                    device_type=device_type,
                    labels=_LABELS[(bool(is_attack_ip), bool(is_ato))],
                )
    finally:
        con.close()
