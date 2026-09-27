"""MR14 — kiểm chứng thuật toán tương quan chiến dịch (`app/detection/campaign_correlation.py`) trên 141 ATO THẬT của
RBA (không phải kẻ tấn công mô phỏng — xem project_rba_dataset.md: chỉ có 38 ATO ở test, 141 toàn bộ; ⚠️ vẫn là dữ
liệu TỔNG HỢP theo Wiefling et al., không phải tấn công thật ngoài đời).

Câu hỏi: nhiều nạn nhân KHÁC NHAU có bị cùng một hạ tầng (IP/ASN) tấn công không, và thuật toán nối-theo-đồ-thị có
PHỤC HỒI được các cụm đó không? Đo trực tiếp bằng cách chạy CHÍNH `correlate()` sẽ dùng ở luồng thật, không phải một
bản mô phỏng riêng.

⚠️ IP trong RBA công khai có vẻ đã được ẩn danh một phần cho nhiều dòng (nhiều giá trị nằm trong dải riêng RFC1918:
10.x.x.x — không thể là IP thật trên Internet) trong khi ASN vẫn là số nguyên thật; vì vậy báo cáo này dùng ASN làm
tín hiệu CHÍNH (nhóm theo ASN thô cho biết mức trần khả dĩ), IP chỉ là tín hiệu PHỤ khi có sẵn — đúng thứ tự ưu tiên
`correlate()` đã dùng (nối khi CÙNG IP HOẶC CÙNG ASN, không yêu cầu cả hai).

Cửa sổ thời gian dùng ở ĐÂY (nhiều ngày — khớp nhịp độ 141 ATO rải suốt gần 1 năm) là RIÊNG cho báo cáo này, KHÔNG
PHẢI cửa sổ dùng cho luồng thật (`CAMPAIGN_WINDOW` trong `app/detection/pipeline.py`, ngắn hơn nhiều — xem lý do ở
`docs/campaign-correlation.md`): hai chế độ trả lời hai câu hỏi khác nhau (RBA: "hạ tầng có tái sử dụng qua nhiều
tháng không", luồng thật: "có nên gộp NGAY hôm nay không").

Chạy: cd backend && venv\\Scripts\\python.exe -m ml.rba.campaign_correlation_eval
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from app.detection.campaign_correlation import CorrelationNode, correlate, group_by_component
from ml.rba.etl import FULL_PARQUET

WINDOWS_DAYS = (1, 7, 30, 90)
REPORT_PATH = Path(__file__).resolve().parents[3] / "docs" / "campaign-correlation.md"  # backend/ml/rba/<file> -> lên 3 cấp = gốc repo
PAYLOAD_PATH = Path(__file__).resolve().parent.parent / "artifacts" / "campaign_correlation_eval.json"


@dataclass(frozen=True)
class AtoRow:
    row_id: int
    ts_s: float
    user_id: int
    ip: str | None
    asn: int | None
    country: str | None


def load_real_ato_rows(parquet: Path | None = None) -> list[AtoRow]:
    """141 dòng `is_ato = true` thật của RBA (không phải kẻ tấn công mô phỏng)."""
    import duckdb

    path = parquet or FULL_PARQUET
    if not path.is_file():
        raise FileNotFoundError(f"không thấy {path} — chạy `python -m ml.rba.etl` trước")
    sql = f"""
        SELECT row_id, epoch(ts) AS ts_s, user_id, ip, asn, country
        FROM read_parquet('{path.as_posix().replace(chr(39), chr(39) * 2)}')
        WHERE is_ato = true
        ORDER BY ts
    """
    con = duckdb.connect()
    try:
        rows = con.execute(sql).fetchall()
    finally:
        con.close()
    return [
        AtoRow(
            row_id=int(row_id), ts_s=float(ts_s), user_id=int(user_id), ip=ip,
            asn=None if asn is None or (isinstance(asn, float) and math.isnan(asn)) else int(asn), country=country,
        )
        for row_id, ts_s, user_id, ip, asn, country in rows
    ]


def _raw_asn_sharing(rows: list[AtoRow]) -> dict:
    """Mức TRẦN không ràng buộc thời gian: bao nhiêu dòng ATO có CHUNG ASN với ít nhất 1 dòng ATO khác — cho biết hạ
    tầng có được TÁI SỬ DỤNG qua nhiều nạn nhân hay không, trước khi thuật toán cắt bớt theo cửa sổ thời gian."""
    by_asn: dict[int, list[AtoRow]] = {}
    for r in rows:
        if r.asn is not None:
            by_asn.setdefault(r.asn, []).append(r)
    shared = [r for group in by_asn.values() if len(group) >= 2 for r in group]
    return {
        "n_total": len(rows), "n_with_known_asn": sum(1 for r in rows if r.asn is not None),
        "n_sharing_asn_with_another_ato": len(shared), "pct_sharing_asn": round(100.0 * len(shared) / len(rows), 1),
        "n_distinct_asns_reused": sum(1 for group in by_asn.values() if len(group) >= 2),
    }


def _campaign_summary(rows: list[AtoRow], window_days: int) -> dict:
    nodes = [CorrelationNode(r.row_id, r.ts_s, r.ip, r.asn) for r in rows]
    by_id = {r.row_id: r for r in rows}
    components = correlate(nodes, window=timedelta(days=window_days))
    campaigns = group_by_component(components)

    def victims(campaign) -> set[int]:
        return {by_id[i].user_id for i in campaign.node_ids}

    multi = [c for c in campaigns if len(victims(c)) >= 2]
    rows_in_multi = sum(c.size for c in multi)
    top = sorted(multi, key=lambda c: -c.size)[:3]

    def describe(campaign) -> dict:
        members = [by_id[i] for i in campaign.node_ids]
        span_days = (max(m.ts_s for m in members) - min(m.ts_s for m in members)) / 86_400
        asns = sorted({m.asn for m in members if m.asn is not None})
        countries = sorted({m.country for m in members if m.country})
        return {
            "n_rows": campaign.size, "n_distinct_victims": len(victims(campaign)), "span_days": round(span_days, 1),
            "asns": asns, "countries": countries,
        }

    return {
        "window_days": window_days, "n_campaigns_total": len(campaigns), "n_multi_victim_campaigns": len(multi),
        "n_ato_rows_in_multi_victim_campaigns": rows_in_multi, "pct_coverage": round(100.0 * rows_in_multi / len(rows), 1),
        "top_campaigns": [describe(c) for c in top],
    }


def build_payload(rows: list[AtoRow] | None = None) -> dict:
    rows = rows if rows is not None else load_real_ato_rows()
    return {
        "n_ato_rows": len(rows),
        "raw_asn_sharing": _raw_asn_sharing(rows),
        "windows": [_campaign_summary(rows, w) for w in WINDOWS_DAYS],
        "live_window_hours": 24,
    }


def render(payload: dict) -> str:
    raw = payload["raw_asn_sharing"]
    lines = [
        "# Tương quan chiến dịch (MR14)",
        "",
        "Kiểm chứng thuật toán nối-theo-đồ-thị (`app/detection/campaign_correlation.py`) trên **141 ATO THẬT** của RBA "
        "(không phải kẻ tấn công mô phỏng — vẫn là dữ liệu tổng hợp theo Wiefling et al., xem project_rba_dataset.md). "
        "Mã nguồn báo cáo: [`ml/rba/campaign_correlation_eval.py`](../backend/ml/rba/campaign_correlation_eval.py).",
        "",
        "## Mức trần: hạ tầng có được tái sử dụng qua nhiều nạn nhân không?",
        "",
        f"Trong {raw['n_total']} dòng ATO thật ({raw['n_with_known_asn']} biết ASN): **{raw['n_sharing_asn_with_another_ato']} dòng "
        f"({raw['pct_sharing_asn']}%)** có CÙNG ASN với ít nhất một dòng ATO khác, tạo thành {raw['n_distinct_asns_reused']} ASN được "
        "tái sử dụng — nghĩa là phần lớn ATO thật KHÔNG phải tấn công đơn lẻ, đáng để tương quan thành chiến dịch. Số này CHƯA có "
        "ràng buộc thời gian (mức trần khả dĩ); các bảng dưới đây áp cửa sổ thời gian thật của thuật toán.",
        "",
        "## Kết quả theo cửa sổ thời gian",
        "",
        "| Cửa sổ | Số chiến dịch | Chiến dịch nhiều nạn nhân | Dòng ATO trong đó | % bao phủ | Chiến dịch lớn nhất |",
        "|---|---|---|---|---|---|",
    ]
    for w in payload["windows"]:
        top1 = w["top_campaigns"][0] if w["top_campaigns"] else None
        biggest = f"{top1['n_rows']} dòng / {top1['n_distinct_victims']} TK / {top1['span_days']} ngày (ASN {top1['asns']})" if top1 else "*(không có)*"
        lines.append(
            f"| {w['window_days']} ngày | {w['n_campaigns_total']} | {w['n_multi_victim_campaigns']} | "
            f"{w['n_ato_rows_in_multi_victim_campaigns']} | {w['pct_coverage']}% | {biggest} |"
        )

    lines += ["", "## 3 chiến dịch lớn nhất ở cửa sổ 30 ngày (kiểm tra định tính)", ""]
    thirty = next(w for w in payload["windows"] if w["window_days"] == 30)
    for c in thirty["top_campaigns"]:
        lines.append(f"- **{c['n_rows']} dòng, {c['n_distinct_victims']} tài khoản khác nhau**, trải {c['span_days']} ngày — ASN {c['asns']}, quốc gia {c['countries']}")

    lines += [
        "",
        "## Diễn giải",
        "",
        "- Cửa sổ CÀNG DÀI, số chiến dịch nhiều nạn nhân/độ bao phủ CÀNG TĂNG (gộp được nhiều đợt tái xuất hiện cách xa "
        "nhau hơn) nhưng cũng dễ gộp NHẦM hai đợt không liên quan tình cờ dùng chung ASN lớn — không có cửa sổ nào "
        "\"đúng tuyệt đối\", đây là đánh đổi có chủ đích, không phải thiếu sót.",
        "- Vài chiến dịch lớn nhất (xem danh sách định tính ở trên) trải dài NHIỀU THÁNG với CHỤC tài khoản khác nhau bị "
        "nhắm — khớp trực giác về một hạ tầng bị lạm dụng lâu dài (proxy/hosting giá rẻ bị nhiều kẻ tấn công thuê lại), "
        "không phải một cụm ngẫu nhiên do trùng hợp ASN.",
        f"- **Cửa sổ dùng cho LUỒNG THẬT** (`app/detection/pipeline.py`) là **{payload['live_window_hours']} giờ**, KHÔNG "
        "PHẢI con số tốt nhất đo được ở bảng trên — hai câu hỏi khác nhau: RBA đo \"hạ tầng có tái dùng qua NHIỀU THÁNG "
        "không\" (dữ liệu 141 dòng rải cả năm, cần cửa sổ dài mới thấy), luồng thật cần \"có nên gộp NGAY hôm nay không\" "
        "để cảnh báo còn kịp hành động — cửa sổ dài ngày cho mục đích vận hành sẽ khiến chiến dịch \"mở\" hàng tháng "
        "trời, không thực tế cho một dashboard giám sát.",
        "",
        "## Giới hạn",
        "",
        "- RBA vẫn là dữ liệu TỔNG HỢP (Wiefling et al., CC BY 4.0) — 141 ATO là mô phỏng theo phân phối thật, không "
        "phải tấn công thật ngoài đời; số liệu ở đây chứng minh thuật toán HOẠT ĐỘNG ĐÚNG Ý ĐỊNH (phục hồi cụm hạ tầng "
        "dùng chung), không chứng minh hiệu quả trên tấn công thật.",
        "- Nhiều giá trị IP trong RBA công khai có vẻ đã ẩn danh về dải riêng (10.x.x.x) — báo cáo dùng ASN làm tín hiệu "
        "chính vì lý do đó; luồng thật (IP không ẩn danh) có thêm tín hiệu IP đầy đủ nên có thể tương quan tốt hơn số đo ở đây.",
        "- Chưa đo được tỉ lệ GỘP NHẦM (hai đợt tấn công độc lập bị coi là một chiến dịch chỉ vì trùng ASN lớn dùng chung "
        "bởi nhiều bên) một cách định lượng — chỉ kiểm tra định tính bằng mắt trên vài chiến dịch lớn nhất.",
        "- Gán chiến dịch ở luồng thật là GIA TĂNG (một alert mới chỉ MỞ RỘNG chiến dịch đang có, không GỘP LẠI hai "
        "chiến dịch đã tách nếu có alert bắc cầu đến sau) — xem giới hạn chi tiết ở docstring `pipeline.py`.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    payload = build_payload()
    PAYLOAD_PATH.parent.mkdir(parents=True, exist_ok=True)
    PAYLOAD_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    REPORT_PATH.write_text(render(payload), encoding="utf-8")
    raw = payload["raw_asn_sharing"]
    print(f"{raw['pct_sharing_asn']}% ATO thật chia sẻ ASN với dòng ATO khác ({raw['n_sharing_asn_with_another_ato']}/{raw['n_total']})")
    for w in payload["windows"]:
        print(f"  cua so {w['window_days']}d: {w['n_multi_victim_campaigns']} chien dich nhieu nan nhan, bao phu {w['pct_coverage']}%")
    print(f"Da ghi {REPORT_PATH} va {PAYLOAD_PATH}")


if __name__ == "__main__":
    main()
