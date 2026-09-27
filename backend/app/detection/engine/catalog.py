"""Sinh danh mục luật (docs/rule-catalog.md) TỰ ĐỘNG từ sổ đăng ký luật:

    cd backend
    venv\\Scripts\\python.exe -m app.detection.engine.catalog            # in ra màn hình
    venv\\Scripts\\python.exe -m app.detection.engine.catalog --write    # ghi docs/rule-catalog.md
    venv\\Scripts\\python.exe -m app.detection.engine.catalog --check    # thoát mã 1 nếu tệp trong docs/ đã lỗi thời (dùng cho CI)

Không sửa tay tệp docs/rule-catalog.md: mọi thứ trong đó (mã, mô tả, mức, MITRE, tham số và mặc định, dữ liệu cần, chế độ) lấy từ chính khai báo `@rule(...)`,
nên tài liệu không thể lệch khỏi mã. tests/test_rule_engine_catalog.py kiểm tra điều đó.
"""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping

import app.detection.engine  # noqa: F401 — nạp module để các luật tự đăng ký
from app.detection.engine.registry import CATEGORIES, NEEDS, REGISTRY, TECHNIQUES, Param, RuleSpec

DOC_PATH = Path(__file__).resolve().parents[4] / "docs" / "rule-catalog.md"
SEVERITY_VI = {"low": "thấp", "medium": "trung bình", "high": "cao"}
MODE_VI = {"enforce": "enforce (tạo cảnh báo)", "shadow": "shadow (chỉ ghi nhận)", "off": "off"}


def fmt_value(value: Any) -> str:
    """Giá trị mặc định viết đúng như trong tệp cấu hình JSON (dấu chấm thập phân)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, tuple):
        shown = ", ".join(value[:8])
        return f"{shown}, … ({len(value)} mục)" if len(value) > 8 else shown
    if isinstance(value, float):
        return f"{value:g}"
    return str(value)  # số nguyên viết liền, đúng như trong tệp JSON


def fmt_range(param: Param) -> str:
    if param.minimum is None and param.maximum is None:
        return "—"
    def number(v: float) -> str:
        return str(int(v)) if float(v).is_integer() else f"{v:g}"  # 1e+06 khó đọc: số nguyên viết liền

    low = "" if param.minimum is None else number(param.minimum)
    high = "" if param.maximum is None else number(param.maximum)
    return f"{low}–{high}" if low and high else (f"≥ {low}" if low else f"≤ {high}")


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render(registry: Mapping[str, RuleSpec] | None = None) -> str:
    registry = REGISTRY if registry is None else registry
    specs = list(registry.values())
    by_category: dict[str, list[RuleSpec]] = defaultdict(list)
    for spec in specs:
        by_category[spec.category].append(spec)
    shadow = [s.id for s in specs if s.default_mode == "shadow"]

    lines = [
        "# Danh mục luật (rule engine v2)",
        "",
        "> **Tệp này được TỰ SINH** từ sổ đăng ký luật (`python -m app.detection.engine.catalog --write`) — đừng sửa tay. `tests/test_rule_engine_catalog.py` báo lỗi nếu tệp lỗi thời so với mã.",
        "",
        "Mã: [`backend/app/detection/engine/`](../backend/app/detection/engine/) · kiểm thử: `tests/test_rule_engine_*.py` · đo từng luật trên log lịch sử: `python -m app.detection.engine.replay` (kết quả trên RBA: [`rule-replay.md`](rule-replay.md)) · ngưỡng đã tinh chỉnh trên train RBA: [`rule-tuning.md`](rule-tuning.md).",
        "",
        "## 1. Tổng quan",
        "",
        f"**{len(specs)} luật** trong {len(by_category)} nhóm; {len(specs) - len(shadow)} luật mặc định ở chế độ `enforce`, {len(shadow)} ở chế độ `shadow` "
        f"({', '.join(f'`{i}`' for i in shadow)}) vì chưa được kiểm chứng trên log thật hoặc dễ báo nhầm.",
        "",
        "| Mã | Tên | Nhóm | Mức | Chế độ mặc định | MITRE ATT&CK |",
        "|---|---|---|---|---|---|",
    ]
    for category in CATEGORIES:
        for spec in by_category.get(category, []):
            techniques = ", ".join(spec.techniques) if spec.techniques else "—"
            lines.append(f"| [`{spec.id}`](#{spec.id}) | {spec.title} | {spec.category} | {SEVERITY_VI[spec.severity]} | {spec.default_mode} | {techniques} |")

    lines += [
        "",
        "## 2. Cách hoạt động",
        "",
        "- **Đầu vào duy nhất** của mọi luật là `LoginAttempt` (một lần thử đăng nhập đã chuẩn hoá: thời điểm SỰ KIỆN, tên đăng nhập, kết quả, IP, ASN, quốc gia, toạ độ, User-Agent...) và lịch sử tài khoản. Luồng thật (MR12), replay log lịch sử và test đều gọi cùng `RuleEngine.evaluate`; luật không biết dữ liệu đến từ đâu và **không bao giờ đọc nhãn** (`labels`) của log replay.",
        "- **Thời gian là thời gian của sự kiện**, không phải giờ hệ thống: replay log năm 2020 cho đúng kết quả của năm 2020. Cửa sổ là (đầu, hiện tại] — sự kiện đúng bằng đầu cửa sổ không được tính.",
        "- **Trạng thái cửa sổ thời gian** (đếm lần sai, đếm tên/IP/User-Agent khác nhau...) nằm ở `WindowStore`: `MemoryStore` cho replay và test, `RedisStore` cho luồng thật; một bộ test chung chứng minh hai cài đặt cùng hợp đồng và cho cùng kết quả trên lưu lượng ngẫu nhiên. Chi phí mỗi sự kiện bị chặn bởi ngưỡng, không tăng theo độ dài cửa sổ.",
        "- **Ba chế độ** cho mỗi luật: `enforce` (khớp thì tạo cảnh báo), `shadow` (vẫn chạy và ghi nhận để đo tỉ lệ khớp/báo nhầm nhưng KHÔNG tạo cảnh báo), `off` (không chạy).",
        "- **Thiếu dữ liệu ≠ báo động:** luật cần dữ liệu mà lần thử không có (ví dụ chưa có file GeoLite2-ASN) bị **bỏ qua** và `Evaluation.skipped` ghi lý do; luật gặp lỗi được ghi ở `Evaluation.errors` và không ảnh hưởng luật khác hay luồng đăng nhập.",
        "- **Thông điệp** ngắn tiếng Việt cùng phong cách chuỗi cảnh báo hiện có; ba luật gốc (`brute_force`, `credential_stuffing`, `impossible_travel`) giữ đúng chuỗi và ngưỡng mặc định của luật tầng 1 cũ.",
        "- ⚠️ Ánh xạ MITRE ATT&CK là **gần đúng**: ATT&CK mô tả kỹ thuật của kẻ tấn công, còn luật nhận diện dấu hiệu của chúng trong log đăng nhập.",
        "",
        "### Cấu hình",
        "",
        "Ghi đè chế độ và tham số theo từng luật bằng JSON (`RuleConfig.from_file(...)`); luật không nêu dùng mặc định của bảng dưới. Tham số sai (không tồn tại, sai kiểu, ngoài khoảng) bị từ chối ngay khi nạp. Mặc định ở bảng dưới là giá trị đặt trước; hồ sơ [`profiles/rba_train_tuned.json`](../backend/app/detection/engine/profiles/rba_train_tuned.json) là bộ tham số đã tinh chỉnh trên train RBA (chỉ đúng cho RBA, xem [`rule-tuning.md`](rule-tuning.md)).",
        "",
        "```json",
        '{"rules": {"brute_force": {"params": {"threshold": 8, "window_s": 600}}, "vpn_ip": {"mode": "off"}, "country_hop": {"mode": "enforce"}}}',
        "```",
        "",
        "## 3. Ánh xạ MITRE ATT&CK",
        "",
        "| Kỹ thuật | Tên | Luật |",
        "|---|---|---|",
    ]
    for technique, name in TECHNIQUES.items():
        rules = [f"`{s.id}`" for s in specs if technique in s.techniques]
        if rules:
            lines.append(f"| [{technique}](https://attack.mitre.org/techniques/{technique.replace('.', '/')}/) | {name} | {', '.join(rules)} |")
    unmapped = [f"`{s.id}`" for s in specs if not s.techniques]
    if unmapped:
        lines.append(f"| — | không ánh xạ kỹ thuật cụ thể | {', '.join(unmapped)} |")

    lines += ["", "## 4. Dữ liệu cần có", "", "Thiếu dữ liệu thì luật tương ứng bị bỏ qua (xem mục 2).", "", "| Dữ liệu | Ý nghĩa | Luật cần |", "|---|---|---|"]
    for need, meaning in NEEDS.items():
        rules = [f"`{s.id}`" for s in specs if need in s.needs]
        if rules:
            lines.append(f"| `{need}` | {meaning} | {', '.join(rules)} |")

    lines += ["", "## 5. Chi tiết từng luật", ""]
    for category in CATEGORIES:
        if not by_category.get(category):
            continue
        lines += [f"### {category}", ""]
        for spec in by_category[category]:
            lines += [
                f"#### <a id=\"{spec.id}\"></a>`{spec.id}` — {spec.title}",
                "",
                spec.description,
                "",
                f"- **Mức nghiêm trọng:** {SEVERITY_VI[spec.severity]} · **chế độ mặc định:** {MODE_VI[spec.default_mode]}",
                f"- **MITRE ATT&CK:** " + (", ".join(f"{t} ({TECHNIQUES[t]})" for t in spec.techniques) if spec.techniques else "không ánh xạ kỹ thuật cụ thể"),
                "- **Dữ liệu cần:** " + (", ".join(f"`{n}`" for n in spec.needs) if spec.needs else "không (chỉ cần `LoginAttempt`)"),
            ]
            if spec.notes:
                lines.append(f"- **Ghi chú:** {spec.notes}")
            if spec.params:
                lines += ["", "| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |", "|---|---|---|---|---|"]
                for p in spec.params:
                    lines.append(f"| `{p.name}` | `{_cell(fmt_value(p.default))}` | {p.unit or '—'} | {fmt_range(p)} | {_cell(p.description)} |")
            lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    text = render()
    if "--write" in argv:
        DOC_PATH.write_text(text, encoding="utf-8", newline="\n")
        print(f"đã ghi {DOC_PATH} ({len(REGISTRY)} luật)")
        return 0
    if "--check" in argv:
        current = DOC_PATH.read_text(encoding="utf-8") if DOC_PATH.is_file() else ""
        if current != text:
            print("docs/rule-catalog.md đã lỗi thời — chạy: python -m app.detection.engine.catalog --write")
            return 1
        print("docs/rule-catalog.md khớp sổ đăng ký")
        return 0
    sys.stdout.reconfigure(encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
