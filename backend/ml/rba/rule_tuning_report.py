"""Chọn bậc thang trên train (và train ∧ val), đo trên val/test/late và ATO, ghi docs/rule-tuning.md, hồ sơ cấu hình luật và JSON số liệu (MR10).

Chạy: `python -m ml.rba.rule_tuning tune` (sau `collect`). Toàn bộ số trong tài liệu lấy từ `build_payload` — `render` chỉ định dạng, nên kiểm thử được bằng dữ liệu nhỏ.

HAI QUY TRÌNH chọn bậc, cả hai dùng cùng ngân sách:
  - **chỉ train** (`train_only`): quy trình ĐẶT TRƯỚC khi xem bất kỳ kết quả nào;
  - **train ∧ val** (`train_val`): quy trình SỬA, thêm điều kiện val cũng phải trong ngân sách, được đưa ra SAU khi thấy quy trình đầu không giữ được ở test/late với hai luật (như mọi mô hình ở dự án
    này, val là nơi chọn còn test chỉ để báo cáo). Cả hai đều được báo cáo để người đọc tự đánh giá; số của quy trình đặt trước mới là ước lượng chưa bị ảnh hưởng bởi kết quả test.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np
import pandas as pd

from app.detection.engine import REGISTRY
from ml.rba import rule_tuning as RT
from ml.rba.rule_tuning import LADDERS, Ladder

CI_BOOT = 200
TRANSFER_FACTOR = 3.0  # "giữ được" = khớp/10.000 trên test không quá 3 lần ngân sách (chỉ để báo cáo, không dùng để chọn)
PROCEDURES = {"train_only": ("train",), "train_val": ("train", "val")}


def union_flags(frame: pd.DataFrame, chosen: Mapping[str, int], index: np.ndarray, ladders: Sequence[Ladder] = LADDERS) -> np.ndarray:
    """Cờ "có ít nhất một luật đã chọn khớp" tại các vị trí `index` của `frame`. `chosen`: tên bậc thang -> bậc (từ 1)."""
    by_name = {l.name: l for l in ladders}
    flagged = np.zeros(len(index), dtype=bool)
    for name, rung in chosen.items():
        flagged |= frame[by_name[name].column].to_numpy()[index] >= rung
    return flagged


def set_metrics(frame: pd.DataFrame, chosen: Mapping[str, int], parts: Mapping[str, RT.Part], ato: RT.AtoSet, with_ci: bool = True) -> dict[str, Any]:
    out: dict[str, Any] = {"members": dict(chosen)}
    for name, part in parts.items():
        flagged = union_flags(frame, chosen, part.index)
        out[name] = part.metrics(flagged)
        if with_ci and name == "test":
            out["test_ci"] = {k: list(v) for k, v in part.ci(flagged, n_boot=CI_BOOT).items()}
    out["ato"] = ato.counts(union_flags(frame, chosen, ato.index))
    return out


def build_payload(frame: pd.DataFrame, ladders: Sequence[Ladder] = LADDERS) -> dict[str, Any]:
    parts = {name: RT.Part(frame, name) for name in RT.PARTITIONS}
    ato = RT.AtoSet(frame)
    tables = {ladder.name: RT.rung_rows(frame, ladder, parts, ato) for ladder in ladders}
    selections = {
        procedure: {budget: {name: RT.select_rung(rows, budget, using) for name, rows in tables.items()} for budget in RT.BUDGETS} for procedure, using in PROCEDURES.items()
    }
    primary = {procedure: selections[procedure][RT.PRIMARY_BUDGET] for procedure in PROCEDURES}

    payload: dict[str, Any] = {
        "budget": RT.PRIMARY_BUDGET, "budgets": list(RT.BUDGETS), "ladders": {}, "not_evaluable": RT.NOT_EVALUABLE, "profile_excluded": RT.PROFILE_EXCLUDED,
        "sizes": {name: {"n_attack": part.metrics(np.zeros(len(part.index), dtype=bool))["n_attack"], "legit_success_weight": part.den_fa, "attack_weight": part.den_recall} for name, part in parts.items()},
        "n_ato": {k: v[1] for k, v in ato.counts(np.ones(len(ato.index), dtype=bool)).items()},
    }
    for ladder in ladders:
        rows = tables[ladder.name]
        entry: dict[str, Any] = {
            "rule_id": ladder.rule_id, "note": ladder.note, "default_rung": ladder.default_rung, "default_mode": REGISTRY[ladder.rule_id].default_mode,
            "rungs": [{"rung": r.rung, "params": r.params, **r.by_part, "ato": r.ato} for r in rows],
            "selected": {procedure: {str(b): selections[procedure][b][ladder.name] for b in RT.BUDGETS} for procedure in PROCEDURES},
            "test_ci": {},
        }
        for procedure in PROCEDURES:
            chosen = primary[procedure][ladder.name]
            if chosen is not None:
                flagged = frame[ladder.column].to_numpy()[parts["test"].index] >= chosen
                entry["test_ci"][procedure] = {k: list(v) for k, v in parts["test"].ci(flagged, n_boot=CI_BOOT).items()}
        payload["ladders"][ladder.name] = entry

    enforce = {l.name for l in ladders if REGISTRY[l.rule_id].default_mode == "enforce"}
    revised = {n: r for n, r in primary["train_val"].items() if r is not None and n not in RT.PROFILE_EXCLUDED}
    sets = {
        "default_enforce": {l.name: l.default_rung for l in ladders if l.name in enforce and l.default_rung},
        "train_only_enforce": {n: r for n, r in primary["train_only"].items() if r is not None and n in enforce},
        "tuned_enforce": {n: r for n, r in revised.items() if n in enforce},
        "tuned_all": dict(revised),
    }
    payload["sets"] = {name: set_metrics(frame, chosen, parts, ato) for name, chosen in sets.items()}
    payload["profile"] = RT.build_profile(primary["train_val"], ladders)

    limit = TRANSFER_FACTOR * RT.PRIMARY_BUDGET
    tested = {name: payload["ladders"][name]["rungs"][primary["train_only"][name] - 1]["test"]["fa10k"] for name in payload["ladders"] if primary["train_only"][name] is not None}
    payload["transfer"] = {"factor": TRANSFER_FACTOR, "limit": limit, "held": sorted(n for n, v in tested.items() if v <= limit), "failed": sorted(n for n, v in tested.items() if v > limit)}
    return payload


# ------------------------------------------------------------------------------------------------ định dạng


def _fa(x: float) -> str:
    return "—" if x is None or (isinstance(x, float) and np.isnan(x)) else f"{x:,.1f}"


def _pct(x: float) -> str:
    return "—" if x is None or (isinstance(x, float) and np.isnan(x)) else f"{x:.1%}"


def _ci(pair, fmt) -> str:
    return "" if not pair else f" [{fmt(pair[0])}–{fmt(pair[1])}]"


def _ato(counts: Mapping[str, Sequence[int]], key: str) -> str:
    k, n = counts[key]
    return f"{k}/{n}"


def _chosen_cells(entry: Mapping[str, Any], procedure: str, budget: float) -> str:
    """Ba ô của một quy trình: tham số đã chọn | khớp/10.000 (train … → test, kèm khoảng tin cậy) | recall test."""
    rungs, chosen = entry["rungs"], entry["selected"][procedure][str(budget)]
    if chosen is None:
        best = rungs[-1]
        return f"**không chọn được** (bậc chặt nhất `{best['params']}` vẫn {_fa(best['train']['fa10k'])}) | — | —"
    row, ci = rungs[chosen - 1], entry["test_ci"].get(procedure, {})
    where = "train → test" if procedure == "train_only" else "train / val → test"
    trail = f"{_fa(row['train']['fa10k'])}" + ("" if procedure == "train_only" else f" / {_fa(row['val']['fa10k'])}") + f" → {_fa(row['test']['fa10k'])}{_ci(ci.get('fa10k'), _fa)}"
    same = " (= mặc định)" if chosen == entry["default_rung"] else ""
    return f"**`{row['params']}`**{same} | {trail} | {_pct(row['test']['recall'])}{_ci(ci.get('recall'), _pct)}"


def render(payload: Mapping[str, Any]) -> str:
    budget, ladders, sizes = payload["budget"], payload["ladders"], payload["sizes"]
    excluded = payload["profile_excluded"]
    transfer = payload["transfer"]
    lines = [
        "# Tinh chỉnh ngưỡng luật trên train RBA (MR10)",
        "",
        "> Báo cáo TỰ SINH bởi `python -m ml.rba.rule_tuning tune` (sau `collect`) — đừng sửa tay. Mã: [`rule_tuning.py`](../backend/ml/rba/rule_tuning.py), [`rule_tuning_report.py`](../backend/ml/rba/rule_tuning_report.py). "
        "Hồ sơ cấu hình luật: [`profiles/rba_train_tuned.json`](../backend/app/detection/engine/profiles/rba_train_tuned.json).",
        "",
        "## 1. Cách làm, quy trình sửa và những gì cần đọc kèm",
        "",
        "- **Đối tượng:** ngưỡng của các luật ở [`rule-catalog.md`](rule-catalog.md) (giá trị mặc định là giá trị đặt trước, chưa từng đo trên dữ liệu — xem [`rule-replay.md`](rule-replay.md)). Mỗi luật có một *bậc thang* tham số từ lỏng đến chặt sao cho lần khớp lồng nhau; "
        "luật hai điều kiện (số lần sai và số tên) quét dọc một tia tỉ lệ, luật hai phạm vi (IP, ASN) có hai bậc thang riêng; các tham số còn lại giữ mặc định.",
        "- **Dữ liệu:** một lượt replay toàn bộ RBA, chấm các dòng thuộc mẫu ML (tài khoản có thật; lần thử vào tên không tồn tại nằm ngoài mẫu) với ĐÚNG trọng số dân số và định nghĩa dương/âm của khung đánh giá ML, để số của luật và của mô hình so được ([`rule-ml-overlap.md`](rule-ml-overlap.md)).",
        f"- **Quy trình đặt trước (chỉ train):** bậc LỎNG NHẤT có tỉ lệ khớp trên dòng bình thường ≤ **{budget:g} lần trên 10.000 đăng nhập hợp lệ thành công** ở train (ngân sách đặt trước khi xem kết quả; 2 và 10 chỉ để xem độ nhạy). "
        "Nhãn tấn công và ATO KHÔNG tham gia chọn: chúng chỉ định nghĩa \"dòng bình thường\" và để báo cáo val/test/late.",
        f"- **Quy trình sửa (train ∧ val):** cùng ngân sách nhưng ở CẢ train và val. ⚠️ Được thêm SAU khi thấy quy trình đặt trước không giữ được ở test/late với {len(transfer['failed'])} bậc thang "
        f"({', '.join(f'`{n}`' for n in transfer['failed']) or '—'}), nên số của quy trình sửa không còn là ước lượng \"sạch\" về mặt thiết kế quy trình (chưa tham số nào được khớp vào test); số của quy trình đặt trước mới là ước lượng chưa bị ảnh hưởng. "
        "Hai bậc thang còn bị loại khỏi hồ sơ cấu hình vì cơ chế, không phải vì điểm (mục 4).",
        "- **Chỉ số:** *khớp/10.000* = trọng số các lần luật khớp trên dòng bình thường (không thuộc IP tấn công, mọi kết quả đăng nhập) chia cho trọng số đăng nhập hợp lệ thành công, nhân 10.000 — cùng mẫu số với \"cảnh báo nhầm trên 10.000 đăng nhập\" của mô hình; "
        "*recall* = tỉ lệ trọng số dòng thuộc IP tấn công (phân vùng tương ứng) mà luật khớp. Khoảng tin cậy 95% lấy mẫu lại theo cụm IP.",
        "- ⚠️ Dòng không nhãn coi là bình thường nên *khớp/10.000* là **cận trên** của báo nhầm (nhà mạng có nhiều IP tấn công thì các dòng còn lại chưa chắc hợp lệ). RBA là dữ liệu tổng hợp; ngưỡng ở đây tinh chỉnh cho RBA, không tự nhiên áp cho hệ thống thật. "
        "Khung mẫu ML chỉ có tài khoản có thật, nên lưu lượng đoán mật khẩu vào tên không tồn tại (45% số dòng của RBA, nơi các luật đoán mật khẩu có nhiều đất dụng võ nhất) nằm NGOÀI phép đo này.",
        "",
        "Cỡ mẫu: " + "; ".join(f"{name}: {s['n_attack']:,} dòng tấn công, {s['legit_success_weight']:,.0f} đăng nhập hợp lệ thành công (đã trọng số)" for name, s in sizes.items()) + f"; ATO: {payload['n_ato']['past']} quá khứ + {payload['n_ato']['future']} tương lai.",
        "",
        f"## 2. Kết quả theo từng luật (ngân sách {budget:g}/10.000)",
        "",
        "| Bậc thang | Mặc định: tham số | khớp/10.000 train → test | **Chỉ train (đặt trước)** | khớp/10.000 train → test | recall test | **Train ∧ val (sửa)** | khớp/10.000 train / val → test | recall test | ATO tương lai | Hồ sơ |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name, entry in ladders.items():
        rungs, d = entry["rungs"], entry["default_rung"]
        default = rungs[d - 1] if d else None
        default_cells = f"`{default['params']}` | {_fa(default['train']['fa10k'])} → {_fa(default['test']['fa10k'])}" if default else "— | —"
        revised = entry["selected"]["train_val"][str(budget)]
        ato_cell = _ato(rungs[revised - 1]["ato"], "future") if revised is not None else "—"
        if name in excluded:
            profile_cell = "loại (mục 4)"
        elif revised is None:
            profile_cell = "shadow"
        else:
            profile_cell = "✔"
        lines.append(f"| `{name}` | {default_cells} | {_chosen_cells(entry, 'train_only', budget)} | {_chosen_cells(entry, 'train_val', budget)} | {ato_cell} | {profile_cell} |")
    lines += [
        "",
        f"Chuyển giao của quy trình đặt trước (khớp/10.000 trên test ≤ {transfer['factor']:g} lần ngân sách = {transfer['limit']:g}): **giữ được {len(transfer['held'])}**, **không giữ được {len(transfer['failed'])}** "
        f"({', '.join(f'`{n}`' for n in transfer['failed']) or '—'}).",
        "",
        "Bậc chọn được ở ngân sách 2 / 5 / 10 — chỉ train | train ∧ val (số thứ tự bậc từ lỏng đến chặt; — = không chọn được): " + "; ".join(
            f"`{name}` " + " / ".join("—" if entry["selected"]["train_only"][str(b)] is None else str(entry["selected"]["train_only"][str(b)]) for b in payload["budgets"]) + " | "
            + " / ".join("—" if entry["selected"]["train_val"][str(b)] is None else str(entry["selected"]["train_val"][str(b)]) for b in payload["budgets"])
            for name, entry in ladders.items()
        ) + ".",
        "",
        "## 3. Bộ luật gộp (có ít nhất một luật khớp)",
        "",
        "`mặc định (enforce)` = các luật mặc định enforce ở giá trị mặc định (chính là bộ luật của MR9 nhưng đo trên khung mẫu ML); `chỉ train (enforce)` = các luật enforce ở bậc của quy trình đặt trước; "
        "`hồ sơ (enforce)` = quy trình sửa, trừ các bậc thang bị loại; `hồ sơ (cả shadow)` thêm các luật mặc định shadow (`country_hop`, `rare_network_login`) nếu chọn được.",
        "",
        "| Bộ luật | Phân vùng | khớp/10.000 | recall dòng tấn công |",
        "|---|---|---|---|",
    ]
    labels = {"default_enforce": "mặc định (enforce)", "train_only_enforce": "chỉ train (enforce)", "tuned_enforce": "hồ sơ (enforce)", "tuned_all": "hồ sơ (cả shadow)"}
    for key, label in labels.items():
        s = payload["sets"][key]
        for part in RT.PARTITIONS:
            ci = s.get("test_ci", {}) if part == "test" else {}
            lines.append(f"| {label} | {part} | {_fa(s[part]['fa10k'])}{_ci(ci.get('fa10k'), _fa)} | {_pct(s[part]['recall'])}{_ci(ci.get('recall'), _pct)} |")
    lines += [
        "",
        f"ATO ({payload['n_ato']['past']} quá khứ trước 09/2020 và {payload['n_ato']['future']} tương lai; **`rare_network_login` vòng tròn với cách RBA sinh ATO**, xem ghi chú luật):",
        "",
        "| Bộ luật | ATO quá khứ | ATO tương lai | ATO tất cả |",
        "|---|---|---|---|",
    ]
    for key, label in labels.items():
        counts = payload["sets"][key]["ato"]
        lines.append(f"| {label} | {_ato(counts, 'past')} | {_ato(counts, 'future')} | {_ato(counts, 'all')} |")

    lines += [
        "",
        "## 4. Bậc thang bị loại khỏi hồ sơ cấu hình",
        "",
        "Chọn được bậc ở train (và val) nhưng không đưa vào hồ sơ vì lý do CƠ CHẾ dưới đây; số đo dẫn ra để tự kiểm tra (khớp/10.000 ở bậc mặc định và ở bậc quy trình sửa chọn, theo train → val → test → late).",
        "",
        "| Bậc thang | Lý do | Bậc mặc định | Bậc quy trình sửa chọn |",
        "|---|---|---|---|",
    ]
    for name, reason in excluded.items():
        entry = ladders.get(name)
        if entry is None:
            continue
        trail = lambda row: " → ".join(_fa(row[p]["fa10k"]) for p in RT.PARTITIONS)
        d = entry["default_rung"]
        chosen = entry["selected"]["train_val"][str(budget)]
        default_cell = f"`{entry['rungs'][d - 1]['params']}`: {trail(entry['rungs'][d - 1])}" if d else "—"
        chosen_cell = f"`{entry['rungs'][chosen - 1]['params']}`: {trail(entry['rungs'][chosen - 1])}" if chosen is not None else "không chọn được"
        lines.append(f"| `{name}` | {reason} | {default_cell} | {chosen_cell} |")
    unusable = [n for n, e in ladders.items() if e["selected"]["train_val"][str(budget)] is None]
    if unusable:
        lines += ["", "Không chọn được bậc nào ở ngân sách chính (riêng ngưỡng không đủ; cần thêm điều kiện, ví dụ chuẩn hoá theo lưu lượng): " + ", ".join(f"`{n}`" for n in unusable) + ". Trong hồ sơ, luật mất hết phạm vi chuyển sang `shadow`."]

    lines += ["", "## 5. Chi tiết từng bậc thang", "", "◀ = bậc mặc định; ✔ = bậc chọn của quy trình đặt trước (chỉ train); ✅ = bậc chọn của quy trình sửa (train ∧ val). Các cột phân vùng: khớp/10.000 | recall dòng tấn công.", ""]
    for name, entry in ladders.items():
        only, both = entry["selected"]["train_only"][str(budget)], entry["selected"]["train_val"][str(budget)]
        lines += [
            f"#### `{name}`" + (f" — {entry['note']}" if entry["note"] else ""),
            "",
            "| Bậc | Tham số | train | val | test | late | ATO quá khứ | ATO tương lai |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for r in entry["rungs"]:
            mark = (" ◀" if r["rung"] == entry["default_rung"] else "") + (" ✔" if r["rung"] == only else "") + (" ✅" if r["rung"] == both else "")
            cells = " | ".join(f"{_fa(r[p]['fa10k'])} \\| {_pct(r[p]['recall'])}" for p in RT.PARTITIONS)
            lines.append(f"| {r['rung']}{mark} | `{r['params']}` | {cells} | {_ato(r['ato'], 'past')} | {_ato(r['ato'], 'future')} |")
        lines.append("")

    lines += ["## 6. Luật không đánh giá được trên RBA", "", "| Luật | Lý do |", "|---|---|"]
    lines += [f"| `{rule_id}` | {reason} |" for rule_id, reason in payload["not_evaluable"].items()]
    lines += [
        "",
        "## 7. Giới hạn",
        "",
        "- Quét một chiều cho mỗi luật; tổ hợp nhiều tham số chưa được tối ưu chung. Số tên khác nhau đếm tối đa 200 (`indexes.CAP`) nên bậc chặt nhất của hai luật phạm vi ASN dừng ở 200.",
        "- Bậc chọn được ngay cả ở bậc lỏng nhất (bậc 1) nghĩa là bậc thang chưa đủ lỏng để thấy điểm cân bằng; bậc không chọn được nghĩa là riêng ngưỡng không đủ, luật cần thêm điều kiện (ví dụ chuẩn hoá theo lưu lượng của nhà mạng).",
        "- Thời gian trong RBA có thành phần ngẫu nhiên, quốc gia gán ngẫu nhiên, User-Agent tổng hợp đổi liên tục (khiến `dormant_account_login` và `rare_network_login` báo nhiều) — xem [`rule-replay.md`](rule-replay.md) mục 1 và 5.",
        "- Giai đoạn `late` (12/2020–02/2021) có phân phối đổi so với train (lưu lượng tấn công tăng, tỉ lệ đăng nhập thành công giảm): chênh lệch train → late cho biết ngưỡng chịu trôi phân phối đến đâu.",
    ]
    return "\n".join(lines).rstrip("\n") + "\n"


def run(levels_path: Path = RT.LEVELS_PARQUET, doc_path: Path = RT.DOC_PATH, json_path: Path = RT.TUNING_JSON, profile_path: Path = RT.PROFILE_PATH) -> int:
    print("nạp bảng mô hình và mức bậc thang …", flush=True)
    frame = RT.load_frame(levels_path)
    print(f"{len(frame):,} dòng; tính bảng bậc thang, chọn bậc, khoảng tin cậy …", flush=True)
    payload = build_payload(frame)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=1, default=float), encoding="utf-8")
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    profile_path.write_text(json.dumps(payload["profile"], ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    doc_path.write_text(render(payload), encoding="utf-8", newline="\n")
    print(f"đã ghi {doc_path}, {profile_path} và {json_path}")
    return 0
