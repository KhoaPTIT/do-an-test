"""Bảng chồng lấn luật / mô hình (MR10): chỉ luật bắt, chỉ mô hình bắt, cả hai, cả hai bỏ sót — bằng chứng cho việc kết hợp (hybrid).

    cd backend
    venv\\Scripts\\python.exe -m ml.rba.rule_overlap        # sau `python -m ml.rba.rule_tuning collect` và `tune`; ghi docs/rule-ml-overlap.md

Cả hai bên chấm ĐÚNG cùng các dòng, cùng trọng số dân số, cùng định nghĩa dương/âm của khung đánh giá ML (`eval_tasks.build_tasks`):
  - mô hình: `hybrid_cp2`, ngưỡng chọn trên đăng nhập hợp lệ thành công của **val** cho FPR 1% và 0,1% (như MR8b);
  - luật: bộ luật đã tinh chỉnh (rule_tuning.py, chọn trên **train**); một dòng "bị luật báo" khi có ít nhất một luật của bộ khớp.

Câu hỏi "có nên kết hợp" không thể trả lời bằng cách so recall khi tổng tỉ lệ báo nhầm khác nhau (gộp hai bộ báo nhiều hơn mỗi bộ riêng). Nên bảng "bằng chứng" so recall của bộ gộp với recall của
CHỈ mô hình được nới ngưỡng đến đúng tổng tỉ lệ báo nhầm của bộ gộp trên cùng tập âm tính: nếu bộ gộp vẫn hơn thì luật đóng góp thứ mà nới ngưỡng mô hình không thay thế được.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

import joblib
import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from app.detection.engine import REGISTRY
from ml.rba import eval_tasks, metrics as M, models
from ml.rba import rule_tuning as RT

DOC_PATH = RT.DOCS_DIR / "rule-ml-overlap.md"
OVERLAP_JSON = RT.ARTIFACT_DIR / "overlap.json"
HYBRID_NAME = "hybrid_cp2"
FPR_LEVELS = (0.01, 0.001)
TASKS = ("attack_ip/test", "attack_ip/late", "ato/future", "ato/all")
PRIMARY_SET = "tuned_enforce"
N_BOOT = 400


# ------------------------------------------------------------------------------------------------ tính toán (thuần numpy)


def cluster_bootstrap(cluster: np.ndarray, weights: np.ndarray, indicators: Mapping[str, np.ndarray], n_boot: int = N_BOOT, seed: int = 0) -> np.ndarray:
    """Ma trận `(n_boot, số chỉ số)` các tỉ lệ có trọng số `Σ w·I / Σ w` khi lấy mẫu lại theo cụm (chỉ phía dương tính: âm tính hàng trăm nghìn dòng nên bất định không đáng kể)."""
    codes, _ = pd.factorize(pd.Series(cluster).fillna("?").to_numpy())
    n = int(codes.max()) + 1
    by = lambda values: np.bincount(codes, weights=values, minlength=n)
    den = by(weights)
    nums = np.column_stack([by(weights * np.asarray(ind, dtype=float)) for ind in indicators.values()])
    rng = np.random.default_rng(seed)
    out = np.empty((n_boot, nums.shape[1]))
    for b in range(n_boot):
        pick = rng.integers(0, n, n)
        out[b] = nums[pick].sum(axis=0) / max(den[pick].sum(), 1e-12)
    return out


def analyse_block(
    y: np.ndarray, weight: np.ndarray, ml_score: np.ndarray, tau: float, rule: np.ndarray, cluster: np.ndarray, n_boot: int = N_BOOT, seed: int = 0
) -> dict[str, Any]:
    """MỘT khối (bài × mức FPR của mô hình × bộ luật): phân rã dương tính thành cả hai/chỉ mô hình/chỉ luật/cả hai bỏ sót, tỉ lệ báo nhầm của từng bên và của bộ gộp, và recall của
    CHỈ mô hình khi nới ngưỡng đến đúng tỉ lệ báo nhầm của bộ gộp (và của luật)."""
    pos, neg = y, ~y
    ml = ml_score > tau
    pw, nw = weight[pos], weight[neg]
    total_pos, total_neg = float(pw.sum()), float(nw.sum())
    ml_p, rule_p, ml_n, rule_n = ml[pos], rule[pos], ml[neg], rule[neg]
    frac_p = lambda mask: float(pw[mask].sum() / total_pos)
    frac_n = lambda mask: float(nw[mask].sum() / total_neg)

    fpr = {"ml": frac_n(ml_n), "rules": frac_n(rule_n), "union": frac_n(ml_n | rule_n), "both": frac_n(ml_n & rule_n), "ml_only": frac_n(ml_n & ~rule_n), "rules_only": frac_n(~ml_n & rule_n)}
    ref = M.NegativeReference.build(ml_score[neg], nw)
    s_union, s_rules = ref.exceeding_score(fpr["union"]), ref.exceeding_score(fpr["rules"])
    matched_union, matched_rules = ml_score[pos] > s_union, ml_score[pos] > s_rules

    recall = {
        "ml": frac_p(ml_p), "rules": frac_p(rule_p), "union": frac_p(ml_p | rule_p),
        "ml_matched_to_union": frac_p(matched_union), "ml_matched_to_rules": frac_p(matched_rules),
    }
    recall["gain_over_matched_ml"] = recall["union"] - recall["ml_matched_to_union"]
    indicators = {"ml": ml_p, "rules": rule_p, "union": ml_p | rule_p, "matched": matched_union, "matched_rules": matched_rules}
    samples = cluster_bootstrap(cluster[pos], pw, indicators, n_boot, seed)
    col = {name: i for i, name in enumerate(indicators)}
    ci = {name: [float(np.percentile(samples[:, col[key]], 2.5)), float(np.percentile(samples[:, col[key]], 97.5))] for name, key in
          (("ml", "ml"), ("rules", "rules"), ("union", "union"), ("ml_matched_to_union", "matched"), ("ml_matched_to_rules", "matched_rules"))}
    gain = samples[:, col["union"]] - samples[:, col["matched"]]
    ci["gain_over_matched_ml"] = [float(np.percentile(gain, 2.5)), float(np.percentile(gain, 97.5))]
    return {
        "n_pos": int(pos.sum()), "n_neg": int(neg.sum()), "recall": recall, "recall_ci": ci, "fpr": fpr,
        "positives": {"both": frac_p(ml_p & rule_p), "ml_only": frac_p(ml_p & ~rule_p), "rules_only": frac_p(~ml_p & rule_p), "neither": frac_p(~ml_p & ~rule_p)},
        "counts": {"both": int((ml_p & rule_p).sum()), "ml_only": int((ml_p & ~rule_p).sum()), "rules_only": int((~ml_p & rule_p).sum()), "neither": int((~ml_p & ~rule_p).sum())},
    }


def rule_attribution(y: np.ndarray, weight: np.ndarray, ml_score: np.ndarray, tau: float, per_ladder: Mapping[str, np.ndarray]) -> list[dict[str, Any]]:
    """Với các dương tính mà mô hình BỎ SÓT: phần (trọng số) và số ca mỗi luật đã chọn bắt được."""
    missed = y & ~(ml_score > tau)
    total = float(weight[missed].sum())
    rows = []
    for name, flag in per_ladder.items():
        hit = missed & flag
        rows.append({"ladder": name, "share": float(weight[hit].sum() / total) if total else 0.0, "count": int(hit.sum())})
    return sorted(rows, key=lambda r: (-r["share"], r["ladder"]))


# ------------------------------------------------------------------------------------------------ nạp dữ liệu


def load_chosen(tuning_json: Path = RT.TUNING_JSON) -> dict[str, dict[str, int]]:
    """Các bộ luật (`default_enforce`, `tuned_enforce`, `tuned_all`) đã chọn ở bước `tune`: tên bậc thang -> bậc."""
    payload = json.loads(tuning_json.read_text(encoding="utf-8"))
    return {name: {k: int(v) for k, v in s["members"].items()} for name, s in payload["sets"].items()}


def rule_flags(frame: pd.DataFrame, levels: pd.DataFrame, chosen: Mapping[str, int]) -> tuple[np.ndarray, dict[str, np.ndarray]]:
    """Cờ "bị luật báo" của các dòng `frame` (theo `row_id`) cho bộ luật `chosen` và cờ của từng bậc thang trong bộ."""
    by_name = RT.ladder_by_name()
    rows = frame["row_id"].to_numpy()
    per = {}
    for name, rung in chosen.items():
        values = levels[by_name[name].column].reindex(rows).to_numpy(dtype=float)
        per[name] = np.nan_to_num(values, nan=0.0) >= rung
    union = np.any(list(per.values()), axis=0) if per else np.zeros(len(rows), dtype=bool)
    return union, per


def build_payload(tasks: Mapping[str, Any], scores: Mapping[str, np.ndarray], thresholds: Mapping[float, float], levels: pd.DataFrame, sets: Mapping[str, Mapping[str, int]], n_boot: int = N_BOOT) -> dict[str, Any]:
    payload: dict[str, Any] = {"hybrid": HYBRID_NAME, "thresholds": {str(k): float(v) for k, v in thresholds.items()}, "sets": {k: dict(v) for k, v in sets.items()}, "tasks": {}}
    for name in TASKS:
        if name not in tasks:
            continue
        frame = tasks[name].frame
        y, w, ml = frame["y"].to_numpy(dtype=bool), frame["pop_weight"].to_numpy(dtype=float), np.asarray(scores[name], dtype=float)
        cluster = frame["cluster"].to_numpy()
        entry: dict[str, Any] = {"description": tasks[name].description, "blocks": {}}
        for set_name, chosen in sets.items():
            flag, per = rule_flags(frame, levels, chosen)
            for level in FPR_LEVELS:
                key = f"{set_name}@{level:g}"
                entry["blocks"][key] = analyse_block(y, w, ml, thresholds[level], flag, cluster, n_boot)
                if set_name == PRIMARY_SET:
                    entry["blocks"][key]["missed_by_ml"] = rule_attribution(y, w, ml, thresholds[level], per)
        payload["tasks"][name] = entry
    return payload


# ------------------------------------------------------------------------------------------------ định dạng


def _pct(x: float, digits: int = 1) -> str:
    return f"{x:.{digits}%}"


def _ci(pair, digits: int = 1) -> str:
    return f" [{pair[0]:.{digits}%}–{pair[1]:.{digits}%}]"


def _points(value: float, pair) -> str:
    """Chênh lệch tính bằng điểm phần trăm, kèm khoảng tin cậy; dấu chấm phẩy để không lẫn với dấu trừ."""
    lo, hi = pair[0] * 100, pair[1] * 100
    return f"{value * 100:+.1f} điểm [{lo:+.1f}; {hi:+.1f}]" + (" — khác 0" if lo > 0 or hi < 0 else "")


def render(payload: Mapping[str, Any]) -> str:
    thresholds = payload["thresholds"]
    lines = [
        "# Chồng lấn giữa luật và mô hình (MR10)",
        "",
        "> Báo cáo TỰ SINH bởi `python -m ml.rba.rule_overlap` (sau `collect` và `tune` của [`rule_tuning.py`](../backend/ml/rba/rule_tuning.py)) — đừng sửa tay. Mã: [`rule_overlap.py`](../backend/ml/rba/rule_overlap.py).",
        "",
        "## 1. Cách đọc",
        "",
        f"- **Mô hình:** `{payload['hybrid']}` (bản chốt ở CP2), ngưỡng chọn trên đăng nhập hợp lệ thành công của val cho FPR 1% ({thresholds['0.01']:.3f}) và 0,1% ({thresholds['0.001']:.3f}).",
        "- **Luật** (bốn bộ, cách chọn ở [`rule-tuning.md`](rule-tuning.md)): `default_enforce` = các luật mặc định enforce ở tham số mặc định; `train_only_enforce` = cùng các luật ở bậc chọn theo quy trình đặt trước (chỉ train, ngân sách 5 lần khớp/10.000 đăng nhập hợp lệ thành công); "
        f"`{PRIMARY_SET}` = quy trình sửa (train ∧ val) trừ các bậc thang bị loại — chính là hồ sơ cấu hình; `tuned_all` thêm luật mặc định shadow nếu chọn được. "
        "Một dòng \"bị luật báo\" khi có ít nhất một luật của bộ khớp (luật báo cả lần thất bại, mô hình chủ yếu chấm lần thành công).",
        "- **Cùng dòng, cùng trọng số, cùng định nghĩa dương/âm** với khung đánh giá ML: tài khoản có thật trong mẫu phân tầng, `pop_weight`, dòng tấn công theo nhóm IP của giai đoạn; `ato/*` so ATO với đăng nhập hợp lệ thành công. "
        "Kẻ tấn công mô phỏng không có ở đây: chúng chỉ đăng nhập thành công một lần, vô hình với các luật đếm lần sai.",
        "- **Bảng chồng lấn** chia mọi dòng dương tính (tính theo trọng số) thành: *cả hai* bắt, *chỉ mô hình*, *chỉ luật*, *cả hai bỏ sót*. **Bảng bằng chứng** so recall của bộ gộp với recall của CHỈ mô hình được nới ngưỡng đến đúng tổng "
        "tỉ lệ báo nhầm của bộ gộp trên cùng tập âm tính — so công bằng, vì gộp hai bộ luôn báo nhầm nhiều hơn mỗi bộ riêng. Cột \"Bộ gộp hơn\" ÂM nghĩa là chỉ nới ngưỡng mô hình còn tốt hơn thêm luật.",
        "- ⚠️ Khoảng tin cậy 95% lấy mẫu lại theo cụm (IP cho `attack_ip/*`, tài khoản cho `ato/*`); ATO chỉ có 38 (tương lai) và 130 (tất cả) ca nên khoảng rất rộng. 38 ca tương lai đã bị nhìn ở MR7. "
        "`rare_network_login` (mặc định shadow) vòng tròn với cách RBA sinh ATO, nên bộ `tuned_all` trên ATO không dùng để tuyên bố. `ato/all` gồm cả train, nơi luật và mô hình đều được chọn/huấn luyện (lạc quan).",
        "",
    ]
    lines += [
        "## 2. Tóm tắt",
        "",
        "Mỗi dòng: bộ luật kết hợp với mô hình ở mức FPR nêu ở cột 2. *Hơn* = recall bộ gộp trừ recall CHỈ mô hình được nới ngưỡng đến cùng tổng báo nhầm (\"khác 0\" khi khoảng tin cậy 95% không chứa 0).",
        "",
        "| Bài | FPR mô hình | Bộ luật | Recall mô hình | Recall luật | Recall bộ gộp | Báo nhầm bộ gộp | Recall CHỈ mô hình cùng báo nhầm | **Hơn** |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for task_name, task in payload["tasks"].items():
        for set_name in (PRIMARY_SET, "default_enforce"):
            for level in FPR_LEVELS:
                b = task["blocks"].get(f"{set_name}@{level:g}")
                if b is None:
                    continue
                r, ci = b["recall"], b["recall_ci"]
                lines.append(
                    f"| `{task_name}` | {level:.1%} | `{set_name}` | {_pct(r['ml'])} | {_pct(r['rules'])} | {_pct(r['union'])} | {_pct(b['fpr']['union'], 2)} | {_pct(r['ml_matched_to_union'])} | "
                    f"**{_points(r['gain_over_matched_ml'], ci['gain_over_matched_ml'])}** |"
                )
    lines.append("")
    for task_name, task in payload["tasks"].items():
        lines += [f"## Bài `{task_name}`", "", task["description"], ""]
        lines += [
            "### Chồng lấn (phần dương tính theo trọng số) — bộ luật `" + PRIMARY_SET + "`",
            "",
            "| Mức FPR của mô hình | Cả hai | Chỉ mô hình | Chỉ luật | Cả hai bỏ sót | Báo nhầm: mô hình | luật | gộp |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for level in FPR_LEVELS:
            b = task["blocks"][f"{PRIMARY_SET}@{level:g}"]
            p, f = b["positives"], b["fpr"]
            lines.append(
                f"| {level:.1%} (n = {b['n_pos']:,}) | {_pct(p['both'])} ({b['counts']['both']:,}) | {_pct(p['ml_only'])} ({b['counts']['ml_only']:,}) | {_pct(p['rules_only'])} ({b['counts']['rules_only']:,}) | "
                f"{_pct(p['neither'])} ({b['counts']['neither']:,}) | {_pct(f['ml'], 2)} | {_pct(f['rules'], 2)} | {_pct(f['union'], 2)} |"
            )
        lines += [
            "",
            "### Bằng chứng cho hybrid: bộ gộp so với CHỈ mô hình ở cùng tổng tỉ lệ báo nhầm",
            "",
            "| Mức FPR của mô hình | Bộ luật | Recall mô hình | Recall luật | Recall bộ gộp | Báo nhầm bộ gộp | Recall CHỈ mô hình cùng báo nhầm | **Bộ gộp hơn** |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for set_name in payload["sets"]:
            for level in FPR_LEVELS:
                b = task["blocks"][f"{set_name}@{level:g}"]
                r, ci = b["recall"], b["recall_ci"]
                lines.append(
                    f"| {level:.1%} | `{set_name}` | {_pct(r['ml'])}{_ci(ci['ml'])} | {_pct(r['rules'])}{_ci(ci['rules'])} | {_pct(r['union'])}{_ci(ci['union'])} | {_pct(b['fpr']['union'], 2)} | "
                    f"{_pct(r['ml_matched_to_union'])}{_ci(ci['ml_matched_to_union'])} | **{_points(r['gain_over_matched_ml'], ci['gain_over_matched_ml'])}** |"
                )
        lines += ["", "### Luật nào bắt phần mô hình bỏ sót (bộ `" + PRIMARY_SET + "`)", "", "| Mức FPR của mô hình | Luật (bậc thang) | Phần ca mô hình bỏ sót mà luật bắt | Số dòng |", "|---|---|---|---|"]
        for level in FPR_LEVELS:
            rows = [r for r in task["blocks"][f"{PRIMARY_SET}@{level:g}"]["missed_by_ml"] if r["count"] > 0][:6]
            for r in rows or [{"ladder": "—", "share": 0.0, "count": 0}]:
                lines.append(f"| {level:.1%} | `{r['ladder']}` | {_pct(r['share'])} | {r['count']:,} |")
        lines.append("")
    lines += [
        "## Giới hạn",
        "",
        "- Chỉ RBA (tổng hợp): dòng tấn công là IP trong danh sách của bộ dữ liệu, không phải kẻ tấn công thích ứng; ATO của RBA có đặc điểm nhân tạo (nhà mạng hiếm).",
        "- Bộ luật đã chọn trên train theo ngân sách báo nhầm, mô hình chọn ngưỡng trên val — cả hai được báo cáo trên giai đoạn sau chúng, nhưng 38 ATO tương lai đã bị nhìn ở MR7.",
        "- Luật báo cả lần thất bại nên tỉ lệ báo nhầm của luật trong cùng bài lấy trên mọi dòng bình thường; ở `ato/*` mẫu số là đăng nhập hợp lệ thành công nên luật chỉ tính trên lần thành công ở đó.",
    ]
    return "\n".join(lines).rstrip("\n") + "\n"


# ------------------------------------------------------------------------------------------------ chạy


def run(levels_path: Path = RT.LEVELS_PARQUET, tuning_json: Path = RT.TUNING_JSON, doc_path: Path = DOC_PATH, json_path: Path = OVERLAP_JSON) -> int:
    from ml.rba.explain_eval import hybrid_thresholds

    print("nạp bảng mô hình, hybrid và mức bậc thang …", flush=True)
    df = eval_tasks.add_population_weights(eval_tasks.load_model_table())
    hybrid = joblib.load(models.ARTIFACT_DIR / f"{HYBRID_NAME}.joblib")
    thresholds = hybrid_thresholds(hybrid, df)
    tasks = {k: v for k, v in eval_tasks.build_tasks(df).items() if k in TASKS}
    print("chấm điểm mô hình trên các dòng của bài …", flush=True)
    scores = eval_tasks.score_all_tasks(hybrid, tasks)
    levels = pq.read_table(levels_path).to_pandas().set_index("row_id")
    payload = build_payload(tasks, scores, thresholds, levels, load_chosen(tuning_json))
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    doc_path.write_text(render(payload), encoding="utf-8", newline="\n")
    print(f"đã ghi {doc_path} và {json_path}")
    return 0


def render_only(json_path: Path = OVERLAP_JSON, doc_path: Path = DOC_PATH) -> int:
    """Dựng lại tài liệu từ số liệu đã tính (`overlap.json`), không nạp mô hình và không chấm điểm lại — khi chỉ đổi cách trình bày."""
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    doc_path.write_text(render(payload), encoding="utf-8", newline="\n")
    print(f"đã dựng lại {doc_path} từ {json_path}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m ml.rba.rule_overlap", description="Bảng chồng lấn luật/mô hình (MR10).")
    parser.add_argument("--render-only", action="store_true", help=f"chỉ dựng lại tài liệu từ {OVERLAP_JSON.name} đã có, không chấm điểm lại")
    args = parser.parse_args(sys.argv[1:] if argv is None else list(argv))
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError, OSError):
        pass
    return render_only() if args.render_only else run()


if __name__ == "__main__":
    sys.exit(main())
