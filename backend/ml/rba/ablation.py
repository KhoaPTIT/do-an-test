"""Ablation theo nhóm đặc trưng (MR7):  python -m ml.rba.ablation [attack-ip|sim|if|sim-extra|all] [--n-boot N]

Mục đích: chứng minh mô hình KHÔNG dựa vào một lối tắt. Với mỗi mô hình, huấn luyện lại (cùng siêu tham số, hạt giống, quy tắc dừng
sớm trên val) trong các cấu hình:
  - `tat_ca`            : cả 50 đặc trưng (đối chứng, phải khớp mô hình đã lưu);
  - `bo:<nhóm>`         : bỏ MỘT nhóm đặc trưng (8 nhóm) — nhóm nào bỏ đi làm hiệu năng sụp = mô hình dựa vào nhóm đó;
  - `chi:<nhóm>`        : CHỈ dùng một nhóm — nhóm nào một mình đã đủ = tín hiệu nằm ở đó;
  - `bo_top1`, `bo_top3`: bỏ 1 và 3 đặc trưng quan trọng nhất của mô hình đối chứng — kiểm tra phụ thuộc vào một đặc trưng đơn lẻ.

Ba mô hình: `gbm_attack_ip` (chấm trên `attack_ip/test`), `gbm_attacker_sim` (chấm trên kẻ tấn công mô phỏng và ATO thật) và
Isolation Forest (chấm trên ATO thật — nhóm đặc trưng nào làm nên khả năng bắt ATO). Đọc kết quả cùng bảng kiểm định dấu vân tay
(`python -m ml.rba.audit`): nhóm nhịp/lịch sử/hạ tầng KHÔNG được là nguồn sức mạnh của mô hình học từ kẻ tấn công mô phỏng.
"""

from __future__ import annotations

import json
import sys
import time

import numpy as np
import pandas as pd

from ml.rba import baselines, eval_tasks, models
from ml.rba import metrics as M
from ml.rba.eval_tasks import ATTACKERS_PARQUET, ATTACKERS_TRAINVAL_PARQUET
from ml.rba.features import FEATURE_GROUPS, FEATURE_NAMES
from ml.rba.holdout import OUT_DIR

METRICS = ("roc_auc", "pr_auc", "recall@fpr=0.01", "recall@fpr=0.001")
IF_KWARGS = dict(n_estimators=100, max_samples=1024, sample_rows=200_000)  # nhẹ hơn mô hình chính để chạy 17 cấu hình; đối chứng dùng cùng cấu hình


def feature_configs(top_features: list[str] | None = None) -> dict[str, list[str]]:
    """Tên cấu hình -> danh sách đặc trưng (giữ thứ tự FEATURE_NAMES)."""
    everything = list(FEATURE_NAMES)
    configs = {"tat_ca": everything}
    for group, members in FEATURE_GROUPS.items():
        configs[f"bo:{group}"] = [f for f in everything if f not in members]
    for group, members in FEATURE_GROUPS.items():
        configs[f"chi:{group}"] = [f for f in everything if f in members]
    if top_features:
        configs["bo_top1"] = [f for f in everything if f != top_features[0]]
        configs["bo_top3"] = [f for f in everything if f not in top_features[:3]]
    return configs


def _union(*groups: str) -> list[str]:
    return [f for f in FEATURE_NAMES if any(f in FEATURE_GROUPS[g] for g in groups)]


def _minus(*groups: str) -> list[str]:
    return [f for f in FEATURE_NAMES if not any(f in FEATURE_GROUPS[g] for g in groups)]


# Cấu hình bổ sung cho mô hình học từ kẻ tấn công MÔ PHỎNG. Kẻ tấn công mô phỏng hoà lẫn về hạ tầng theo thiết kế (audit: các nhóm
# độ hiếm/hạ tầng ≈ 0,5), nên các nhóm đó chỉ có thể dạy mô hình rằng "hạ tầng lạ = an toàn". Hai cấu hình dưới đây kiểm tra giả thuyết ấy.
EXTRA_SIM_CONFIGS = {
    "chi_quan_he_voi_lich_su": _union("novelty", "freeman", "rhythm", "history"),
    "bo:rarity+infra_asn": _minus("rarity", "infra_asn"),
    "bo:rarity+infra_asn+infra_ip": _minus("rarity", "infra_asn", "infra_ip"),
}


def summarize(frame: pd.DataFrame, score: np.ndarray, n_boot: int) -> dict:
    result = M.evaluate(frame["y"].to_numpy(), score, frame["pop_weight"].to_numpy(), frame["cluster"].to_numpy(), n_boot=n_boot, seed=0)
    return {k: {"value": result.values[k], "ci95": list(result.ci[k])} for k in METRICS}


def run_gbm_ablation(kind: str, df: pd.DataFrame, trainval: pd.DataFrame | None, attackers_test: pd.DataFrame | None, n_boot: int = 100, rounds: int = 1500, log=print, only_configs: dict[str, list[str]] | None = None) -> dict:
    """`kind`: "attack_ip" (nhãn Is Attack IP) hoặc "sim" (kẻ tấn công mô phỏng). `only_configs`: chỉ chạy các cấu hình này (cùng đối chứng)."""
    started = time.time()
    tasks = eval_tasks.build_tasks(df, attackers_test)
    if kind == "attack_ip":
        train_set, val_set = models.attack_ip_sets(df)
        frames = {"attack_ip/test": tasks["attack_ip/test"].frame}
    else:
        train_set, val_set = models.simulated_attacker_sets(df, trainval)
        frames = {name: tasks[name].frame for name in ("attacker/naive", "attacker/vpn", "attacker/targeted", "ato/future")}

    def fit(name: str, features: list[str]) -> models.GbmScorer:
        return models.train_gbm(f"abl_{kind}_{name}", features, train_set, val_set, rounds=rounds)

    baseline = fit("tat_ca", list(FEATURE_NAMES))
    top = [entry["feature"] for entry in baseline.importance(top=3)]
    rows = []
    configs = {"tat_ca": list(FEATURE_NAMES), **only_configs} if only_configs is not None else feature_configs(top)
    for name, features in configs.items():
        model = baseline if name == "tat_ca" else fit(name, features)
        rows.append(
            {
                "config": name, "n_features": len(features), "best_iteration": model.meta["best_iteration"],
                "removed": None if name.startswith("chi:") else sorted(set(FEATURE_NAMES) - set(features)),
                "results": {task: summarize(frame, model(frame), n_boot) for task, frame in frames.items()},
            }
        )
        head = next(iter(rows[-1]["results"]))
        log(f"  [{time.time() - started:5.0f}s] {kind:9s} {name:16s} {len(features):2d} đặc trưng | {head}: recall@1% {rows[-1]['results'][head]['recall@fpr=0.01']['value']:.1%}")
    return {"kind": kind, "top_features": top, "tasks": list(frames), "rows": rows}


def run_if_ablation(df: pd.DataFrame, n_boot: int = 200, log=print) -> dict:
    started = time.time()
    tasks = eval_tasks.build_tasks(df)
    frames = {name: tasks[name].frame for name in ("ato/future", "ato/all")}
    rows = []
    for name, features in feature_configs().items():
        forest = baselines.IsolationForestScorer(features=features, **IF_KWARGS).fit(df)
        rows.append({"config": name, "n_features": len(features), "results": {task: summarize(frame, forest(frame), n_boot) for task, frame in frames.items()}})
        head = rows[-1]["results"]["ato/future"]
        log(f"  [{time.time() - started:5.0f}s] if {name:16s} {len(features):2d} đặc trưng | ato/future: AUC {head['roc_auc']['value']:.3f} recall@1% {head['recall@fpr=0.01']['value']:.1%}")
    return {"kind": "if", "tasks": list(frames), "rows": rows}


# ------------------------------------------------------------------------------------------- bảng tài liệu

_LABELS = {
    "tat_ca": "tất cả (đối chứng)", "bo_top1": "bỏ đặc trưng quan trọng nhất", "bo_top3": "bỏ 3 đặc trưng quan trọng nhất",
    "chi_quan_he_voi_lich_su": "chỉ các nhóm quan hệ với lịch sử (`novelty`, `freeman`, `rhythm`, `history`)",
}


def config_label(name: str) -> str:
    if name in _LABELS:
        return _LABELS[name]
    action, group = name.split(":")
    return f"{'bỏ' if action == 'bo' else 'chỉ'} nhóm `{group.replace('+', '` + `')}`"


def ablation_markdown(result: dict, metric: str = "recall@fpr=0.01") -> str:
    """Mỗi dòng một cấu hình; mỗi cột một bài; ô = giá trị và thay đổi so với đối chứng (điểm phần trăm hoặc điểm AUC)."""
    tasks = result["tasks"]
    percent = metric.startswith("recall")
    base = {t: result["rows"][0]["results"][t][metric]["value"] for t in tasks}

    def cell(value, ref):
        if percent:
            return f"{value:.1%} ({(value - ref) * 100:+.1f})"
        return f"{value:.3f} ({value - ref:+.3f})"

    lines = ["| Cấu hình | Số đặc trưng | " + " | ".join(f"`{t}`" for t in tasks) + " |", "|---|---|" + "---|" * len(tasks)]
    for row in result["rows"]:
        cells = [cell(row["results"][t][metric]["value"], base[t]) for t in tasks]
        lines.append(f"| {config_label(row['config'])} | {row['n_features']} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


# --------------------------------------------------------------------------------------------- dòng lệnh


def main() -> int:
    which = (sys.argv[1] if len(sys.argv) > 1 else "all").lower()
    n_boot = int(sys.argv[sys.argv.index("--n-boot") + 1]) if "--n-boot" in sys.argv else 100
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for path in (ATTACKERS_TRAINVAL_PARQUET, ATTACKERS_PARQUET):
        if not path.is_file():
            print(f"Thiếu {path} — chạy `python -m ml.rba.attackers` trước.")
            return 1
    df = eval_tasks.add_population_weights(eval_tasks.load_model_table())
    trainval, attackers_test = pd.read_parquet(ATTACKERS_TRAINVAL_PARQUET), pd.read_parquet(ATTACKERS_PARQUET)
    log = lambda m: print(m, flush=True)
    jobs = {
        "attack-ip": ("ablation_attack_ip.json", lambda: run_gbm_ablation("attack_ip", df, None, attackers_test, n_boot=n_boot, log=log)),
        "sim": ("ablation_sim.json", lambda: run_gbm_ablation("sim", df, trainval, attackers_test, n_boot=n_boot, log=log)),
        "if": ("ablation_if_ato.json", lambda: run_if_ablation(df, n_boot=max(n_boot, 200), log=log)),
        "sim-extra": ("ablation_sim_extra.json", lambda: run_gbm_ablation("sim", df, trainval, attackers_test, n_boot=n_boot, log=log, only_configs=EXTRA_SIM_CONFIGS)),
    }
    for name, (filename, run) in jobs.items():
        if which != name and not (which == "all" and name != "sim-extra"):
            continue
        result = run()
        (OUT_DIR / filename).write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"\n## {name}\n" + ablation_markdown(result) + "\n", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
