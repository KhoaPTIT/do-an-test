"""Các bài kiểm tra chuẩn trên bảng đặc trưng RBA và bảng báo cáo (MR4).

Mọi mô hình/luật chấm điểm đi qua đúng cùng các bài này, nên số liệu so sánh được với nhau:

| Bài | Dương tính | Âm tính |
|---|---|---|
| `attack_ip/<val|test|late>` | dòng thuộc IP tấn công (có trọng số phục hồi tỉ lệ tự nhiên) | dòng bình thường cùng giai đoạn |
| `ato/future`  | 38 ca ATO từ 09/2020 (tương lai so với train/val) | đăng nhập hợp lệ thành công ở giai đoạn `test` |
| `ato/all`     | cả 141 ca ATO (trừ warm-up) — "nhìn lại", lạc quan hơn | đăng nhập hợp lệ thành công ở train+val+test |
| `attacker/<naive|vpn|targeted>` | đăng nhập của kẻ tấn công mô phỏng (attackers.py) | như `ato/future` |

"Đăng nhập hợp lệ thành công" = thành công, không thuộc IP tấn công, không phải ATO. Đăng nhập thành công từ IP
tấn công KHÔNG được coi là âm tính: chúng có thể là tấn công chưa gắn nhãn, đưa vào sẽ phạt oan mô hình.

Điểm càng cao càng đáng ngờ. Mô hình là một hàm `frame -> điểm` (xem scorers.py).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from ml.rba import metrics as M
from ml.rba import splits
from ml.rba.build_features import MODEL_TABLE_PARQUET
from ml.rba.features import FEATURE_NAMES
from ml.rba.paths import RBA_DATA_DIR
from ml.rba.sample import SAMPLE_PARQUET

ATTACKERS_PARQUET = RBA_DATA_DIR / "rba_attackers.parquet"
ATTACKERS_TRAINVAL_PARQUET = RBA_DATA_DIR / "rba_attackers_trainval.parquet"
REPORT_DIR = Path(__file__).resolve().parents[1] / "artifacts" / "rba_reports"

# Tỉ lệ lấy mẫu user theo tầng (ml/rba/sample.py); user có ATO được lấy 100%
STRATUM_SAMPLE_RATE = {"single": 0.05, "light": 0.10, "heavy": 0.25}

HISTORY_BUCKETS = (("chưa có lịch sử thành công", 0, 0), ("mỏng (1–4)", 1, 4), ("dày (≥5)", 5, 10**9))

Scorer = Callable[[pd.DataFrame], np.ndarray]


@dataclass
class Task:
    name: str
    description: str
    frame: pd.DataFrame  # cột đặc trưng + y (bool), weight, cluster
    excluded_note: str = ""


def load_model_table() -> pd.DataFrame:
    df = pq.read_table(MODEL_TABLE_PARQUET).to_pandas()
    ips = pq.read_table(SAMPLE_PARQUET, columns=["row_id", "ip"]).to_pandas()
    return df.merge(ips, on="row_id", how="left")


def add_population_weights(df: pd.DataFrame) -> pd.DataFrame:
    """Thêm cột `pop_weight`: trọng số quy về DÂN SỐ user (weight của dòng chia tỉ lệ lấy mẫu của tầng user).

    Mẫu lấy 25% user hoạt động nhiều nhưng chỉ 5% user chỉ có 1 lần đăng nhập, nên tỉ lệ báo nhầm đo trên mẫu
    thô lệch về user nhiều lịch sử. Mọi chỉ số dùng `pop_weight` để phản ánh đúng khi triển khai cho toàn bộ user.
    Bảng không có cột `stratum` (dữ liệu thử nghiệm nhỏ) thì `pop_weight` = `weight`."""
    out = df.copy()
    out["pop_weight"] = population_weights(out) if "stratum" in out else out["weight"].to_numpy(dtype=float)
    return out


def _legit_success(df: pd.DataFrame) -> pd.Series:
    return (df["cur_success"] == 1) & ~df["is_attack_ip"] & ~df["is_ato"]


def _with_labels(frame: pd.DataFrame, y, cluster) -> pd.DataFrame:
    out = frame.copy()
    out["y"] = np.asarray(y, dtype=bool)
    out["cluster"] = np.asarray(cluster)
    return out


def build_tasks(
    df: pd.DataFrame,
    attackers: pd.DataFrame | None = None,
    attackers_val: pd.DataFrame | None = None,
) -> dict[str, Task]:
    df = add_population_weights(df[~df["in_warmup"]])
    if attackers is not None:
        attackers = attackers.assign(pop_weight=1.0)  # mỗi đăng nhập giả là một cuộc tấn công giả định, trọng số 1
    if attackers_val is not None:
        attackers_val = attackers_val.assign(pop_weight=1.0)
    tasks: dict[str, Task] = {}

    for part in ("val", "test", "late"):
        sub = df[df["partition"] == part]
        tasks[f"attack_ip/{part}"] = Task(
            f"attack_ip/{part}",
            f"IP tấn công so với bình thường, giai đoạn {part} (có trọng số; cụm = IP)",
            _with_labels(sub, sub["is_attack_ip"], sub["ip"]),
        )

    legit_test = df[(df["partition"] == "test") & _legit_success(df)]
    ato = df[df["is_ato"]]
    ato_future = ato[(ato["ts"] >= splits.VAL_END) & (ato["ts"] < splits.TEST_END)]
    frame = pd.concat([legit_test, ato_future])
    tasks["ato/future"] = Task(
        "ato/future",
        f"{len(ato_future)} ATO tương lai (09–11/2020) so với đăng nhập hợp lệ thành công giai đoạn test",
        _with_labels(frame, frame["is_ato"], frame["user_id"]),
    )

    legit_all = df[df["partition"].isin(["train", "val", "test"]) & _legit_success(df)]
    frame = pd.concat([legit_all, ato])
    tasks["ato/all"] = Task(
        "ato/all",
        f"{len(ato)} ATO (nhìn lại, lạc quan hơn) so với đăng nhập hợp lệ thành công train+val+test",
        _with_labels(frame, frame["is_ato"], frame["user_id"]),
    )

    # Kẻ tấn công mô phỏng chỉ nhắm vào tài khoản đã có ít nhất 1 lần đăng nhập thành công (cần hồ sơ để mô phỏng),
    # nên âm tính tương ứng cũng chỉ gồm đăng nhập của tài khoản đã có lịch sử — nếu không, "tài khoản mới" thành lối tắt.
    legit_test_history = legit_test[legit_test["u_n_success"] >= 1]
    if attackers is not None:
        for kind in ("naive", "vpn", "targeted"):
            part = attackers[attackers["attacker_type"] == kind]
            if part.empty:
                continue
            frame = pd.concat([legit_test_history, part])
            y = np.r_[np.zeros(len(legit_test_history), dtype=bool), np.ones(len(part), dtype=bool)]
            cluster = np.r_[legit_test_history["user_id"].to_numpy(), part["user_id"].to_numpy()]
            tasks[f"attacker/{kind}"] = Task(
                f"attacker/{kind}",
                f"{len(part)} đăng nhập kẻ tấn công mô phỏng '{kind}' so với đăng nhập hợp lệ thành công của tài khoản ĐÃ CÓ LỊCH SỬ, giai đoạn test",
                _with_labels(frame, y, cluster),
            )
    if attackers_val is not None:
        legit_val = df[(df["partition"] == "val") & _legit_success(df) & (df["u_n_success"] >= 1)]
        for kind in ("naive", "vpn", "targeted"):
            part = attackers_val[attackers_val["attacker_type"] == kind]
            if part.empty:
                continue
            frame = pd.concat([legit_val, part])
            y = np.r_[np.zeros(len(legit_val), dtype=bool), np.ones(len(part), dtype=bool)]
            cluster = np.r_[legit_val["user_id"].to_numpy(), part["user_id"].to_numpy()]
            tasks[f"attacker_val/{kind}"] = Task(
                f"attacker_val/{kind}",
                f"[CHỌN MÔ HÌNH] {len(part)} đăng nhập kẻ tấn công mô phỏng '{kind}' giai đoạn val so với đăng nhập hợp lệ thành công của tài khoản đã có lịch sử, giai đoạn val",
                _with_labels(frame, y, cluster),
            )
    return tasks


def evaluate_task(task: Task, scorer: Scorer | None, n_boot: int = 500, seed: int = 0, scores: np.ndarray | None = None) -> dict:
    frame = task.frame
    score = np.asarray(scorer(frame) if scores is None else scores, dtype=float)
    weight = frame["pop_weight"].to_numpy() if "pop_weight" in frame and frame["pop_weight"].notna().all() else None
    result = M.evaluate(frame["y"].to_numpy(), score, weight, frame["cluster"].to_numpy(), n_boot=n_boot, seed=seed)
    out = {
        "task": task.name,
        "description": task.description,
        "n_pos": result.n_pos,
        "n_neg": result.n_neg,
        "metrics": {k: {"value": v, "ci95": list(result.ci[k])} for k, v in result.values.items()},
        "by_history": breakdown_by_history(frame, score, weight, fpr_target=0.01),
    }
    if "pop_weight" in frame and "stratum" in frame:
        out["alert_volume"] = [alert_volume(frame, score, target) for target in (0.90, 0.99)]
    return out


def point_metrics(task: Task, scores: np.ndarray) -> dict[str, float]:
    """Chỉ số điểm (không bootstrap) — nhanh, dùng để chọn mô hình trên val."""
    frame = task.frame
    y = frame["y"].to_numpy()
    w = frame["pop_weight"].to_numpy()
    ref = M.NegativeReference.build(scores[~y], w[~y])
    return M.compute_metrics(ref, scores[y], w[y])


def breakdown_by_history(frame: pd.DataFrame, score: np.ndarray, weight, fpr_target: float) -> list[dict]:
    """Với NGƯỠNG TOÀN CỤC cho FPR = fpr_target, mỗi nhóm lịch sử có recall và tỉ lệ báo nhầm bao nhiêu.

    Đây là điều xảy ra khi triển khai (một ngưỡng chung): user mới có bị thử thách oan nhiều hơn không?
    """
    y = frame["y"].to_numpy()
    w = np.ones(len(frame)) if weight is None else weight
    ref = M.NegativeReference.build(score[~y], w[~y])
    tau = ref.exceeding_score(fpr_target)
    history = frame["u_n_success"].to_numpy()

    rows = []
    for label, lo, hi in HISTORY_BUCKETS:
        in_bucket = (history >= lo) & (history <= hi)
        pos, neg = in_bucket & y, in_bucket & ~y
        rows.append(
            {
                "bucket": label,
                "n_pos": int(pos.sum()),
                "n_neg": int(neg.sum()),
                "recall": float(w[pos & (score > tau)].sum() / w[pos].sum()) if pos.any() else None,
                "false_alert_rate": float(w[neg & (score > tau)].sum() / w[neg].sum()) if neg.any() else None,
            }
        )
    return rows


def population_weights(frame: pd.DataFrame) -> np.ndarray:
    """Trọng số quy về TOÀN BỘ dân số user được chấm điểm: trọng số dòng chia tỉ lệ lấy mẫu của tầng user."""
    rate = frame["stratum"].map(STRATUM_SAMPLE_RATE).astype(float).where(~frame["forced"].astype(bool), 1.0)
    return frame["weight"].to_numpy() / rate.to_numpy()


def alert_volume(frame: pd.DataFrame, score: np.ndarray, recall_target: float) -> dict:
    """Ở ngưỡng bắt được recall_target ca tấn công, sẽ có bao nhiêu cảnh báo mỗi 1.000 lần đăng nhập và mỗi ngày
    (ước lượng cho toàn bộ dân số user RBA được chấm điểm, không tính tài khoản không tồn tại)."""
    y = frame["y"].to_numpy()
    pop = frame["pop_weight"].to_numpy()
    tau = M.threshold_for_recall(score[y], pop[y], recall_target)
    flagged = score >= tau
    days = max((frame["ts"].max() - frame["ts"].min()).total_seconds() / 86400, 1.0)
    return {
        "recall_target": recall_target,
        "alerts_per_1000_logins": float(1000 * pop[flagged].sum() / pop.sum()),
        "alerts_per_day": float(pop[flagged].sum() / days),
        "days": round(days, 1),
    }


def score_all_tasks(scorer: Scorer, tasks: dict[str, Task]) -> dict[str, np.ndarray]:
    """Chấm điểm MỘT LẦN cho hợp các dòng của mọi bài (nhiều bài dùng chung các dòng hợp lệ), rồi tách theo bài."""
    union = pd.concat([t.frame for t in tasks.values()]).drop_duplicates("row_id")
    values = np.asarray(scorer(union), dtype=float)
    by_row = pd.Series(values, index=union["row_id"].to_numpy())
    return {name: by_row.loc[t.frame["row_id"].to_numpy()].to_numpy() for name, t in tasks.items()}


def run_report(scorer_name: str, scorer: Scorer, tasks: dict[str, Task], n_boot: int = 500) -> dict:
    scores = score_all_tasks(scorer, tasks)
    return {
        "scorer": scorer_name,
        "features": len(FEATURE_NAMES),
        "tasks": [evaluate_task(t, None, n_boot, scores=scores[name]) for name, t in tasks.items()],
    }


def _fmt(metric: dict, pct: bool = True) -> str:
    v, (lo, hi) = metric["value"], metric["ci95"]
    return f"{v:.3f} [{lo:.3f}–{hi:.3f}]" if not pct else f"{v:.1%} [{lo:.1%}–{hi:.1%}]"


def to_markdown(report: dict) -> str:
    lines = [
        f"### {report['scorer']}",
        "",
        "| Bài | Dương/âm tính | ROC-AUC | PR-AUC | Recall@FPR 1% | Recall@FPR 0,1% | Xác thực lại @TPR 90% | Xác thực lại @TPR 99% |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for t in report["tasks"]:
        m = t["metrics"]
        lines.append(
            f"| `{t['task']}` | {t['n_pos']:,} / {t['n_neg']:,} | {_fmt(m['roc_auc'], False)} | {_fmt(m['pr_auc'], False)} | "
            f"{_fmt(m['recall@fpr=0.01'])} | {_fmt(m['recall@fpr=0.001'])} | {_fmt(m['reauth@tpr=0.9'])} | {_fmt(m['reauth@tpr=0.99'])} |"
        )
    volume_rows = [(t["task"], v) for t in report["tasks"] for v in t.get("alert_volume", [])]
    if volume_rows:
        lines += ["", "Khối lượng cảnh báo khi bắt được 90% / 99% dòng tấn công (ước lượng cho toàn bộ dân số user được chấm điểm):", "", "| Bài | Recall mục tiêu | Cảnh báo / 1.000 đăng nhập | Cảnh báo / ngày |", "|---|---|---|---|"]
        for task, v in volume_rows:
            lines.append(f"| `{task}` | {v['recall_target']:.0%} | {v['alerts_per_1000_logins']:.1f} | {v['alerts_per_day']:,.0f} |")
    lines += ["", "Theo mức lịch sử của tài khoản, tại ngưỡng chung cho FPR = 1%:", "", "| Bài | Nhóm lịch sử | Dương/âm tính | Recall | Báo nhầm |", "|---|---|---|---|---|"]
    for t in report["tasks"]:
        if t["task"].startswith("attack_ip"):
            continue
        for b in t["by_history"]:
            recall = "—" if b["recall"] is None else f"{b['recall']:.1%}"
            fa = "—" if b["false_alert_rate"] is None else f"{b['false_alert_rate']:.2%}"
            lines.append(f"| `{t['task']}` | {b['bucket']} | {b['n_pos']:,} / {b['n_neg']:,} | {recall} | {fa} |")
    return "\n".join(lines) + "\n"


def save_report(report: dict, name: str) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / f"{name}.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path = REPORT_DIR / f"{name}.md"
    md_path.write_text(to_markdown(report), encoding="utf-8")
    return md_path
