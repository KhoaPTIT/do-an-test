"""Kiểm chứng "kiểu tấn công mới" (MR7):  python -m ml.rba.holdout [attack-ip|sim|all]

Câu hỏi: mô hình học từ các họ tấn công đã biết có bắt được một họ CHƯA TỪNG THẤY không? Cách đo: giấu hẳn một HỌ tấn công
khỏi tập huấn luyện VÀ tập chọn mô hình (dừng sớm, hiệu chỉnh), huấn luyện lại, rồi đo phần bắt được của chính họ đó ở giai đoạn
test (chưa từng dùng khi học) so với đúng mô hình ấy khi ĐÃ thấy họ. Đặt cạnh các bộ phát hiện không dùng nhãn tấn công.

Dòng lệnh: python -m ml.rba.holdout [attack-ip|variants|sim|all] [--n-boot N] [--families it_luot,rai_rong]

Hai loạt thí nghiệm:
1. HỌ IP TẤN CÔNG (nhãn `Is Attack IP`): họ định nghĩa theo hành vi của IP trên TOÀN BỘ dữ liệu (chậm và ít, rải rộng), theo
   nhà mạng/quốc gia nguồn và theo loại thiết bị. RBA gần như không có thiết bị bot (2 trong 2,5 triệu dòng hợp lệ) nên "bot/
   thiết bị" của kế hoạch được thay bằng loại thiết bị (máy tính/máy tính bảng so với điện thoại, họ thiểu số của tấn công).
   Lưu ý: họ theo hành vi được xác định bằng thống kê cả giai đoạn của IP — chỉ để PHÂN NHÓM khi đánh giá, không phải đặc trưng.
2. KIỂU KẺ TẤN CÔNG MÔ PHỎNG: giấu lần lượt Naive, VPN, Targeted (và học chỉ từ Naive rồi chấm Targeted).
ATO thật là họ "chưa từng thấy" theo thiết kế (141 ca không bao giờ vào huấn luyện) — kết quả đã có ở MR6.

Quy tắc chống rò rỉ: dòng của họ bị loại khỏi train VÀ val (dương tính); mọi thứ khác giữ nguyên (siêu tham số, hạt giống, dừng
sớm theo val đã bỏ họ). Ngưỡng đo ở FPR cố định trên chính âm tính test (như bảng MR4); âm tính = đăng nhập hợp lệ giai đoạn test.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import joblib
import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from ml.rba import baselines, eval_tasks, models
from ml.rba import ensemble as En
from ml.rba import metrics as M
from ml.rba.eval_tasks import ATTACKERS_PARQUET, ATTACKERS_TRAINVAL_PARQUET
from ml.rba.etl import FULL_PARQUET
from ml.rba.features import FEATURE_GROUPS, FEATURE_NAMES, RBA_CATCHALL_USER_ID
from ml.rba.paths import RBA_DATA_DIR
from ml.rba.sample import SAMPLE_PARQUET
from ml.rba.scorers import SCORER_FACTORIES

IP_STATS_PARQUET = RBA_DATA_DIR / "attack_ip_stats.parquet"
OUT_DIR = Path(__file__).resolve().parents[1] / "artifacts" / "rba_mr7"
METRIC_KEYS = ("roc_auc", "recall@fpr=0.01", "recall@fpr=0.001")
DOMINANT_ASN = 393398  # mạng chiếm ~62% số dòng tấn công của RBA (kiểm chứng trên dữ liệu, xem docs)


@dataclass(frozen=True)
class Family:
    key: str
    label: str
    description: str
    rule: Callable[[pd.DataFrame], np.ndarray]  # nhận bảng có attempts/successes/users/asn/country/device_type, trả cờ bool


FAMILIES: tuple[Family, ...] = (
    Family("it_luot", "Chậm và ít", "IP chỉ có ≤ 10 lượt thử trong toàn bộ dữ liệu (dò chậm hoặc thử một lần)", lambda f: f["attempts"] <= 10),
    Family("rai_rong", "Rải rộng", "IP nhắm > 30 tài khoản thật khác nhau (nhồi/rải mật khẩu quy mô lớn)", lambda f: f["users"] > 30),
    Family("mang_393398", "Mạng chiếm ưu thế", f"IP thuộc ASN {DOMINANT_ASN}, mạng chiếm ~62% số dòng tấn công", lambda f: f["asn"] == DOMINANT_ASN),
    Family("ngoai_my", "Ngoài Mỹ", "IP nguồn không phải Mỹ (Mỹ chiếm 71% số dòng tấn công)", lambda f: f["country"].fillna("?") != "US"),
    Family("mang_duoi_0", "Mạng đuôi (nhóm 0)", f"IP thuộc ASN ≠ {DOMINANT_ASN} với ASN mod 3 = 0", lambda f: (f["asn"] != DOMINANT_ASN) & (f["asn"] % 3 == 0)),
    Family("mang_duoi_1", "Mạng đuôi (nhóm 1)", f"IP thuộc ASN ≠ {DOMINANT_ASN} với ASN mod 3 = 1", lambda f: (f["asn"] != DOMINANT_ASN) & (f["asn"] % 3 == 1)),
    Family("mang_duoi_2", "Mạng đuôi (nhóm 2)", f"IP thuộc ASN ≠ {DOMINANT_ASN} với ASN mod 3 = 2", lambda f: (f["asn"] != DOMINANT_ASN) & (f["asn"] % 3 == 2)),
    Family("may_tinh", "Máy tính / máy tính bảng", "dòng tấn công từ máy tính hoặc máy tính bảng (họ thiểu số: 13%, còn lại là điện thoại)", lambda f: f["device_type"].isin(["desktop", "tablet"])),
)
FAMILY_BY_KEY = {f.key: f for f in FAMILIES}


# ------------------------------------------------------------------------------------------- dữ liệu và họ


def build_attack_ip_stats(full_parquet: Path = FULL_PARQUET, out_path: Path | None = IP_STATS_PARQUET) -> pd.DataFrame:
    """Hành vi mỗi IP tấn công trên TOÀN BỘ dữ liệu: số lượt thử, số lần thành công, số tài khoản thật bị nhắm (không tính "thùng
    chứa" tài khoản không tồn tại). ATO không tính vào (nhãn riêng)."""
    import duckdb

    con = duckdb.connect()
    con.execute("PRAGMA memory_limit='3GB'")
    frame = con.execute(
        f"""
        SELECT ip, COUNT(*) AS attempts, SUM(CASE WHEN success THEN 1 ELSE 0 END) AS successes,
               COUNT(DISTINCT CASE WHEN user_id <> {RBA_CATCHALL_USER_ID} THEN user_id END) AS users
        FROM read_parquet('{Path(full_parquet).as_posix()}') WHERE is_attack_ip AND NOT is_ato GROUP BY ip
        """
    ).df()
    if out_path is not None:
        frame.to_parquet(out_path, index=False)
    return frame


def load_attack_ip_stats() -> pd.DataFrame:
    return pd.read_parquet(IP_STATS_PARQUET) if IP_STATS_PARQUET.is_file() else build_attack_ip_stats()


def load_table_with_attributes() -> pd.DataFrame:
    """Bảng đặc trưng + trọng số dân số + các thuộc tính thô (quốc gia, ASN, loại thiết bị) để định nghĩa họ."""
    df = eval_tasks.add_population_weights(eval_tasks.load_model_table())
    attrs = pq.read_table(SAMPLE_PARQUET, columns=["row_id", "country", "asn", "device_type"]).to_pandas()
    return df.merge(attrs, on="row_id", how="left")


def add_family_columns(df: pd.DataFrame, stats: pd.DataFrame, families=FAMILIES) -> pd.DataFrame:
    """Thêm cột bool `fam_<key>`: dòng tấn công thuộc họ nào. Dòng không phải IP tấn công luôn False."""
    out = df.merge(stats[["ip", "attempts", "successes", "users"]], on="ip", how="left")
    attack = out["is_attack_ip"].to_numpy(dtype=bool)
    for family in families:
        out[f"fam_{family.key}"] = attack & np.asarray(family.rule(out), dtype=bool)
    return out.drop(columns=["attempts", "successes", "users"])


# --------------------------------------------------------------------------------------- học không có họ


def _drop_family(triple, column: str):
    frame, y, w = triple
    keep = ~frame[column].to_numpy(dtype=bool)
    return frame[keep], y[keep], w[keep]


def attack_ip_sets_without(df: pd.DataFrame, key: str):
    """Tập huấn luyện/chọn mô hình của `gbm_attack_ip` với mọi dòng tấn công của họ `key` bị loại (cả train lẫn val)."""
    column = f"fam_{key}"
    return tuple(_drop_family(triple, column) for triple in models.attack_ip_sets(df))


def sim_sets_without(df: pd.DataFrame, trainval: pd.DataFrame, drop_types: tuple[str, ...]):
    """Tập huấn luyện/chọn của `gbm_attacker_sim` không có các kiểu kẻ tấn công mô phỏng trong `drop_types`."""
    return models.simulated_attacker_sets(df, trainval[~trainval["attacker_type"].isin(drop_types)])


# ------------------------------------------------------------------------------------------- đo lường


def summarize(y: np.ndarray, score: np.ndarray, weight: np.ndarray, cluster: np.ndarray, n_boot: int, seed: int = 0) -> dict:
    result = M.evaluate(y, score, weight, cluster, n_boot=n_boot, seed=seed)
    return {k: {"value": result.values[k], "ci95": list(result.ci[k])} for k in METRIC_KEYS}


def _hybrid_parts(hybrid: En.HybridMinTail, frame: pd.DataFrame):
    """Điểm thô và xác suất đuôi (đã qua cổng) của từng thành phần hybrid trên `frame`."""
    raw, tails = [], []
    for component in hybrid.components:
        s = np.asarray(component.scorer(frame), dtype=float)
        tail = component.calibrator.tail(s)
        if component.gate is not None:
            tail = np.where(component.gate(frame), tail, 1.0)
        raw.append(s)
        tails.append(tail)
    return raw, np.column_stack(tails)


def _score_from_tails(tails: np.ndarray) -> np.ndarray:
    return -np.log10(tails.min(axis=1))


def _recalibrated_tail(scorer, gate, reference: pd.DataFrame, frame: pd.DataFrame) -> np.ndarray:
    """Xác suất đuôi của một thành phần MỚI: hiệu chỉnh trên đăng nhập hợp lệ của val (qua cổng của chính nó), áp lên `frame`."""
    ref = reference if gate is None else reference[gate(reference)]
    calibrator = En.EcdfCalibrator.fit(scorer(ref), ref["pop_weight"].to_numpy())
    tail = calibrator.tail(scorer(frame))
    return tail if gate is None else np.where(gate(frame), tail, 1.0)


# ------------------------------------------------------------------------- loạt 1: họ IP tấn công


def run_attack_ip_holdout(df: pd.DataFrame, families=FAMILIES, n_boot: int = 200, rounds: int = 1500, log=print) -> dict:
    """`df`: bảng có cột `fam_<key>` (add_family_columns), `pop_weight`, `ip`. Trả kết quả đủ để dựng bảng tài liệu."""
    from ml.rba.train import _val_reference

    started = time.time()
    test = df[(df["partition"] == "test") & ~df["in_warmup"]].reset_index(drop=True)
    tv = df[df["partition"].isin(["train", "val"])]
    train_rows = tv[tv["partition"] == "train"]
    reference = _val_reference(df, success_only=False)
    weight, cluster, is_attack = test["pop_weight"].to_numpy(), test["ip"].to_numpy(), test["is_attack_ip"].to_numpy(dtype=bool)

    log(f"  [{time.time() - started:5.0f}s] chấm các bộ phát hiện không đổi trên {len(test):,} dòng test")
    hybrid = joblib.load(models.ARTIFACT_DIR / "hybrid.joblib")
    raw, tails = _hybrid_parts(hybrid, test)
    constant = {
        "tier2_current": SCORER_FACTORIES["tier2_current"](df)(test),
        "freeman_all": SCORER_FACTORIES["freeman_all"](df)(test),
        "isolation_forest": raw[2],
        "knn_distance": SCORER_FACTORIES["knn_distance"](df)(test),
        "gbm_attack_ip (đã thấy họ)": raw[0],
        "hybrid (đã thấy họ)": _score_from_tails(tails),
    }
    gate_ip = hybrid.components[0].gate  # None: thành phần IP tấn công không có cổng

    results = []
    for family in families:
        column = f"fam_{family.key}"
        in_family_test = test[column].to_numpy(dtype=bool)
        keep = ~is_attack | in_family_test  # dương tính = dòng của họ; âm tính = đăng nhập hợp lệ; họ khác bị bỏ
        info = {
            "key": family.key, "label": family.label, "description": family.description,
            "test_rows": int(in_family_test.sum()), "test_ips": int(test.loc[in_family_test, "ip"].nunique()),
            "test_share_of_attack_rows": float(weight[in_family_test].sum() / weight[is_attack].sum()),
            "train_rows_removed": int(train_rows[column].sum()), "train_ips_removed": int(train_rows.loc[train_rows[column], "ip"].nunique()),
            "train_share_removed": float(train_rows.loc[train_rows[column], "weight"].sum() / train_rows.loc[train_rows["is_attack_ip"], "weight"].sum()),
        }
        if info["test_rows"] < 20:
            log(f"  họ {family.key}: chỉ {info['test_rows']} dòng test — bỏ qua")
            continue

        train_set, val_set = attack_ip_sets_without(tv, family.key)
        unseen = models.train_gbm(f"gbm_attack_ip_khong_{family.key}", FEATURE_NAMES, train_set, val_set, rounds=rounds)
        rules = baselines.fit_tuned_rules(train_rows[~train_rows[column]])
        s_unseen = unseen(test)
        tail_new = _recalibrated_tail(unseen, gate_ip, reference, test)
        scores = {
            **constant,
            "rules_tuned (không có họ)": rules(test),
            "gbm_attack_ip (chưa thấy họ)": s_unseen,
            "hybrid (chưa thấy họ)": _score_from_tails(np.column_stack([tail_new, tails[:, 1], tails[:, 2]])),
        }
        info["gbm_best_iteration"] = unseen.meta["best_iteration"]
        info["results"] = {
            name: summarize(in_family_test[keep], s[keep], weight[keep], cluster[keep], n_boot) for name, s in scores.items()
        }
        results.append(info)
        seen_r = info["results"]["gbm_attack_ip (đã thấy họ)"]["recall@fpr=0.01"]["value"]
        unseen_r = info["results"]["gbm_attack_ip (chưa thấy họ)"]["recall@fpr=0.01"]["value"]
        log(f"  [{time.time() - started:5.0f}s] {family.key:12s} {info['test_rows']:5,} dòng test | GBM recall@1%: đã thấy {seen_r:6.1%} → chưa thấy {unseen_r:6.1%}")
    return {"kind": "attack_ip", "n_boot": n_boot, "families": results}


def _without_groups(*groups: str) -> list[str]:
    return [f for f in FEATURE_NAMES if not any(f in FEATURE_GROUPS[g] for g in groups)]


# Biến thể đặc trưng cho câu hỏi "bỏ đặc trưng kiểu định danh (độ hiếm) có giúp mô hình tổng quát sang họ chưa thấy không?".
# Ablation (ml/rba/ablation.py) cho thấy nhóm độ hiếm một mình đã đủ và nhóm hạ tầng IP làm giảm hiệu năng ở test.
VARIANTS = {
    "bỏ độ hiếm": _without_groups("rarity"),
    "bỏ hạ tầng IP": _without_groups("infra_ip"),
    "chỉ độ hiếm": list(FEATURE_GROUPS["rarity"]),
}


def run_attack_ip_variant_holdout(df: pd.DataFrame, variants=None, families=FAMILIES, n_boot: int = 200, rounds: int = 1500, log=print) -> dict:
    """Như `run_attack_ip_holdout` nhưng cho các biến thể ĐẶC TRƯNG của `gbm_attack_ip`: mỗi biến thể được huấn luyện một lần trên
    mọi họ ("đã thấy") và một lần cho mỗi họ bị giấu ("chưa thấy"). Chỉ đo GBM (không chấm lại các bộ phát hiện không đổi)."""
    variants = variants or VARIANTS
    started = time.time()
    test = df[(df["partition"] == "test") & ~df["in_warmup"]].reset_index(drop=True)
    tv = df[df["partition"].isin(["train", "val"])]
    weight, cluster, is_attack = test["pop_weight"].to_numpy(), test["ip"].to_numpy(), test["is_attack_ip"].to_numpy(dtype=bool)

    seen_scores = {}
    for label, features in variants.items():
        train_set, val_set = models.attack_ip_sets(tv)
        seen_scores[label] = models.train_gbm(f"gbm_attack_ip_{label}", features, train_set, val_set, rounds=rounds)(test)
        log(f"  [{time.time() - started:5.0f}s] đã huấn luyện biến thể '{label}' ({len(features)} đặc trưng) trên mọi họ")

    results = []
    for family in families:
        column = f"fam_{family.key}"
        in_family = test[column].to_numpy(dtype=bool)
        keep = ~is_attack | in_family
        if in_family.sum() < 20:
            continue
        entry = {"key": family.key, "label": family.label, "test_rows": int(in_family.sum()), "results": {}}
        for label, features in variants.items():
            train_set, val_set = attack_ip_sets_without(tv, family.key)
            unseen = models.train_gbm(f"gbm_attack_ip_{label}_khong_{family.key}", features, train_set, val_set, rounds=rounds)
            for suffix, s in (("đã thấy họ", seen_scores[label]), ("chưa thấy họ", unseen(test))):
                entry["results"][f"{label} ({suffix})"] = summarize(in_family[keep], s[keep], weight[keep], cluster[keep], n_boot)
        results.append(entry)
        log(f"  [{time.time() - started:5.0f}s] {family.key:12s} " + " | ".join(
            f"{label}: {entry['results'][f'{label} (đã thấy họ)']['recall@fpr=0.01']['value']:.1%} → {entry['results'][f'{label} (chưa thấy họ)']['recall@fpr=0.01']['value']:.1%}" for label in variants
        ))
    return {"kind": "attack_ip_variants", "n_boot": n_boot, "variants": {k: len(v) for k, v in variants.items()}, "families": results}


# ------------------------------------------------------------------ loạt 2: kiểu kẻ tấn công mô phỏng

SIM_VARIANTS = {
    "khong_naive": ("naive",),
    "khong_vpn": ("vpn",),
    "khong_targeted": ("targeted",),
    "chi_naive": ("vpn", "targeted"),
}
SIM_TYPES = ("naive", "vpn", "targeted")


def run_sim_holdout(df: pd.DataFrame, trainval: pd.DataFrame, attackers_test: pd.DataFrame, n_boot: int = 200, rounds: int = 1500, log=print) -> dict:
    from ml.rba.train import _val_reference

    started = time.time()
    tasks = eval_tasks.build_tasks(df, attackers_test)
    tasks = {k.split("/")[1]: v for k, v in tasks.items() if k.startswith("attacker/")}
    reference = _val_reference(df, success_only=False)
    hybrid = joblib.load(models.ARTIFACT_DIR / "hybrid.joblib")
    gate_sim = hybrid.components[1].gate

    frames = {kind: task.frame for kind, task in tasks.items()}
    parts = {kind: _hybrid_parts(hybrid, frame) for kind, frame in frames.items()}
    constant = {
        kind: {
            "freeman_all": SCORER_FACTORIES["freeman_all"](df)(frame),
            "isolation_forest": parts[kind][0][2],
            "knn_distance": SCORER_FACTORIES["knn_distance"](df)(frame),
            "gbm_attacker_sim (đã thấy kiểu)": parts[kind][0][1],
            "hybrid (đã thấy kiểu)": _score_from_tails(parts[kind][1]),
        }
        for kind, frame in frames.items()
    }
    log(f"  [{time.time() - started:5.0f}s] đã chấm các bộ phát hiện không đổi")

    results = []
    for variant, dropped in SIM_VARIANTS.items():
        train_set, val_set = sim_sets_without(df, trainval, dropped)
        unseen = models.train_gbm(f"gbm_attacker_sim_{variant}", FEATURE_NAMES, train_set, val_set, rounds=rounds)
        per_type = {}
        for kind in SIM_TYPES:
            frame = frames[kind]
            tail_new = _recalibrated_tail(unseen, gate_sim, reference, frame)
            tails = parts[kind][1]
            scores = {
                **constant[kind],
                "gbm_attacker_sim (chưa thấy kiểu)" if kind in dropped else "gbm_attacker_sim (mô hình này)": unseen(frame),
                "hybrid (chưa thấy kiểu)" if kind in dropped else "hybrid (mô hình này)": _score_from_tails(np.column_stack([tails[:, 0], tail_new, tails[:, 2]])),
            }
            y = frame["y"].to_numpy()
            per_type[kind] = {
                "seen_in_training": kind not in dropped,
                "n_pos": int(y.sum()),
                "results": {name: summarize(y, s, frame["pop_weight"].to_numpy(), frame["cluster"].to_numpy(), n_boot) for name, s in scores.items()},
            }
        results.append({"variant": variant, "dropped": list(dropped), "trained_on": [t for t in SIM_TYPES if t not in dropped], "best_iteration": unseen.meta["best_iteration"], "per_type": per_type})
        held = [t for t in dropped]
        text = ", ".join(f"{t}: {per_type[t]['results']['gbm_attacker_sim (chưa thấy kiểu)']['recall@fpr=0.01']['value']:.1%}" for t in held)
        log(f"  [{time.time() - started:5.0f}s] {variant:15s} chưa thấy → recall@1% {text}")
    return {"kind": "sim", "n_boot": n_boot, "variants": results}


# ------------------------------------------------------------------------------------------- bảng tài liệu


def _cell(entry: dict, key: str = "recall@fpr=0.01", with_ci: bool = False) -> str:
    value, (lo, hi) = entry[key]["value"], entry[key]["ci95"]
    if key == "roc_auc":
        return f"{value:.3f}"
    return f"{value:.1%} [{lo:.0%}–{hi:.0%}]" if with_ci else f"{value:.1%}"


def attack_ip_markdown(result: dict) -> str:
    order = ["tier2_current", "freeman_all", "rules_tuned (không có họ)", "isolation_forest", "knn_distance",
             "gbm_attack_ip (đã thấy họ)", "gbm_attack_ip (chưa thấy họ)", "hybrid (đã thấy họ)", "hybrid (chưa thấy họ)"]
    header = "| Họ bị giấu | Dòng test (IP) | % dòng tấn công bị loại khỏi huấn luyện | " + " | ".join(f"`{n}`" for n in order) + " |"
    lines = [header, "|---|---|---|" + "---|" * len(order)]
    for fam in result["families"]:
        cells = [_cell(fam["results"][n], with_ci=n.startswith(("gbm_attack_ip", "hybrid"))) for n in order]
        lines.append(f"| **{fam['label']}** | {fam['test_rows']:,} ({fam['test_ips']:,}) | {fam['train_share_removed']:.0%} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def sim_markdown(result: dict) -> str:
    order = ["freeman_all", "isolation_forest", "knn_distance", "gbm_attacker_sim (đã thấy kiểu)", "gbm_attacker_sim (chưa thấy kiểu)", "hybrid (đã thấy kiểu)", "hybrid (chưa thấy kiểu)"]
    lines = ["| Học từ | Chấm trên | Ca dương | " + " | ".join(f"`{n}`" for n in order) + " |", "|---|---|---|" + "---|" * len(order)]
    for variant in result["variants"]:
        trained = " + ".join(variant["trained_on"])
        for kind in variant["dropped"]:
            entry = variant["per_type"][kind]
            cells = [_cell(entry["results"][n], with_ci=n.startswith(("gbm_attacker_sim (chưa", "hybrid (chưa"))) if n in entry["results"] else "—" for n in order]
            lines.append(f"| {trained} | **{kind}** (chưa thấy) | {entry['n_pos']:,} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def variants_markdown(result: dict, full: dict | None = None) -> str:
    """Bảng: họ bị giấu × biến thể đặc trưng, mỗi ô "đã thấy → chưa thấy" (recall@FPR 1%). `full`: kết quả `run_attack_ip_holdout`
    để thêm cột mô hình đủ 50 đặc trưng."""
    labels = list(result["variants"])
    full_by_key = {f["key"]: f for f in full["families"]} if full else {}
    columns = (["đủ 50 đặc trưng"] if full else []) + [f"{l} ({n})" for l, n in result["variants"].items()]
    lines = ["| Họ bị giấu | Dòng test | " + " | ".join(columns) + " |", "|---|---|" + "---|" * len(columns)]
    for fam in result["families"]:
        cells = []
        if full:
            r = full_by_key[fam["key"]]["results"]
            cells.append(f"{r['gbm_attack_ip (đã thấy họ)']['recall@fpr=0.01']['value']:.1%} → **{r['gbm_attack_ip (chưa thấy họ)']['recall@fpr=0.01']['value']:.1%}**")
        for label in labels:
            r = fam["results"]
            cells.append(f"{r[f'{label} (đã thấy họ)']['recall@fpr=0.01']['value']:.1%} → **{r[f'{label} (chưa thấy họ)']['recall@fpr=0.01']['value']:.1%}**")
        lines.append(f"| **{fam['label']}** | {fam['test_rows']:,} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


# --------------------------------------------------------------------------------------------- dòng lệnh


def main() -> int:
    which = (sys.argv[1] if len(sys.argv) > 1 else "all").lower()
    n_boot = int(sys.argv[sys.argv.index("--n-boot") + 1]) if "--n-boot" in sys.argv else 200
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for path in (models.ARTIFACT_DIR / "hybrid.joblib", ATTACKERS_TRAINVAL_PARQUET, ATTACKERS_PARQUET):
        if not path.is_file():
            print(f"Thiếu {path} — chạy `python -m ml.rba.train` và `python -m ml.rba.attackers` trước.")
            return 1

    print("Nạp bảng đặc trưng và định nghĩa các họ...", flush=True)
    df = add_family_columns(load_table_with_attributes(), load_attack_ip_stats())
    if which in ("attack-ip", "all"):
        wanted = sys.argv[sys.argv.index("--families") + 1].split(",") if "--families" in sys.argv else [f.key for f in FAMILIES]
        result = run_attack_ip_holdout(df, families=[FAMILY_BY_KEY[k] for k in wanted], n_boot=n_boot, log=lambda m: print(m, flush=True))
        (OUT_DIR / "holdout_attack_ip.json").write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
        print("\n" + attack_ip_markdown(result), flush=True)
    if which in ("variants", "all"):
        wanted = sys.argv[sys.argv.index("--families") + 1].split(",") if "--families" in sys.argv else [f.key for f in FAMILIES]
        result = run_attack_ip_variant_holdout(df, families=[FAMILY_BY_KEY[k] for k in wanted], n_boot=n_boot, log=lambda m: print(m, flush=True))
        (OUT_DIR / "holdout_attack_ip_variants.json").write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
        full_path = OUT_DIR / "holdout_attack_ip.json"
        full = json.loads(full_path.read_text(encoding="utf-8")) if full_path.is_file() else None
        print("\n" + variants_markdown(result, full), flush=True)
    if which in ("sim", "all"):
        trainval = pd.read_parquet(ATTACKERS_TRAINVAL_PARQUET)
        result = run_sim_holdout(df, trainval, pd.read_parquet(ATTACKERS_PARQUET), n_boot=n_boot, log=lambda m: print(m, flush=True))
        (OUT_DIR / "holdout_sim.json").write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
        print("\n" + sim_markdown(result), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
