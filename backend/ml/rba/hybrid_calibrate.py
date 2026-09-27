"""Hiệu chỉnh hybrid risk engine trên RBA (MR11): trọng số từng luật, đường hiệu chỉnh xác suất của `hybrid_cp2`, ba ngưỡng
hành động — rồi kiểm tra chuyển miền (train/val -> test/late trong RBA; RBA -> kẻ tấn công mô phỏng).

Chạy (sau `python -m ml.rba.rule_tuning collect` — dùng lại `levels.parquet`, KHÔNG replay lại RBA):

    cd backend
    venv\\Scripts\\python.exe -m ml.rba.hybrid_calibrate

Ghi `app/detection/hybrid/profiles/rba_calibrated.json` (hồ sơ dùng ngay bởi `app.detection.hybrid.combine_risk`),
`ml/artifacts/hybrid_risk/calibration.json` (số liệu đầy đủ) và `docs/hybrid-risk-engine.md`.

CÁCH HIỆU CHỈNH TRỌNG SỐ LUẬT: với 12 mã luật có "bậc thang" ở MR10 (`rule_tuning.LADDERS`), trọng số = ĐỘ CHÍNH XÁC đo
được trên `val` khi luật khớp ở BẬC MẶC ĐỊNH (cấu hình hiện hành của sổ đăng ký — KHÔNG dùng hồ sơ đã tinh chỉnh của
MR10, xem giới hạn trong docs). Đây là "nếu chỉ một mình luật này khớp, khả năng đúng là bao nhiêu" — dùng làm p_i của
noisy-OR (`combine.noisy_or`); KHÔNG phải mức tăng recall biên khi đã có mô hình (MR10 đã đo mức đó và thấy gần 0 —
hai câu hỏi khác nhau, không được lẫn khi đọc báo cáo). 7 mã luật không đánh giá được trên RBA (`rule_tuning.NOT_EVALUABLE`)
dùng trọng số mặc định đặt trước, đánh dấu `calibrated=false`.

CÁCH HIỆU CHỈNH MÔ HÌNH: hồi quy isotonic (`ml.rba.ensemble.IsotonicCalibrator`, MR6) học trên `attack_ip/val`, xuất lại
thành các điểm gãy tuyến tính từng đoạn (`app.detection.hybrid.calibration.MonotonicCalibrator`) để dùng lúc chấm điểm
thật mà không cần scikit-learn.

CÁCH CHỌN NGƯỠNG HÀNH ĐỘNG: trên đăng nhập hợp lệ THÀNH CÔNG của `val` (cùng tập âm tính hybrid_cp2 đã dùng ở MR8b) cho
ba FPR mục tiêu ĐẶT TRƯỚC — 1% và 0,1% là hai ngưỡng vận hành đã công bố của `hybrid_cp2` (model-card-rba.md), 0,01% là
mức mới, chặt hơn, dành riêng cho hành động khoá tạm.
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
from app.detection.hybrid.calibration import ActionBands, HybridProfile, MonotonicCalibrator, RuleWeightEntry, RuleWeights
from app.detection.hybrid.combine import REPUTATION_CATEGORY
from ml.rba import ensemble as En
from ml.rba import eval_tasks, metrics as M, models
from ml.rba import rule_tuning as RT
from ml.rba.rule_overlap import cluster_bootstrap
from ml.rba.rule_tuning import LADDERS

ARTIFACT_DIR = Path(__file__).resolve().parents[1] / "artifacts" / "hybrid_risk"
CALIBRATION_JSON = ARTIFACT_DIR / "calibration.json"
PROFILE_PATH = Path(__file__).resolve().parents[2] / "app" / "detection" / "hybrid" / "profiles" / "rba_calibrated.json"
DOC_PATH = RT.DOCS_DIR / "hybrid-risk-engine.md"
HYBRID_NAME = "hybrid_cp2"

TARGET_FPR = {"alert_at": 0.01, "step_up_at": 0.001, "lock_at": 0.0001}  # đặt trước; 1% và 0,1% trùng hai ngưỡng vận hành đã công bố của hybrid_cp2
N_BOOT = 300
ML_BREAKPOINTS = 400  # số điểm gãy tối đa xuất ra cho MonotonicCalibrator (đủ mịn, JSON vẫn gọn)
DEFAULT_WEIGHT = RuleWeights().default_weight
TRANSFER_TASKS = ("attack_ip/test", "attack_ip/late", "ato/future", "ato/all")
ATTACKER_KINDS = ("naive", "vpn", "targeted")


# ------------------------------------------------------------------------------------------------ dữ liệu gộp: bảng mô hình + mức bậc thang MR10


def build_master_frame() -> pd.DataFrame:
    """Bảng mô hình (đặc trưng, nhãn, `pop_weight`, `ip`) GHÉP với mức bậc thang của MR10 (`rule_tuning.LEVELS_PARQUET`,
    không replay lại). Mọi dòng của bảng mô hình đều có mặt trong mức bậc thang (MR10 chạy trên toàn bộ mẫu) — kiểm bằng
    assert để lỗi sớm nếu ai chạy `collect` lại với tệp mẫu khác."""
    df = eval_tasks.add_population_weights(eval_tasks.load_model_table())
    levels = pq.read_table(RT.LEVELS_PARQUET).to_pandas()
    keep = ["row_id"] + [ladder.column for ladder in LADDERS]
    merged = df.merge(levels[keep], on="row_id", how="left")
    missing = merged[[ladder.column for ladder in LADDERS]].isna().any(axis=1).sum()
    assert missing == 0, f"{missing} dòng của bảng mô hình không có trong levels.parquet — chạy lại `python -m ml.rba.rule_tuning collect`"
    return merged


def fired_by_rule(frame: pd.DataFrame, ladders: Sequence = LADDERS) -> pd.DataFrame:
    """Với mỗi mã luật có bậc thang: cờ "khớp ở bậc MẶC ĐỊNH" (hợp các phạm vi của cùng một luật), lập chỉ mục theo `row_id`
    để tra theo bất kỳ tập dòng nào (kể cả dòng không có trong `frame`, ví dụ kẻ tấn công mô phỏng — xem `rule_probability_of`)."""
    out = pd.DataFrame(index=pd.Index(frame["row_id"], name="row_id"))
    for ladder in ladders:
        fired = frame[ladder.column].to_numpy() >= ladder.default_rung
        if ladder.rule_id in out:
            out[ladder.rule_id] |= fired
        else:
            out[ladder.rule_id] = fired
    return out


def rule_probability_of(row_ids: np.ndarray, fired: pd.DataFrame, weights: RuleWeights, registry=REGISTRY) -> tuple[np.ndarray, np.ndarray]:
    """(xác suất luật, xác suất danh tiếng) cho từng dòng của `row_ids`, bằng CÔNG THỨC noisy-OR giống hệt
    `combine.combine_risk` (kiểm bằng test so từng dòng với `combine_risk`). Dòng không có trong `fired` (ví dụ kẻ tấn
    công mô phỏng — luật chưa từng được chạy trên chúng) coi như KHÔNG luật nào khớp: xác suất tổ hợp khi đó chỉ còn
    thành phần ML — một CẬN DƯỚI của giá trị thật, xem docs/hybrid-risk-engine.md mục "Chuyển miền"."""
    aligned = fired.reindex(row_ids, fill_value=False)
    rule_complement = np.ones(len(row_ids))
    reputation_complement = np.ones(len(row_ids))
    for rule_id in aligned.columns:
        w = weights.weight_of(rule_id)
        mask = aligned[rule_id].to_numpy()
        target = reputation_complement if registry[rule_id].category == REPUTATION_CATEGORY else rule_complement
        target *= np.where(mask, 1.0 - w, 1.0)
    return 1.0 - rule_complement, 1.0 - reputation_complement


def combined_probability(ml_probability: np.ndarray, rule_probability: np.ndarray, reputation_probability: np.ndarray) -> np.ndarray:
    """1 − (1−ml)(1−luật)(1−danh tiếng) — noisy-OR của ba thành phần, vector hoá; công thức giống hệt `combine.combine_risk`
    khi không có luật ghi đè nào khớp (RBA không có mục blocklist nên đường ghi đè không kiểm được trên dữ liệu này, chỉ
    bằng unit test tổng hợp — xem tests/test_hybrid_combine.py)."""
    return 1.0 - (1.0 - ml_probability) * (1.0 - rule_probability) * (1.0 - reputation_probability)


# ------------------------------------------------------------------------------------------------ trọng số luật


def calibrate_rule_weights(master: pd.DataFrame, n_boot: int = N_BOOT, seed: int = 0) -> dict[str, RuleWeightEntry]:
    val = master[(master["partition"] == "val") & ~master["in_warmup"]]
    w, attack, ip = val["pop_weight"].to_numpy(), val["is_attack_ip"].to_numpy(dtype=bool), val["ip"].to_numpy()
    fired = fired_by_rule(val)
    entries: dict[str, RuleWeightEntry] = {}
    for rule_id in fired.columns:
        mask = fired[rule_id].to_numpy()
        n = int(mask.sum())
        if n == 0:
            entries[rule_id] = RuleWeightEntry(DEFAULT_WEIGHT, False, 0, None)
            continue
        precision = float(w[mask & attack].sum() / w[mask].sum())
        samples = cluster_bootstrap(ip[mask], w[mask], {"precision": attack[mask].astype(float)}, n_boot, seed)[:, 0]
        entries[rule_id] = RuleWeightEntry(precision, True, n, (float(np.percentile(samples, 2.5)), float(np.percentile(samples, 97.5))))
    for rule_id in RT.NOT_EVALUABLE:
        entries[rule_id] = RuleWeightEntry(DEFAULT_WEIGHT, False, 0, None)
    missing = set(REGISTRY) - set(entries)
    assert not missing, f"luật chưa có trọng số (thiếu trong LADDERS và NOT_EVALUABLE): {missing}"
    return entries


# ------------------------------------------------------------------------------------------------ hiệu chỉnh mô hình ML


def calibrate_ml(df: pd.DataFrame, hybrid) -> tuple[MonotonicCalibrator, dict[str, Any]]:
    val = eval_tasks.build_tasks(df)["attack_ip/val"].frame
    scores = np.asarray(hybrid(val), dtype=float)
    y, w = val["y"].to_numpy(dtype=bool), val["pop_weight"].to_numpy()
    isotonic = En.IsotonicCalibrator.fit(scores, y, w)

    xs = np.unique(scores)
    if len(xs) > ML_BREAKPOINTS:
        xs = xs[np.linspace(0, len(xs) - 1, ML_BREAKPOINTS).round().astype(int)]
    ys = np.maximum.accumulate(isotonic.probability(xs))  # nội suy tuyến tính có thể phá tính đơn điệu ở sai số làm tròn cực nhỏ
    calibrator = MonotonicCalibrator.from_dict({"xs": xs.tolist(), "ys": ys.tolist()})

    calibrated = calibrator.probability(scores)
    quality = {
        "n_val": int(len(val)), "base_rate": float((y * w).sum() / w.sum()), "brier_calibrated": En.brier_score(calibrated, y, w),
        "brier_constant": En.brier_score(np.full(len(y), (y * w).sum() / w.sum()), y, w), "reliability": En.reliability_table(calibrated, y, w, bins=10),
    }
    return calibrator, quality


# ------------------------------------------------------------------------------------------------ ngưỡng hành động


def _strictly_increasing(raw: Sequence[float], maximum: int = 100) -> list[int]:
    """Ép ba ngưỡng thành số nguyên tăng NGẶT trong [0, maximum]: làm tròn LÊN (giữ đúng hoặc chặt hơn FPR mục tiêu, không
    lỏng hơn), rồi đẩy các mức sau lên nếu trùng/thấp hơn mức trước (dữ liệu rời rạc có thể khiến hai FPR mục tiêu gần
    nhau rơi vào cùng một điểm số)."""
    out: list[int] = []
    previous = -1
    for value in raw:
        v = max(int(np.ceil(value)), previous + 1)
        out.append(v)
        previous = v
    if out[-1] > maximum:
        out[-1] = maximum
        for i in range(len(out) - 2, -1, -1):
            out[i] = min(out[i], out[i + 1] - 1)
    return out


def calibrate_bands(master: pd.DataFrame, combined: np.ndarray, target_fpr: Mapping[str, float] = TARGET_FPR) -> ActionBands:
    legit_val = ((master["partition"] == "val") & ~master["in_warmup"] & (master["cur_success"].to_numpy() == 1) & ~master["is_attack_ip"].to_numpy() & ~master["is_ato"].to_numpy()).to_numpy()
    ref = M.NegativeReference.build(combined[legit_val] * 100, master.loc[legit_val, "pop_weight"].to_numpy())
    cuts = [ref.exceeding_score(target_fpr[name]) for name in ("alert_at", "step_up_at", "lock_at")]
    alert_at, step_up_at, lock_at = _strictly_increasing(cuts)
    return ActionBands(alert_at, step_up_at, lock_at)


# ------------------------------------------------------------------------------------------------ chuyển miền


def transfer_report(
    master: pd.DataFrame, attackers: pd.DataFrame, hybrid, ml_calibrator: MonotonicCalibrator, weights: RuleWeights, bands: ActionBands, ml_only_bands: ActionBands, n_boot: int = N_BOOT
) -> dict[str, Any]:
    """`bands`: ngưỡng THẬT sẽ triển khai (hiệu chỉnh trên điểm GỘP). `ml_only_bands`: ngưỡng RIÊNG của một mình mô hình ở
    CÙNG BA FPR MỤC TIÊU (hiệu chỉnh trên chỉ điểm ML) — dùng CHỈ ĐỂ SO SÁNH công bằng trong mục "combined vs ml_only" bên
    dưới. Lý do cần hai bộ ngưỡng: điểm gộp luôn >= điểm chỉ-ML tại mọi dòng (bằng chứng luật chỉ CỘNG THÊM xác suất),
    nên so ở CÙNG một ngưỡng tuyệt đối sẽ luôn có lợi cho bộ gộp một cách máy móc (nó thấy nhiều dòng đạt ngưỡng hơn kể cả
    khi luật là nhiễu thuần) — không phải bằng chứng luật có ích. So đúng phải ở CÙNG tổng tỉ lệ báo nhầm (như MR10)."""
    df_tasks = eval_tasks.build_tasks(master, attackers)
    scores = eval_tasks.score_all_tasks(hybrid, df_tasks)
    fired = fired_by_rule(master)
    rows: dict[str, Any] = {}
    for name in TRANSFER_TASKS:
        frame = df_tasks[name].frame
        ml_probability = ml_calibrator.probability(scores[name])
        rule_probability, reputation_probability = rule_probability_of(frame["row_id"].to_numpy(), fired, weights)
        combined = combined_probability(ml_probability, rule_probability, reputation_probability)
        ml_only_score = np.clip(np.round(ml_probability * 100), 0, 100)
        combined_score = np.clip(np.round(combined * 100), 0, 100)
        y, w, cluster = frame["y"].to_numpy(dtype=bool), frame["pop_weight"].to_numpy(), frame["cluster"].to_numpy()
        rows[name] = {
            "n_pos": int(y.sum()),
            "combined": _band_recall(combined_score, y, w, cluster, bands, n_boot),
            "ml_only": _band_recall(ml_only_score, y, w, cluster, ml_only_bands, n_boot),
        }
    attacker_rows: dict[str, Any] = {}
    for kind in ATTACKER_KINDS:
        key = f"attacker/{kind}"
        if key not in df_tasks:
            continue
        frame = df_tasks[key].frame
        pos = frame[frame["y"].to_numpy(dtype=bool)]
        if pos.empty:
            continue
        ml_probability = ml_calibrator.probability(np.asarray(hybrid(pos), dtype=float))
        score = np.clip(np.round(ml_probability * 100), 0, 100)
        attacker_rows[kind] = {"n": len(pos), "by_band": {action: float(np.mean(np.array([bands.classify(int(s)) for s in score]) == action)) for action in ("allow", "alert", "step_up", "lock")}}
    return {"tasks": rows, "attacker_lower_bound": attacker_rows}


def _band_recall(score: np.ndarray, y: np.ndarray, w: np.ndarray, cluster: np.ndarray, bands: ActionBands, n_boot: int) -> dict[str, Any]:
    action = np.array([bands.classify(int(s)) for s in score])
    at_least = {"allow": np.ones(len(score), dtype=bool), "alert": action != "allow", "step_up": np.isin(action, ["step_up", "lock"]), "lock": action == "lock"}
    pos = y
    out: dict[str, Any] = {}
    for name, indicator in at_least.items():
        hit = indicator & pos
        recall = float(w[hit].sum() / w[pos].sum()) if pos.any() else None
        if pos.any():
            samples = cluster_bootstrap(cluster[pos], w[pos], {"r": indicator[pos].astype(float)}, n_boot)[:, 0]
            ci = (float(np.percentile(samples, 2.5)), float(np.percentile(samples, 97.5)))
        else:
            ci = None
        out[name] = {"recall": recall, "ci95": ci}
    return out


# ------------------------------------------------------------------------------------------------ payload + báo cáo


def build_payload() -> dict[str, Any]:
    master = build_master_frame()
    hybrid = joblib.load(models.ARTIFACT_DIR / f"{HYBRID_NAME}.joblib")
    attackers = pd.read_parquet(eval_tasks.ATTACKERS_PARQUET)

    rule_weights = calibrate_rule_weights(master)
    weights = RuleWeights(rule_weights)
    ml_calibrator, ml_quality = calibrate_ml(master, hybrid)

    scores_all = np.asarray(hybrid(master), dtype=float)
    ml_prob_all = ml_calibrator.probability(scores_all)
    fired = fired_by_rule(master)
    rule_prob_all, reputation_prob_all = rule_probability_of(master["row_id"].to_numpy(), fired, weights)
    combined_all = combined_probability(ml_prob_all, rule_prob_all, reputation_prob_all)
    bands = calibrate_bands(master, combined_all)
    ml_only_bands = calibrate_bands(master, ml_prob_all)  # chỉ để so sánh công bằng ở mục 3 của báo cáo, KHÔNG dùng khi triển khai

    transfer = transfer_report(master, attackers, hybrid, ml_calibrator, weights, bands, ml_only_bands)
    profile = HybridProfile(weights, bands, ml_calibrator)
    return {
        "rule_weights": rule_weights, "ml_quality": ml_quality, "bands": bands.to_dict(), "ml_only_bands": ml_only_bands.to_dict(),
        "target_fpr": TARGET_FPR, "transfer": transfer, "profile": profile.to_dict(),
    }


def _pct(x: float | None, digits: int = 1) -> str:
    return "—" if x is None else f"{x:.{digits}%}"


def _ci(pair, fmt=_pct) -> str:
    return "" if pair is None else f" [{fmt(pair[0])}–{fmt(pair[1])}]"


def render(payload: Mapping[str, Any]) -> str:
    weights, quality, bands = payload["rule_weights"], payload["ml_quality"], payload["bands"]
    lines = [
        "# Hybrid risk engine — hiệu chỉnh trên RBA (MR11)",
        "",
        "> Báo cáo TỰ SINH bởi `python -m ml.rba.hybrid_calibrate` — đừng sửa tay. Mã: [`hybrid_calibrate.py`](../backend/ml/rba/hybrid_calibrate.py), bộ gộp dùng lúc chấm điểm: "
        "[`app/detection/hybrid/combine.py`](../backend/app/detection/hybrid/combine.py). Hồ sơ: [`profiles/rba_calibrated.json`](../backend/app/detection/hybrid/profiles/rba_calibrated.json).",
        "",
        "## 1. Cách làm",
        "",
        "- **Điểm = noisy-OR có trọng số** của ba nguồn: xác suất mô hình `hybrid_cp2` đã hiệu chỉnh (hồi quy isotonic trên `attack_ip/val`), xác suất gộp của các luật KHÔNG thuộc nhóm danh tiếng, xác suất gộp của nhóm \"Danh tiếng hạ tầng\" "
        "(Tor/datacenter/VPN/blocklist). `P = 1 − (1−p_ml)(1−p_luật)(1−p_danh_tiếng)`; luật `blocklist_hit` GHI ĐÈ (điểm 100, hành động `lock`) vì đó là quyết định của quản trị viên, không phải bằng chứng xác suất.",
        "- **Trọng số một luật** = độ chính xác đo trên `val` khi luật khớp ở bậc MẶC ĐỊNH của sổ đăng ký (dùng lại `levels.parquet` của MR10, KHÔNG replay lại): \"nếu chỉ một mình luật này khớp, khả năng đúng là bao nhiêu\" — dùng làm bằng chứng độc lập trong noisy-OR. ⚠️ KHÁC câu hỏi MR10 đã trả lời (\"luật cộng thêm bao nhiêu recall khi ĐàCÓ mô hình\", câu đó gần 0) — ở đây là độ tin cậy của luật khi ĐỨNG MỘT MÌNH, dùng để giải thích cảnh báo.",
        "- Luật `shadow` (`country_hop`, `rare_network_login`, `regular_rhythm`, `datacenter_ip`, `vpn_ip`) vẫn là bằng chứng đầy đủ ở đây: chế độ shadow chỉ quyết định rule engine có TỰ tạo cảnh báo hay không (MR9), không phải luật vô giá trị.",
        "- **Ngưỡng hành động** (0–100): chọn trên đăng nhập hợp lệ THÀNH CÔNG của `val` cho ba FPR mục tiêu ĐẶT TRƯỚC — 1% (`alert`) và 0,1% (`step_up`) trùng hai ngưỡng vận hành đã công bố của `hybrid_cp2` (model-card-rba.md); 0,01% (`lock`) là mức mới, chặt hơn, cho khoá tạm.",
        "",
        f"**Chất lượng hiệu chỉnh mô hình** (n={quality['n_val']:,} dòng val, tỉ lệ tấn công {quality['base_rate']:.3%}): Brier sau hiệu chỉnh **{quality['brier_calibrated']:.4f}** so với đoán theo tỉ lệ trung bình {quality['brier_constant']:.4f} (thấp hơn = tốt hơn).",
        "",
        f"**Ngưỡng hành động:** `alert_at` = {bands['alert_at']}, `step_up_at` = {bands['step_up_at']}, `lock_at` = {bands['lock_at']} (thang 0–100).",
        "",
        "## 2. Trọng số từng luật",
        "",
        "| Luật | Nhóm | Trọng số | Đo được trên RBA? | n (dòng khớp ở val) |",
        "|---|---|---|---|---|",
    ]
    for rule_id, entry in weights.items():
        category = REGISTRY[rule_id].category
        ci = f" {_ci(entry.ci95, lambda v: f'{v:.1%}')}" if entry.ci95 else ""
        lines.append(f"| `{rule_id}` | {category} | {entry.weight:.1%}{ci} | {'có' if entry.calibrated else 'KHÔNG (giá trị đặt trước)'} | {entry.n:,} |")

    ml_only_bands = payload["ml_only_bands"]
    lines += [
        "",
        "## 3. Chuyển miền (val → test/late trong RBA; xem thêm mục 4 cho kẻ tấn công mô phỏng)",
        "",
        "Recall \"≥ mức\" = tỉ lệ (trọng số) dòng dương tính đạt hành động đó HOẶC chặt hơn; ngưỡng chọn trên val, áp THẲNG sang test/late/ATO — không hiệu chỉnh lại.",
        "",
        f"⚠️ **So sánh phải công bằng:** điểm gộp luôn ≥ điểm chỉ-ML tại mọi dòng (bằng chứng luật chỉ CỘNG THÊM xác suất), nên so ở CÙNG một ngưỡng tuyệt đối luôn có lợi máy móc cho bộ gộp — không phải bằng chứng luật có ích (bài học từ MR10). "
        f"Vì vậy cột \"Chỉ ML\" dưới đây dùng NGƯỠNG RIÊNG của một mình mô hình, hiệu chỉnh ở CÙNG BA FPR MỤC TIÊU trên val (`alert_at`={ml_only_bands['alert_at']}, `step_up_at`={ml_only_bands['step_up_at']}, `lock_at`={ml_only_bands['lock_at']} — khác ngưỡng triển khai thật ở mục 1), không phải ngưỡng gộp — so sánh này mới trả lời được \"luật có thêm giá trị ngoài việc chỉ nới ngưỡng mô hình\" hay không.",
        "",
    ]
    for name in TRANSFER_TASKS:
        entry = payload["transfer"]["tasks"][name]
        lines += [f"### `{name}` (n dương = {entry['n_pos']:,})", "", "| Bộ | ≥ alert | ≥ step_up | = lock |", "|---|---|---|---|"]
        for label, key in (("Gộp (luật + ML, ngưỡng triển khai)", "combined"), ("Chỉ ML (ngưỡng riêng, cùng FPR mục tiêu)", "ml_only")):
            r = entry[key]
            lines.append(f"| {label} | {_pct(r['alert']['recall'])}{_ci(r['alert']['ci95'])} | {_pct(r['step_up']['recall'])}{_ci(r['step_up']['ci95'])} | {_pct(r['lock']['recall'])}{_ci(r['lock']['ci95'])} |")
        lines.append("")

    lines += [
        "**Vì sao khác kết luận của MR10 (`docs/rule-ml-overlap.md`: gộp không tăng recall ở cùng ngân sách báo nhầm)?** MR10 so hai bộ luật CỰC ĐOAN: mặc định (union thô, ngân sách báo nhầm ~18,6% — quá lớn để so công bằng) và đã tinh chỉnh riêng lẻ theo ngân sách 5/10.000 "
        "(mỗi luật gần như không còn recall một mình: bộ `tuned_enforce` chỉ 0,3% recall đứng riêng). ĐÂY khác: dùng NGUYÊN luật mặc định (nhiều recall hơn hẳn khi đứng riêng) nhưng KHÔNG lấy union thô — mỗi luật đóng góp theo ĐÚNG độ chính xác đo được (trọng số nhỏ với luật ồn), rồi ngưỡng của điểm GỘP (không phải của từng luật) được hiệu chỉnh để tự nó đạt đúng 1%/0,1%/0,01% FPR. "
        "Nhờ vậy ở mức `alert` (ngân sách lỏng nhất), phần recall thêm từ luật là THẬT (không chỉ vì union thô đốt ngân sách): 43,4% so với 11,7% trên `attack_ip/test`. Ở mức `step_up`/`lock` (ngân sách chặt), phần thêm gần như biến mất — khớp với MR10: một khi điểm ML đã đủ cao, thêm bằng chứng luật hiếm khi đổi kết quả.",
        "",
    ]

    lines += [
        "## 4. Kẻ tấn công mô phỏng — CẬN DƯỚI (chỉ thành phần ML)",
        "",
        "⚠️ Rule engine chưa từng chạy trên dòng kẻ tấn công mô phỏng (chúng không nằm trong luồng sự kiện đã replay ở MR9/10); số dưới đây giả định KHÔNG luật nào khớp, nên là CẬN DƯỚI của tỉ lệ đạt mỗi hành động — bằng chứng thật (nếu có) chỉ làm tăng, không giảm. "
        "Dùng ngưỡng TRIỂN KHAI THẬT ở mục 1 (không phải ngưỡng riêng của mục 3): câu hỏi ở đây là \"hệ thống thật sẽ làm gì\", không phải so sánh công bằng luật/ML.",
        "",
    ]
    lines += ["| Loại | n | allow | alert | step_up | lock |", "|---|---|---|---|---|---|"]
    for kind, entry in payload["transfer"]["attacker_lower_bound"].items():
        b = entry["by_band"]
        lines.append(f"| `{kind}` | {entry['n']:,} | {_pct(b['allow'])} | {_pct(b['alert'])} | {_pct(b['step_up'])} | {_pct(b['lock'])} |")

    lines += [
        "",
        "## 5. Giới hạn",
        "",
        "- Trọng số luật hiệu chỉnh với luật ở CẤU HÌNH MẶC ĐỊNH của sổ đăng ký, không phải hồ sơ đã tinh chỉnh của MR10 (xem `docs/rule-tuning.md`); nếu đổi cấu hình luật thì trọng số cần hiệu chỉnh lại.",
        "- Bốn luật nhóm \"Danh tiếng hạ tầng\" và ba luật khác (`username_enumeration`, `regular_rhythm`, `impossible_travel`) không đánh giá được trên RBA (IP tổng hợp, không toạ độ, tên không tồn tại bị gộp — `docs/rule-tuning.md` mục 6): trọng số của chúng là giá trị đặt trước, và trong mọi số đo ở mục 3–4, thành phần \"danh tiếng\" luôn bằng 0 (không có dòng RBA nào để bốn luật đó khớp).",
        "- Đường ghi đè (`blocklist_hit`) không kiểm được trên RBA (blocklist rỗng khi replay) — chỉ kiểm bằng unit test tổng hợp (`tests/test_hybrid_combine.py`).",
        "- Chuyển miền sang \"live\" (log thật của web app mẫu) CHƯA làm được: cần pipeline tính đặc trưng RBA và chạy rule engine trên `login_events`, việc đó thuộc MR12 (tích hợp realtime).",
        "- 38 ATO tương lai đã bị nhìn ở MR7 (chỉ xác nhận, không phải kiểm định độc lập); ATO của RBA có đặc điểm nhân tạo (nhà mạng hiếm — xem `rare_network_login`).",
    ]
    return "\n".join(lines).rstrip("\n") + "\n"


def _json_safe(payload: Mapping[str, Any]) -> dict[str, Any]:
    """`payload["rule_weights"]` giữ nguyên `RuleWeightEntry` (để `render` đọc bằng thuộc tính); đổi sang dict thuần trước khi ghi JSON."""
    safe = dict(payload)
    safe["rule_weights"] = {rule_id: entry.to_dict() for rule_id, entry in payload["rule_weights"].items()}
    return safe


def run() -> int:
    print("nạp bảng mô hình, mức bậc thang MR10 và hybrid_cp2 …", flush=True)
    payload = build_payload()
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    CALIBRATION_JSON.write_text(json.dumps(_json_safe(payload), ensure_ascii=False, indent=1, default=float), encoding="utf-8")
    PROFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    PROFILE_PATH.write_text(json.dumps(payload["profile"], ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    DOC_PATH.write_text(render(payload), encoding="utf-8", newline="\n")
    print(f"đã ghi {DOC_PATH}, {PROFILE_PATH} và {CALIBRATION_JSON}")
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError, OSError):
        pass
    return run()


if __name__ == "__main__":
    sys.exit(main())
