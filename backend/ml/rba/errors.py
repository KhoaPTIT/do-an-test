"""Phân tích lỗi của hybrid (MR7):  python -m ml.rba.errors

Ba câu hỏi, mỗi câu một bảng, trả lời bằng chính dữ liệu chứ không đoán:
1. ATO thật nào bị BỎ SÓT và vì sao? (từng ca: hybrid báo hay không, thành phần nào báo, hồ sơ ca đó; tóm tắt theo lịch sử tài khoản,
   theo việc IP có bị gắn nhãn tấn công không.)
2. Đăng nhập hợp lệ nào bị BÁO NHẦM (ở ngưỡng FPR 1%)? Gom thành các "kiểu" dễ hiểu và đo tỉ lệ báo nhầm của từng kiểu so với mức chung
   — kiểu nào bị báo nhầm gấp mấy lần? Lưu ý: RBA có thể chứa tấn công chưa gắn nhãn, nên một phần "báo nhầm" có thể là đúng.
3. GIỚI HẠN VỚI KẺ TẤN CÔNG TARGETED: phần bắt được của hybrid theo khoảng cách từ lần đăng nhập thành công trước (kẻ tấn công biết trọn
   hồ sơ phiên chỉ lộ ở IP mới, mà đăng nhập hợp lệ cũng hay đổi IP khi cách lâu) và theo độ dày lịch sử.
Ngưỡng luôn chọn trên đăng nhập hợp lệ của `val` (như bảng chuyển ngưỡng ở MR6); không chọn trên test hay ATO.
"""

from __future__ import annotations

import json
import sys

import joblib
import numpy as np
import pandas as pd

from ml.rba import analysis, eval_tasks, models, splits
from ml.rba import ensemble as En
from ml.rba.eval_tasks import ATTACKERS_PARQUET
from ml.rba.holdout import OUT_DIR, _hybrid_parts, _score_from_tails

FPR_TARGETS = (0.01, 0.001)
KEY_FEATURES = ["rare_asn", "rare_country", "new_country", "new_asn", "new_ip", "ip_prior_attempts_all", "asn_attempts_24h", "u_secs_since_last_success", "u_n_success", "llr_sum"]
COMPONENT_NAMES = ("ip_tan_cong", "chiem_tai_khoan", "bat_thuong")
DAY = 86_400.0

GAP_BUCKETS = (("< 1 phút", 0, 60), ("1–10 phút", 60, 600), ("10 phút–1 giờ", 600, 3600), ("1–24 giờ", 3600, DAY), ("1–7 ngày", DAY, 7 * DAY), ("7–30 ngày", 7 * DAY, 30 * DAY), ("> 30 ngày", 30 * DAY, np.inf))
HISTORY_BUCKETS = (("chưa có lịch sử", 0, 1), ("mỏng (1–4)", 1, 5), ("dày (≥ 5)", 5, np.inf))  # nửa mở [lo, hi)


def _bucket(values: np.ndarray, buckets) -> np.ndarray:
    """Nhãn nhóm cho từng giá trị, nhóm là khoảng nửa mở [lo, hi). NaN (chưa từng thành công) coi là vô hạn."""
    labels = np.full(len(values), "?", dtype=object)
    v = np.nan_to_num(np.asarray(values, dtype=float), nan=1e300)  # NaN -> số rất lớn (rơi vào nhóm cuối); nan=inf sẽ lọt khỏi khoảng nửa mở
    for label, lo, hi in buckets:
        labels[(v >= lo) & (v < hi)] = label
    return labels


def thresholds(hybrid: En.HybridMinTail, df: pd.DataFrame, with_history: bool, targets=FPR_TARGETS) -> dict[float, float]:
    """Ngưỡng hybrid cho từng FPR mục tiêu, chọn trên đăng nhập hợp lệ thành công của val (`with_history`: chỉ tài khoản đã có lịch sử)."""
    frame = analysis._val_legit_success_task(df, with_history=with_history).frame
    score = _score_from_tails(_hybrid_parts(hybrid, frame)[1])
    return {t: En.threshold_for_fpr(score, frame["pop_weight"].to_numpy(), t) for t in targets}


# ---------------------------------------------------------------------------------------------- 1. ATO


def ato_case_table(df: pd.DataFrame, hybrid: En.HybridMinTail, tau: dict[float, float]) -> pd.DataFrame:
    ato = df[df["is_ato"]].copy()
    _, tails = _hybrid_parts(hybrid, ato)
    score = _score_from_tails(tails)
    out = pd.DataFrame(
        {
            "row_id": ato["row_id"].to_numpy(),
            "ts": ato["ts"].to_numpy(),
            "tuong_lai": ((ato["ts"] >= splits.VAL_END) & (ato["ts"] < splits.TEST_END)).to_numpy(),
            "warmup": ato["in_warmup"].to_numpy(),
            "lich_su": _bucket(ato["u_n_success"].to_numpy(), HISTORY_BUCKETS),
            "ip_bi_gan_nhan": ato["is_attack_ip"].to_numpy(),
            "diem": score,
            "thanh_phan_bao": np.array(COMPONENT_NAMES)[tails.argmin(axis=1)],
        }
    )
    for i, name in enumerate(COMPONENT_NAMES):
        out[f"duoi_{name}"] = tails[:, i]
    for target, value in tau.items():
        out[f"bat_{target:g}"] = score > value
    for feature in KEY_FEATURES:
        out[feature] = ato[feature].to_numpy(dtype=float)
    return out.sort_values("ts").reset_index(drop=True)


def ato_segments(cases: pd.DataFrame, target: float = 0.01) -> list[dict]:
    """Tỉ lệ bắt được và thành phần báo, theo từng lát cắt của ca ATO (bỏ ca warm-up: chưa có lịch sử để so)."""
    cases = cases[~cases["warmup"]]
    column = f"bat_{target:g}"
    cuts = [(f"tất cả ({len(cases)} ca)", np.ones(len(cases), dtype=bool)), ("tương lai (test)", cases["tuong_lai"].to_numpy()), ("quá khứ", ~cases["tuong_lai"].to_numpy())]
    for label, _, _ in HISTORY_BUCKETS:
        cuts.append((f"lịch sử: {label}", (cases["lich_su"] == label).to_numpy()))
    cuts += [("IP bị gắn nhãn tấn công", cases["ip_bi_gan_nhan"].to_numpy()), ("IP không gắn nhãn", ~cases["ip_bi_gan_nhan"].to_numpy())]
    rows = []
    for label, mask in cuts:
        sub = cases[mask]
        if sub.empty:
            continue
        caught = sub[sub[column]]
        rows.append(
            {
                "lat_cat": label, "n": int(len(sub)), "bat_duoc": int(len(caught)), "recall": float(len(caught) / len(sub)),
                "theo_thanh_phan": {name: int((caught["thanh_phan_bao"] == name).sum()) for name in COMPONENT_NAMES},
            }
        )
    return rows


def ato_profile(cases: pd.DataFrame, target: float = 0.01) -> pd.DataFrame:
    """Trung vị các đặc trưng chính của ca bắt được và ca bỏ sót (bỏ warm-up)."""
    cases = cases[~cases["warmup"]]
    caught = cases[f"bat_{target:g}"]
    table = pd.DataFrame({"bắt được": cases[caught][KEY_FEATURES].median(), "bỏ sót": cases[~caught][KEY_FEATURES].median()})
    table.loc["số ca"] = [int(caught.sum()), int((~caught).sum())]
    return table


def single_feature_rules(df: pd.DataFrame) -> dict:
    """CHẨN ĐOÁN (không phải mô hình): điểm = MỘT đặc trưng độ hiếm, không học gì, chấm trên hai bài ATO thật. Chọn SAU KHI đã thấy ATO nên
    không phải phép so sánh công bằng với các mô hình; chỉ để biết tín hiệu của ATO nằm ở đâu và mô hình có khai thác hết không."""
    tasks = eval_tasks.build_tasks(df)
    scorers = {
        "rare_asn": lambda f: f["rare_asn"].to_numpy(dtype=float),
        "rare_country": lambda f: f["rare_country"].to_numpy(dtype=float),
        "rare_asn + rare_country": lambda f: (f["rare_asn"] + f["rare_country"]).to_numpy(dtype=float),
        "rare_ip": lambda f: f["rare_ip"].to_numpy(dtype=float),
    }
    negatives = tasks["ato/future"].frame
    negatives = negatives[~negatives["y"]]
    out = {"rare_asn_phan_vi_hop_le": {str(q): float(np.quantile(negatives["rare_asn"], q)) for q in (0.5, 0.95, 0.99)}, "rows": []}
    for task_name in ("ato/future", "ato/all"):
        task = tasks[task_name]
        frame = task.frame
        out["rare_asn_trung_vi_ato_" + task_name.split("/")[1]] = float(frame.loc[frame["y"], "rare_asn"].median())
        for name, fn in scorers.items():
            score = fn(frame)
            m = eval_tasks.point_metrics(task, score)
            cold = frame["u_n_success"].to_numpy() < 1
            buckets = eval_tasks.breakdown_by_history(frame, score, frame["pop_weight"].to_numpy(), 0.01)
            out["rows"].append(
                {
                    "bai": task_name, "luat": name, "roc_auc": m["roc_auc"], "recall@fpr=0.01": m["recall@fpr=0.01"], "recall@fpr=0.001": m["recall@fpr=0.001"],
                    "theo_lich_su": {b["bucket"]: b["recall"] for b in buckets}, "so_ca": int(frame["y"].sum()), "so_ca_chua_co_lich_su": int((frame["y"].to_numpy() & cold).sum()),
                }
            )
    return out


def single_rules_markdown(result: dict) -> str:
    lines = ["| Bài | Điểm = một đặc trưng | ROC-AUC | Recall @ FPR 1% | Recall @ FPR 0,1% | Chưa có lịch sử | Mỏng | Dày |", "|---|---|---|---|---|---|---|---|"]
    for r in result["rows"]:
        buckets = [v for v in r["theo_lich_su"].values()]
        cells = ["—" if v is None else f"{v:.0%}" for v in buckets]
        lines.append(f"| `{r['bai']}` ({r['so_ca']} ca) | `{r['luat']}` | {r['roc_auc']:.3f} | {r['recall@fpr=0.01']:.1%} | {r['recall@fpr=0.001']:.1%} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------- 2. báo nhầm

ARCHETYPES = (
    ("moi_tai_khoan", "Tài khoản chưa có lịch sử", lambda f: f["u_n_success"] < 1),
    ("quoc_gia_hoac_mang_moi", "Quốc gia hoặc nhà mạng mới với tài khoản", lambda f: (f["new_country"] == 1) | (f["new_asn"] == 1)),
    ("ip_hoat_dong_la", "IP có hoạt động lạ (nhiều tài khoản / nhiều lần thất bại)", lambda f: (f["ip_distinct_users_24h"] >= 5) | (f["ip_fail_ratio_24h"].fillna(0) >= 0.5)),
    ("thiet_bi_moi", "Thiết bị/trình duyệt mới hoàn toàn", lambda f: (f["new_ua"] == 1) & ((f["new_browser"] == 1) | (f["new_os"] == 1) | (f["new_device"] == 1))),
    ("ip_moi_sau_nghi_dai", "IP mới sau khi nghỉ > 30 ngày", lambda f: (f["new_ip"] == 1) & (f["u_secs_since_last_success"].fillna(np.inf) > 30 * DAY)),
    ("khac", "Không thuộc kiểu nào ở trên", lambda f: np.ones(len(f), dtype=bool)),
)


def assign_archetype(frame: pd.DataFrame) -> np.ndarray:
    """Kiểu đầu tiên khớp (thứ tự ưu tiên như ARCHETYPES)."""
    labels = np.full(len(frame), "khac", dtype=object)
    taken = np.zeros(len(frame), dtype=bool)
    for key, _, rule in ARCHETYPES[:-1]:
        match = np.asarray(rule(frame), dtype=bool) & ~taken
        labels[match] = key
        taken |= match
    return labels


def false_alert_archetypes(df: pd.DataFrame, hybrid: En.HybridMinTail, tau: float, partition: str = "test", cases_per_kind: int = 3) -> dict:
    frame = df[(df["partition"] == partition) & ~df["in_warmup"] & eval_tasks._legit_success(df)].reset_index(drop=True)
    _, tails = _hybrid_parts(hybrid, frame)
    score = _score_from_tails(tails)
    weight = frame["pop_weight"].to_numpy()
    flagged = score > tau
    arch = assign_archetype(frame)
    overall = weight[flagged].sum() / weight.sum()
    rows, examples = [], {}
    for key, label, _ in ARCHETYPES:
        mask = arch == key
        if not mask.any():
            continue
        rate = weight[mask & flagged].sum() / weight[mask].sum()
        rows.append(
            {
                "kieu": key, "nhan": label, "ty_le_dang_nhap": float(weight[mask].sum() / weight.sum()),
                "ty_le_bi_bao": float(rate), "gap_may_lan": float(rate / overall) if overall > 0 else None,
                "ty_le_trong_bao_nham": float(weight[mask & flagged].sum() / weight[flagged].sum()),
                "theo_thanh_phan": {name: float(weight[mask & flagged & (np.array(COMPONENT_NAMES)[tails.argmin(axis=1)] == name)].sum() / max(weight[mask & flagged].sum(), 1e-12)) for name in COMPONENT_NAMES},
            }
        )
        top = np.argsort(-score * (mask & flagged))[:cases_per_kind]
        examples[key] = [{"diem": float(score[i]), "thanh_phan_bao": COMPONENT_NAMES[int(tails[i].argmin())], **{f: (None if pd.isna(frame.loc[i, f]) else float(frame.loc[i, f])) for f in KEY_FEATURES}} for i in top if mask[i] and flagged[i]]
    return {"tau": tau, "fpr_thuc_te": float(overall), "n_dang_nhap": int(len(frame)), "kieu": rows, "vi_du": examples}


# ------------------------------------------------------------------------------------ 3. giới hạn Targeted


def targeted_limits(df: pd.DataFrame, hybrid: En.HybridMinTail, attackers_test: pd.DataFrame, tau: dict[float, float]) -> dict:
    """Recall của hybrid theo khoảng cách từ lần thành công trước và theo độ dày lịch sử, cho từng kiểu kẻ tấn công mô phỏng, so với
    tỉ lệ báo nhầm của đăng nhập hợp lệ trong cùng lát cắt (ngưỡng `tau` chọn trên val, chỉ tài khoản đã có lịch sử)."""
    tasks = eval_tasks.build_tasks(df, attackers_test)
    out = {"tau": {str(k): v for k, v in tau.items()}, "kieu": {}}
    for kind in ("naive", "vpn", "targeted"):
        if f"attacker/{kind}" not in tasks:
            continue
        frame = tasks[f"attacker/{kind}"].frame
        score = _score_from_tails(_hybrid_parts(hybrid, frame)[1])
        y, w = frame["y"].to_numpy(), frame["pop_weight"].to_numpy()
        gap = frame["u_secs_since_last_success"].to_numpy(dtype=float)
        history = frame["u_n_success"].to_numpy(dtype=float)
        result = {}
        for cut_name, labels, buckets in (("khoang_cach", _bucket(gap, GAP_BUCKETS), GAP_BUCKETS), ("lich_su", _bucket(history, HISTORY_BUCKETS), HISTORY_BUCKETS)):
            rows = []
            for label, _, _ in buckets:
                in_cut = labels == label
                pos, neg = in_cut & y, in_cut & ~y
                if pos.sum() == 0 or neg.sum() == 0:
                    continue
                entry = {"lat_cat": label, "ca_dương": int(pos.sum()), "ty_le_hop_le": float(w[neg].sum() / w[~y].sum())}
                for target, value in tau.items():
                    entry[f"recall_{target:g}"] = float(w[pos & (score > value)].sum() / w[pos].sum())
                    entry[f"bao_nham_{target:g}"] = float(w[neg & (score > value)].sum() / w[neg].sum())
                rows.append(entry)
            result[cut_name] = rows
        out["kieu"][kind] = result
    return out


def legit_new_ip_by_gap(df: pd.DataFrame, partition: str = "test") -> list[dict]:
    """Tỉ lệ đăng nhập HỢP LỆ dùng IP mới (chưa từng dùng thành công) theo khoảng cách từ lần thành công trước — nguyên nhân gốc của giới hạn
    Targeted: kẻ tấn công biết trọn hồ sơ phiên chỉ lộ ở IP mới, và ở khoảng cách dài đăng nhập hợp lệ cũng hay đổi IP."""
    frame = df[(df["partition"] == partition) & ~df["in_warmup"] & eval_tasks._legit_success(df) & (df["u_n_success"] >= 1)]
    labels = _bucket(frame["u_secs_since_last_success"].to_numpy(dtype=float), GAP_BUCKETS)
    weight, new_ip = frame["pop_weight"].to_numpy(), frame["new_ip"].to_numpy(dtype=float) == 1
    rows = []
    for label, _, _ in GAP_BUCKETS:
        mask = labels == label
        if mask.any():
            rows.append({"lat_cat": label, "ty_le_dang_nhap": float(weight[mask].sum() / weight.sum()), "ty_le_ip_moi": float(weight[mask & new_ip].sum() / weight[mask].sum())})
    return rows


def new_ip_markdown(rows: list[dict]) -> str:
    lines = ["| Khoảng cách từ lần thành công trước | % đăng nhập hợp lệ | % dùng IP mới |", "|---|---|---|"]
    lines += [f"| {r['lat_cat']} | {r['ty_le_dang_nhap']:.1%} | {r['ty_le_ip_moi']:.1%} |" for r in rows]
    return "\n".join(lines)


# ------------------------------------------------------------------------------------------- bảng tài liệu


def segments_markdown(rows: list[dict]) -> str:
    lines = ["| Lát cắt ca ATO | Số ca | Hybrid bắt được | Do `ip_tan_cong` | Do `chiem_tai_khoan` | Do `bat_thuong` |", "|---|---|---|---|---|---|"]
    for r in rows:
        t = r["theo_thanh_phan"]
        lines.append(f"| {r['lat_cat']} | {r['n']} | {r['bat_duoc']} ({r['recall']:.0%}) | {t['ip_tan_cong']} | {t['chiem_tai_khoan']} | {t['bat_thuong']} |")
    return "\n".join(lines)


def profile_markdown(profile: pd.DataFrame) -> str:
    """Bảng `ato_profile` (đặc trưng x {bắt được, bỏ sót}) thành markdown; không cần thư viện tabulate."""
    lines = ["| Đặc trưng (trung vị) | " + " | ".join(profile.columns) + " |", "|---|" + "---|" * len(profile.columns)]
    for name, row in profile.iterrows():
        lines.append(f"| `{name}` | " + " | ".join(f"{v:,.0f}" if name == "số ca" else f"{v:,.2f}" for v in row) + " |")
    return "\n".join(lines)


def archetypes_markdown(result: dict) -> str:
    lines = [
        f"Ngưỡng {result['tau']:.3f}; tỉ lệ báo nhầm thực tế trên test {result['fpr_thuc_te']:.2%} ({result['n_dang_nhap']:,} đăng nhập hợp lệ thành công).",
        "",
        "| Kiểu đăng nhập hợp lệ | % đăng nhập | % bị báo nhầm | Gấp mấy lần mức chung | % trong số báo nhầm | Thành phần báo (`ip` / `chiếm TK` / `bất thường`) |",
        "|---|---|---|---|---|---|",
    ]
    for r in result["kieu"]:
        t = r["theo_thanh_phan"]
        lines.append(
            f"| {r['nhan']} | {r['ty_le_dang_nhap']:.1%} | {r['ty_le_bi_bao']:.2%} | {r['gap_may_lan']:.1f}× | {r['ty_le_trong_bao_nham']:.1%} | "
            f"{t['ip_tan_cong']:.0%} / {t['chiem_tai_khoan']:.0%} / {t['bat_thuong']:.0%} |"
        )
    return "\n".join(lines)


def limits_markdown(result: dict, kind: str = "targeted", cut: str = "khoang_cach") -> str:
    rows = result["kieu"][kind][cut]
    taus = sorted(result["tau"], key=float, reverse=True)
    header = "| Lát cắt | Ca dương | " + " | ".join(f"Bắt được @FPR {float(t):.1%} (báo nhầm cùng lát cắt)" for t in taus) + " |"
    lines = [header, "|---|---|" + "---|" * len(taus)]
    for r in rows:
        cells = [f"{r[f'recall_{float(t):g}']:.1%} ({r[f'bao_nham_{float(t):g}']:.2%})" for t in taus]
        lines.append(f"| {r['lat_cat']} | {r['ca_dương']:,} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


# --------------------------------------------------------------------------------------------- dòng lệnh


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    df = eval_tasks.add_population_weights(eval_tasks.load_model_table())
    hybrid = joblib.load(models.ARTIFACT_DIR / "hybrid.joblib")
    tau_all, tau_history = thresholds(hybrid, df, with_history=False), thresholds(hybrid, df, with_history=True)
    print(f"Ngưỡng hybrid (val, mọi tài khoản): {tau_all}; (val, tài khoản có lịch sử): {tau_history}", flush=True)

    cases = ato_case_table(df, hybrid, tau_all)
    cases.to_csv(OUT_DIR / "errors_ato_cases.csv", index=False, encoding="utf-8")
    segments = ato_segments(cases)
    print("\n### ATO thật: bắt được và bỏ sót\n" + segments_markdown(segments), flush=True)
    print("\n### Trung vị đặc trưng chính\n" + profile_markdown(ato_profile(cases)), flush=True)

    single = single_feature_rules(df)
    print("\n### Chẩn đoán: một đặc trưng độ hiếm, không học\n" + single_rules_markdown(single), flush=True)

    archetypes = false_alert_archetypes(df, hybrid, tau_all[0.01])
    print("\n### Báo nhầm theo kiểu đăng nhập (test)\n" + archetypes_markdown(archetypes), flush=True)

    new_ip = legit_new_ip_by_gap(df)
    print("\n### Đăng nhập hợp lệ dùng IP mới theo khoảng cách\n" + new_ip_markdown(new_ip), flush=True)
    limits = targeted_limits(df, hybrid, pd.read_parquet(ATTACKERS_PARQUET), tau_history)
    for kind in ("targeted", "naive"):
        print(f"\n### {kind}: theo khoảng cách từ lần thành công trước\n" + limits_markdown(limits, kind, "khoang_cach"), flush=True)
        print(f"\n### {kind}: theo độ dày lịch sử\n" + limits_markdown(limits, kind, "lich_su"), flush=True)

    result = {"tau_all": {str(k): v for k, v in tau_all.items()}, "tau_history": {str(k): v for k, v in tau_history.items()}, "ato_segments": segments,
              "ato_profile": ato_profile(cases).round(3).to_dict(), "false_alerts": archetypes, "targeted_limits": limits, "single_feature_rules": single, "legit_new_ip_by_gap": new_ip}
    (OUT_DIR / "errors.json").write_text(json.dumps(result, ensure_ascii=False, indent=1, default=float), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
