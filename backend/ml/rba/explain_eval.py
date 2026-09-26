"""Đo chất lượng giải thích cảnh báo (MR8):  python -m ml.rba.explain_eval [reference|faithfulness|global|examples|operating|latency|all] [--hybrid TÊN]

1. `faithfulness` — phép thử "XOÁ / GIỮ YẾU TỐ". Giải thích chỉ có ích nếu nó trỏ đúng thứ MÔ HÌNH dựa vào. Với các đăng nhập bị hybrid báo,
   chấm lại đúng thành phần đã báo sau khi đưa một số yếu tố về mức "thường thấy" của đăng nhập hợp lệ:
   - CẦN THIẾT: xoá các yếu tố nêu trong giải thích (tối đa 3) — cảnh báo có biến mất (điểm thành phần tụt dưới ngưỡng) không? Và chỉ xoá yếu tố ĐỨNG ĐẦU?
   - ĐỦ: xoá MỌI yếu tố TRỪ những yếu tố được nêu — cảnh báo có còn không?
   Đối chứng: cùng số yếu tố nhưng chọn NGẪU NHIÊN, và cùng số yếu tố nhưng là những yếu tố quan trọng nhất TOÀN CỤC của thành phần (giống nhau cho
   mọi cảnh báo) — giải thích theo từng cảnh báo phải hơn cả hai thì mới có giá trị hơn một bảng "đặc trưng quan trọng" chung.
2. `global` — yếu tố hay đứng đầu giải thích nhất và đóng góp SHAP trung bình theo yếu tố.
3. `examples` — câu giải thích cho ca thật, có ngữ cảnh "thường … → nay …" dựng từ lịch sử tài khoản trong RBA (ATO, IP tấn công, báo nhầm).
4. `operating` — ngưỡng vận hành, số cảnh báo nhầm trên 10.000 đăng nhập, độ chính xác cảnh báo theo tỉ lệ tấn công giả định.
5. `latency` — thời gian giải thích MỘT cảnh báo (từng dòng một, như luồng realtime sẽ gọi).

Chỉ dùng phân vùng `test` (và `val` để chọn ngưỡng). Mặc định chạy trên `hybrid_cp2` (chốt ở CP2, ml/rba/selection.py) và ghi vào
backend/ml/artifacts/rba_cp2/explain/; `--hybrid hybrid` chạy trên hybrid MR6 và ghi vào backend/ml/artifacts/rba_mr8/. Đây là kiểm tra trung thực của giải thích, KHÔNG
phải chỉ số phát hiện; các cảnh báo được chọn ở đây là cảnh báo của test nên độ phủ ATO/IP tấn công vẫn theo các báo cáo MR6–MR7.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Sequence

import duckdb
import joblib
import numpy as np
import pandas as pd

from ml.rba import analysis, eval_tasks, etl, models
from ml.rba import ensemble as En
from ml.rba import explain as Ex
from ml.rba.features import FEATURE_NAMES, FREEMAN_ATTRS, RBA_CATCHALL_USER_ID, EventRecord

OUT_DIR = Path(__file__).resolve().parents[1] / "artifacts" / "rba_mr8"  # kết quả cho hybrid MR6 (`--hybrid hybrid`)
CP2_OUT_DIR = Path(__file__).resolve().parents[1] / "artifacts" / "rba_cp2" / "explain"  # kết quả cho hybrid chốt ở CP2
HYBRID_NAME = "hybrid_cp2"
FPR_TARGETS = (0.01, 0.001)
N_RANDOM = 5  # số lần bốc ngẫu nhiên cho nhóm đối chứng
MAX_HISTORY_EVENTS = 5_000  # user có quá nhiều sự kiện (thùng "tài khoản không tồn tại", user khổng lồ) không dựng ngữ cảnh


# ------------------------------------------------------------------------------------------------ nạp đầu vào


class World:
    """Bảng đặc trưng, các bài kiểm tra, hybrid đã huấn luyện, ngưỡng chọn trên val và bộ giải thích."""

    def __init__(self, df: pd.DataFrame, attackers: pd.DataFrame, hybrid: En.HybridMinTail, reference: Ex.ExplainReference, target_fpr: float = 0.01):
        self.df, self.attackers, self.hybrid, self.reference = df, attackers, hybrid, reference
        self.tasks = eval_tasks.build_tasks(df, attackers)
        self.thresholds = hybrid_thresholds(hybrid, df)
        self.threshold = self.thresholds[target_fpr]
        self.explainer = Ex.HybridExplainer(hybrid, reference, self.threshold)

    @classmethod
    def load(cls, target_fpr: float = 0.01, hybrid_name: str = HYBRID_NAME) -> "World":
        """Nạp bảng đặc trưng, kẻ tấn công mô phỏng và hybrid đã huấn luyện từ đĩa (`hybrid`: MR6 — `python -m ml.rba.train`;
        `hybrid_cp2`: bản chốt ở CP2 — `python -m ml.rba.selection`)."""
        df = eval_tasks.add_population_weights(eval_tasks.load_model_table())
        return cls(df, pd.read_parquet(eval_tasks.ATTACKERS_PARQUET), joblib.load(models.ARTIFACT_DIR / f"{hybrid_name}.joblib"), load_or_build_reference(df), target_fpr)

    def flagged(self, frame: pd.DataFrame) -> pd.DataFrame:
        return frame[self.hybrid(frame) > self.threshold]


def hybrid_thresholds(hybrid, df: pd.DataFrame) -> dict[float, float]:
    """Ngưỡng hybrid cho từng FPR mục tiêu, chọn chỉ trên đăng nhập hợp lệ thành công của val (như analysis.hybrid_attribution)."""
    val = analysis._val_legit_success_task(df).frame
    scores, weights = hybrid(val), val["pop_weight"].to_numpy()
    return {target: En.threshold_for_fpr(scores, weights, target) for target in FPR_TARGETS}


def load_or_build_reference(df: pd.DataFrame) -> Ex.ExplainReference:
    try:
        return Ex.ExplainReference.load()
    except (FileNotFoundError, ValueError):
        reference = Ex.ExplainReference.fit(df)
        reference.save()
        return reference


# ------------------------------------------------------------------------------------------------ xoá yếu tố


def neutralize(frame: pd.DataFrame, concept_sets: Sequence[Sequence[str]], reference: Ex.ExplainReference) -> pd.DataFrame:
    """Đưa mọi đặc trưng của các yếu tố đã chọn (mỗi dòng một tập) về mức thường thấy; `llr_sum` được tính lại từ bảy llr_* cho nhất quán."""
    features = FEATURE_NAMES
    concepts = Ex.EXPLAINABLE_CONCEPTS
    x = frame[features].to_numpy(dtype=float).copy()
    chosen = np.zeros((len(frame), len(concepts)), dtype=bool)
    for i, picked in enumerate(concept_sets):
        for concept in picked:
            chosen[i, concepts.index(concept)] = True
    column_concept = np.array([concepts.index(Ex.CONCEPT_OF[f]) if Ex.CONCEPT_OF[f] in concepts else -1 for f in features])
    mask = np.zeros(x.shape, dtype=bool)
    valid = column_concept >= 0
    mask[:, valid] = chosen[:, column_concept[valid]]
    x = np.where(mask, reference.vector(features)[None, :], x)

    llr_columns = [features.index(f"llr_{a}") for a in FREEMAN_ATTRS]
    had_llr = ~np.isnan(frame["llr_sum"].to_numpy(dtype=float))
    x[had_llr, features.index("llr_sum")] = np.nansum(x[had_llr][:, llr_columns], axis=1)
    out = frame.copy()
    out[features] = x
    return out


def component_score(component: En.Component, frame: pd.DataFrame) -> np.ndarray:
    """−log10 xác suất đuôi CỦA RIÊNG thành phần (không qua cổng: chỉ đo tác động lên mô hình)."""
    return -np.log10(component.calibrator.tail(component.scorer(frame)))


def _complement(sets: Sequence[Sequence[str]], universe: Sequence[str] = Ex.EXPLAINABLE_CONCEPTS) -> list[list[str]]:
    return [[c for c in universe if c not in set(s)] for s in sets]


def deletion_test(explainer: Ex.HybridExplainer, frame: pd.DataFrame, explanations: Sequence[Ex.Explanation], seed: int = 0, n_random: int = N_RANDOM) -> list[dict]:
    """Mỗi thành phần đã báo động: tỉ lệ cảnh báo biến mất khi xoá yếu tố (`necessity_k`: cả k yếu tố nêu ra; `necessity_1`: chỉ yếu tố đầu),
    tỉ lệ cảnh báo CÒN khi chỉ giữ các yếu tố nêu ra (`sufficiency_k`), tỉ lệ điểm còn lại khi chỉ giữ chúng (`retention_k`; điểm cảnh báo sát
    ngưỡng nên "còn cảnh báo" là phép thử khắt khe, tỉ lệ điểm cho biết các yếu tố nêu ra giải thích được bao nhiêu phần) và điểm tụt khi xoá
    (`drop_k`) — cho giải thích / ngẫu nhiên / quan trọng toàn cục."""
    rows = []
    for component in explainer.hybrid.components:
        index = [i for i, e in enumerate(explanations) if e.component == component.name]
        if not index:
            continue
        sub = frame.iloc[index]
        picked = [[f.concept for f in explanations[i].factors] for i in index]
        k = np.array([len(p) for p in picked])
        before = component_score(component, sub)

        attr = Ex.attribute(component.scorer, sub)
        all_concepts, scores, _ = Ex.concept_scores(attr, sub)
        # chỉ xét yếu tố mà mô hình thật sự có đặc trưng (bản CP2 bỏ nhóm đặc trưng ở một số thành phần): xoá yếu tố mô hình không dùng thì vô nghĩa
        used = [c for c in all_concepts if any(f in attr.features for f in Ex.CONCEPTS[c])]
        concepts = used
        by_importance = np.argsort(-np.maximum(scores[:, [all_concepts.index(c) for c in used]], 0.0).mean(axis=0))  # yếu tố quan trọng nhất TOÀN CỤC của thành phần trên tập này

        def outcome(sets):
            """(cảnh báo biến mất khi xoá `sets`, cảnh báo còn khi chỉ giữ `sets`, điểm tụt khi xoá, tỉ lệ điểm còn khi chỉ giữ) — trung bình trên các dòng."""
            after = component_score(component, neutralize(sub, sets, explainer.reference))
            kept = component_score(component, neutralize(sub, _complement(sets, used), explainer.reference))
            return float((after <= explainer.threshold).mean()), float((kept > explainer.threshold).mean()), float((before - after).mean()), float((kept / before).mean())

        def measure(count):
            """Ba cách chọn `count[i]` yếu tố cho dòng i: theo giải thích, quan trọng toàn cục, ngẫu nhiên (trung bình `n_random` lần bốc)."""
            out = {
                "explanation": outcome([p[:n] for p, n in zip(picked, count)]),
                "global": outcome([[concepts[c] for c in by_importance[:n]] for n in count]),
            }
            rng = np.random.default_rng(seed)
            draws = [outcome([[concepts[c] for c in rng.choice(len(concepts), min(n, len(concepts)), replace=False)] for n in count]) for _ in range(n_random)]
            out["random"] = tuple(float(np.mean([d[j] for d in draws])) for j in range(4))
            return out

        all_k, first_only = measure(k), measure(np.minimum(k, 1))
        pick = lambda source, j: {name: source[name][j] for name in ("explanation", "random", "global")}
        rows.append(
            {
                "component": component.name, "n": len(index), "mean_factors": float(k.mean()), "empty": int((k == 0).sum()),
                "necessity_k": pick(all_k, 0), "necessity_1": pick(first_only, 0), "sufficiency_k": pick(all_k, 1), "drop_k": pick(all_k, 2), "retention_k": pick(all_k, 3),
            }
        )
    return rows


def evaluation_sets(world: World, seed: int = 0, legit_sample: int = 60_000, attack_sample: int = 6_000) -> dict[str, pd.DataFrame]:
    """Các nhóm đăng nhập để đo giải thích (mọi ca đều thuộc giai đoạn test trừ ATO: lấy cả 141 ca cho đủ mẫu — chỉ để đo giải thích, không để đo phát hiện)."""
    attack_ip = world.tasks["attack_ip/test"].frame.query("y")
    legit = world.tasks["ato/future"].frame.query("~y")
    sims = pd.concat([world.tasks[f"attacker/{k}"].frame.query("y") for k in ("naive", "vpn", "targeted")])
    return {
        "IP tấn công (test)": attack_ip.sample(min(attack_sample, len(attack_ip)), random_state=seed),
        "Kẻ tấn công mô phỏng (test)": sims,
        "ATO thật (cả 141 ca)": world.tasks["ato/all"].frame.query("y"),
        "Đăng nhập hợp lệ (test)": legit.sample(min(legit_sample, len(legit)), random_state=seed),
    }


def run_faithfulness(world: World, log=print) -> dict:
    out = {}
    for name, frame in evaluation_sets(world).items():
        flagged = world.flagged(frame)
        explanations = world.explainer.explain(flagged)
        rows = deletion_test(world.explainer, flagged, explanations)
        out[name] = {
            "n_frame": len(frame), "n_flagged": len(flagged), "components": rows, "concept_frequency": concept_frequency(explanations),
            "length": text_length(explanations),
        }
        log(f"  {name}: {len(flagged)}/{len(frame)} bị báo")
    return out


def text_length(explanations: Sequence[Ex.Explanation]) -> dict:
    """Độ dài (ký tự) của câu giải thích — phải đủ ngắn để đọc lướt (định dạng rút gọn của cảnh báo hiện tại) — và số cảnh báo không có yếu tố nào."""
    lengths = np.array([len(e.text) for e in explanations]) if explanations else np.zeros(1)
    return {"median": float(np.median(lengths)), "p95": float(np.percentile(lengths, 95)), "max": int(lengths.max()), "empty": int(sum(1 for e in explanations if not e.factors))}


def concept_frequency(explanations: Sequence[Ex.Explanation]) -> dict[str, dict[str, float]]:
    """Thành phần -> yếu tố -> phần cảnh báo có yếu tố đó trong giải thích (sắp giảm dần)."""
    out: dict[str, dict[str, float]] = {}
    for component in sorted({e.component for e in explanations}):
        group = [e for e in explanations if e.component == component]
        counts = pd.Series([f.concept for e in group for f in e.factors]).value_counts()
        out[component] = {"n": len(group), **{c: float(v / len(group)) for c, v in counts.items()}}
    return out


# ------------------------------------------------------------------------------------------------ toàn cục


def global_shap_table(scorer: models.GbmScorer, frame: pd.DataFrame, weights: np.ndarray | None = None) -> list[dict]:
    """Đóng góp SHAP tuyệt đối trung bình (có trọng số) theo yếu tố, và hướng: phần dòng mà yếu tố đẩy điểm LÊN."""
    attr = Ex.shap_attribution(scorer, frame)
    concepts, scores, _ = Ex.concept_scores(attr, frame)
    w = np.ones(len(frame)) if weights is None else np.asarray(weights, dtype=float)
    magnitude = (np.abs(scores) * w[:, None]).sum(axis=0) / w.sum()
    up = ((scores > 0) * w[:, None]).sum(axis=0) / w.sum()
    order = np.argsort(-magnitude)
    total = float(magnitude.sum()) or 1.0
    return [{"concept": concepts[c], "mean_abs": float(magnitude[c]), "share": float(magnitude[c] / total), "pushes_up": float(up[c])} for c in order]


def run_global(world: World, sample: int = 30_000, seed: int = 0) -> dict:
    """SHAP toàn cục của hai LightGBM: `gbm_attack_ip` trên mọi đăng nhập test, `gbm_attacker_sim` trên đăng nhập hợp lệ có lịch sử + kẻ tấn công mô phỏng."""
    components = {c.name: c for c in world.hybrid.components}
    test = world.df[(world.df["partition"] == "test") & ~world.df["in_warmup"]].sample(sample, random_state=seed)
    attack_task = world.tasks["attacker/naive"].frame
    sim_frame = pd.concat([attack_task.query("~y").sample(min(sample, int((~attack_task["y"]).sum())), random_state=seed), *[world.tasks[f"attacker/{k}"].frame.query("y") for k in ("naive", "vpn", "targeted")]])
    return {
        "ip_tan_cong": global_shap_table(components["ip_tan_cong"].scorer, test, test["pop_weight"].to_numpy()),
        "chiem_tai_khoan": global_shap_table(components["chiem_tai_khoan"].scorer, sim_frame, sim_frame["pop_weight"].to_numpy()),
    }


# ------------------------------------------------------------------------------------------------ ví dụ thật có ngữ cảnh


def fetch_events(row_ids: Sequence[int], user_ids: Sequence[int]) -> tuple[dict[int, EventRecord], dict[int, list[EventRecord]]]:
    """Sự kiện thô của các dòng đã chọn và toàn bộ lịch sử của user tương ứng (từ rba_full.parquet)."""
    users = [int(u) for u in user_ids if int(u) != RBA_CATCHALL_USER_ID]
    path = str(etl.FULL_PARQUET).replace("\\", "/")
    ids = ",".join(str(int(r)) for r in row_ids) or "-1"
    in_users = ",".join(str(u) for u in users) or "NULL"
    sql = (
        f"SELECT row_id, epoch_us(ts) AS ts_us, user_id, ip, asn, country, ua, browser, os, device_type, success FROM read_parquet('{path}') "
        f"WHERE row_id IN ({ids}) OR user_id IN ({in_users})"
    )
    by_row: dict[int, EventRecord] = {}
    history: dict[int, list[EventRecord]] = {}
    targets = {int(r) for r in row_ids}
    for row_id, ts_us, user_id, ip, asn, country, ua, browser, os_, device, success in duckdb.connect().execute(sql).fetchall():
        record = EventRecord(int(ts_us), int(user_id), ip, None if asn is None else int(asn), country, ua, browser, os_, device, bool(success))
        history.setdefault(int(user_id), []).append(record)
        if int(row_id) in targets:
            by_row[int(row_id)] = record
    return by_row, history


def contexts_for(frame: pd.DataFrame) -> list[Ex.Context | None]:
    """Ngữ cảnh "thường … → nay …" cho từng dòng của bảng đặc trưng. None nếu không dựng được (thiếu dòng gốc, hoặc user có quá nhiều sự kiện);
    thùng "tài khoản không tồn tại" không nạp lịch sử nên chỉ có giá trị lần này, không có giá trị quen thuộc."""
    by_row, history = fetch_events(frame["row_id"].tolist(), frame["user_id"].tolist())
    out: list[Ex.Context | None] = []
    for row_id, user_id in zip(frame["row_id"], frame["user_id"]):
        event = by_row.get(int(row_id))
        events = history.get(int(user_id), [])
        out.append(None if event is None or len(events) > MAX_HISTORY_EVENTS else Ex.build_context(event, events))
    return out


def pick_examples(scores: np.ndarray, n: int) -> list[int]:
    """n chỉ số nằm ở các phân vị đều nhau của điểm (đại diện, không chọn lọc ca đẹp nhất)."""
    order = np.argsort(scores, kind="stable")
    return sorted({int(order[round(q * (len(order) - 1))]) for q in np.linspace(0.15, 0.85, n)}) if len(order) else []


def run_examples(world: World, per_set: int = 3) -> list[dict]:
    sets = {
        "ATO thật bị báo": world.flagged(world.tasks["ato/all"].frame.query("y")),
        "IP tấn công bị báo": world.flagged(world.tasks["attack_ip/test"].frame.query("y")).pipe(lambda f: f.sample(min(2000, len(f)), random_state=0)),
        "Đăng nhập hợp lệ bị báo nhầm": world.flagged(world.tasks["ato/future"].frame.query("~y").pipe(lambda f: f.sample(min(60_000, len(f)), random_state=0))),
    }
    out = []
    for name, frame in sets.items():
        scores = world.hybrid(frame)
        chosen = frame.iloc[pick_examples(scores, per_set)]
        contexts = contexts_for(chosen)
        plain = world.explainer.explain(chosen)
        rich = world.explainer.explain(chosen, contexts)
        for row, p, r, ctx in zip(chosen.itertuples(), plain, rich, contexts):
            out.append({"set": name, "row_id": int(row.row_id), "score": r.score, "component": r.component, "method": r.method, "label": r.label, "no_context": p.text, "with_context": r.text, "has_context": ctx is not None})
    return out


# ------------------------------------------------------------------------------------------------ ngưỡng vận hành


def precision_at(recall: float, fpr: float, prevalence: float) -> float:
    """Trong các cảnh báo, bao nhiêu phần là tấn công thật khi tấn công chiếm `prevalence` số đăng nhập (công thức Bayes)."""
    hit, false = recall * prevalence, fpr * (1.0 - prevalence)
    return hit / (hit + false) if hit + false > 0 else 0.0


def run_operating(world: World) -> dict:
    """Mỗi mức FPR: ngưỡng chọn trên val, FPR thực tế trên test và late, recall theo họ tấn công, cảnh báo nhầm trên 10.000 đăng nhập."""
    df, hybrid = world.df, world.hybrid
    legit = df[~df["in_warmup"] & eval_tasks._legit_success(df)]
    positives = {
        "ATO thật tương lai (38)": world.tasks["ato/future"].frame.query("y"),
        "IP tấn công (test)": world.tasks["attack_ip/test"].frame.query("y"),
        **{f"mô phỏng {k}": world.tasks[f"attacker/{k}"].frame.query("y") for k in ("naive", "vpn", "targeted")},
    }
    scored = {name: hybrid(frame) for name, frame in positives.items()}
    rows = []
    for target, threshold in world.thresholds.items():
        realized = {}
        for part in ("val", "test", "late"):
            frame = legit[legit["partition"] == part]
            realized[part] = float(frame["pop_weight"].to_numpy()[hybrid(frame) > threshold].sum() / frame["pop_weight"].sum())
        recalls = {name: float(np.average(scored[name] > threshold, weights=positives[name]["pop_weight"].to_numpy())) for name in positives}
        rows.append({"target_fpr": target, "threshold": threshold, "fpr": realized, "false_alerts_per_10k": realized["test"] * 10_000, "recall": recalls})
    return {"levels": rows, "prevalences": [1e-4, 1e-3, 1e-2]}


def run_latency(world: World, n: int = 150, seed: int = 0) -> dict:
    """Mili-giây để giải thích MỘT cảnh báo, gọi từng dòng một: `total` (gồm chấm điểm lại ba thành phần để biết thành phần nào báo) và `explain`
    (chỉ phần giải thích của thành phần đã báo — thứ luồng realtime phải trả thêm khi đã có điểm)."""
    legit = world.tasks["ato/future"].frame.query("~y")
    pool = world.flagged(legit.sample(min(60_000, len(legit)), random_state=seed))
    pool = pool.sample(min(n, len(pool)), random_state=seed)
    components = {c.name: c for c in world.hybrid.components}
    total, explain_only = [], []
    for i in range(len(pool)):
        row = pool.iloc[[i]]
        started = time.perf_counter()
        (explanation,) = world.explainer.explain(row)
        total.append((time.perf_counter() - started) * 1000)
        started = time.perf_counter()
        Ex.explain_component(components[explanation.component].scorer, row, world.reference)
        explain_only.append((time.perf_counter() - started) * 1000)

    def summary(values):
        return {"p50": float(np.percentile(values, 50)), "p95": float(np.percentile(values, 95)), "p99": float(np.percentile(values, 99))}

    return {"n": len(pool), "total_ms": summary(total), "explain_ms": summary(explain_only)}


# ------------------------------------------------------------------------------------------------ bảng markdown

_COMPONENT_VI = {"ip_tan_cong": "IP tấn công", "chiem_tai_khoan": "chiếm tài khoản", "bat_thuong": "bất thường"}


def faithfulness_markdown(result: dict) -> str:
    """Bốn bảng nhỏ: cần thiết (xoá k yếu tố), cần thiết (chỉ xoá yếu tố đầu), đủ (chỉ giữ k yếu tố), điểm còn lại. Mỗi bảng: giải thích / ngẫu nhiên / quan trọng toàn cục."""
    specs = [
        ("necessity_k", "Xoá các yếu tố nêu ra → phần cảnh báo BIẾN MẤT (cao = giải thích trỏ đúng thứ mô hình dựa vào)"),
        ("necessity_1", "Chỉ xoá yếu tố ĐỨNG ĐẦU → phần cảnh báo biến mất"),
        ("sufficiency_k", "Chỉ GIỮ các yếu tố nêu ra (xoá mọi yếu tố còn lại) → phần cảnh báo CÒN"),
        ("retention_k", "Chỉ GIỮ các yếu tố nêu ra → điểm còn lại so với điểm gốc (điểm cảnh báo sát ngưỡng nên phép thử trên khắt khe hơn)"),
    ]
    blocks = []
    for key, title in specs:
        lines = [f"**{title}**", "", "| Nhóm cảnh báo | Thành phần | Số cảnh báo | Yếu tố/cảnh báo | Giải thích | Ngẫu nhiên | Quan trọng toàn cục |", "|---|---|---|---|---|---|---|"]
        for name, info in result.items():
            for r in info["components"]:
                v = r[key]
                lines.append(f"| {name} | `{r['component']}` | {r['n']:,} | {r['mean_factors']:.2f} | **{v['explanation']:.0%}** | {v['random']:.0%} | {v['global']:.0%} |")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def length_markdown(result: dict) -> str:
    lines = ["| Nhóm cảnh báo | Số cảnh báo | Độ dài trung vị (ký tự) | p95 | Dài nhất | Không có yếu tố nào |", "|---|---|---|---|---|---|"]
    for name, info in result.items():
        n, length = info["n_flagged"], info["length"]
        lines.append(f"| {name} | {n:,} | {length['median']:.0f} | {length['p95']:.0f} | {length['max']} | {length['empty']} |")
    return "\n".join(lines)


def frequency_markdown(result: dict, top: int = 5) -> str:
    lines = ["| Nhóm cảnh báo | Thành phần | Yếu tố hay đứng trong giải thích (phần cảnh báo có yếu tố đó) |", "|---|---|---|"]
    for name, info in result.items():
        for component, freq in info["concept_frequency"].items():
            items = [(c, v) for c, v in freq.items() if c != "n"][:top]
            lines.append(f"| {name} | `{component}` ({freq['n']:,}) | " + ", ".join(f"{Ex.CONCEPT_TITLES[c]} {v:.0%}" for c, v in items) + " |")
    return "\n".join(lines)


def global_markdown(result: dict) -> str:
    lines = []
    for component, table in result.items():
        lines += [f"**`{component}`** — đóng góp SHAP tuyệt đối trung bình theo yếu tố:", "", "| Yếu tố | Đóng góp trung bình (log-odds) | Tỉ trọng | Phần đăng nhập mà yếu tố đẩy điểm LÊN |", "|---|---|---|---|"]
        lines += [f"| {Ex.CONCEPT_TITLES[r['concept']]} | {r['mean_abs']:.3f} | {r['share']:.1%} | {r['pushes_up']:.1%} |" for r in table]
        lines.append("")
    return "\n".join(lines)


def examples_markdown(rows: list[dict]) -> str:
    lines = ["| Nhóm | Điểm | Loại | Giải thích (chỉ có đặc trưng) | Giải thích (thêm ngữ cảnh tài khoản) |", "|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['set']} | {r['score']:.2f} | {r['label']} ({'SHAP' if r['method'] == 'shap' else 'z-score'}) | {r['no_context']} | {r['with_context'] if r['has_context'] else '—'} |")
    return "\n".join(lines)


def latency_markdown(result: dict) -> str:
    lines = [f"Giải thích từng cảnh báo một ({result['n']} cảnh báo, mili-giây):", "", "| | p50 | p95 | p99 |", "|---|---|---|---|"]
    for key, title in (("total_ms", "toàn bộ (gồm chấm điểm lại ba thành phần)"), ("explain_ms", "chỉ phần giải thích của thành phần đã báo")):
        v = result[key]
        lines.append(f"| {title} | {v['p50']:.1f} | {v['p95']:.1f} | {v['p99']:.1f} |")
    return "\n".join(lines)


def operating_markdown(result: dict) -> str:
    names = list(result["levels"][0]["recall"])
    lines = [
        "| FPR mục tiêu (val) | Ngưỡng | FPR thực tế val / test / late | Cảnh báo nhầm / 10 nghìn đăng nhập | " + " | ".join(f"Recall {n}" for n in names) + " |",
        "|---|---|---|---|" + "---|" * len(names),
    ]
    for level in result["levels"]:
        f = level["fpr"]
        lines.append(
            f"| {level['target_fpr']:.1%} | {level['threshold']:.3f} | {f['val']:.2%} / {f['test']:.2%} / {f['late']:.2%} | {level['false_alerts_per_10k']:.0f} | "
            + " | ".join(f"{level['recall'][n]:.1%}" for n in names) + " |"
        )
    lines += ["", "Độ chính xác của cảnh báo (phần cảnh báo là tấn công thật) theo tỉ lệ tấn công giả định trong số đăng nhập thành công, dùng recall ATO thật tương lai:", "", "| Tỉ lệ tấn công | " + " | ".join(f"FPR {level['target_fpr']:.1%}" for level in result["levels"]) + " |", "|---|" + "---|" * len(result["levels"])]
    for prevalence in result["prevalences"]:
        cells = [f"{precision_at(level['recall']['ATO thật tương lai (38)'], level['fpr']['test'], prevalence):.2%}" for level in result["levels"]]
        lines.append(f"| 1 trên {1 / prevalence:,.0f} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


# ------------------------------------------------------------------------------------------------ dòng lệnh


def _save(name: str, payload, directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=float), encoding="utf-8")


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    what = args[0] if args else "all"
    hybrid_name = sys.argv[sys.argv.index("--hybrid") + 1] if "--hybrid" in sys.argv else HYBRID_NAME
    out_dir = OUT_DIR if hybrid_name == "hybrid" else CP2_OUT_DIR
    started = time.time()

    def say(message: str) -> None:
        print(f"  [{time.time() - started:6.0f}s] {message}", flush=True)

    say("nạp bảng đặc trưng, mô hình và tạo bảng 'thường thấy'")
    world = World.load(hybrid_name=hybrid_name)
    say(f"ngưỡng hybrid (val): " + ", ".join(f"FPR {t:.1%} → {v:.3f}" for t, v in world.thresholds.items()))
    if what in ("reference", "all"):
        path = world.reference.save()
        say(f"đã lưu {path} ({world.reference.n_rows:,} dòng, chữ ký đặc trưng {world.reference.signature})")
    if what in ("operating", "all"):
        result = run_operating(world)
        _save("operating", result, out_dir)
        print("\n### Ngưỡng vận hành\n\n" + operating_markdown(result), flush=True)
    if what in ("faithfulness", "all"):
        result = run_faithfulness(world, say)
        _save("faithfulness", result, out_dir)
        print("\n### Phép thử xoá yếu tố\n\n" + faithfulness_markdown(result), flush=True)
        print("\n### Yếu tố hay đứng trong giải thích\n\n" + frequency_markdown(result), flush=True)
        print("\n### Độ dài câu giải thích\n\n" + length_markdown(result), flush=True)
    if what in ("global", "all"):
        result = run_global(world)
        _save("global", result, out_dir)
        print("\n### SHAP toàn cục\n\n" + global_markdown(result), flush=True)
    if what in ("examples", "all"):
        rows = run_examples(world)
        _save("examples", rows, out_dir)
        print("\n### Ví dụ\n\n" + examples_markdown(rows), flush=True)
    if what in ("latency", "all"):
        result = run_latency(world)
        _save("latency", result, out_dir)
        print("\n### Độ trễ\n\n" + latency_markdown(result), flush=True)
    say("xong")
    return 0


if __name__ == "__main__":
    sys.exit(main())
