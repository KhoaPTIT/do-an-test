"""Tinh chỉnh ngưỡng luật trên train RBA, báo cáo trên test (MR10).

    cd backend
    venv\\Scripts\\python.exe -m ml.rba.rule_tuning collect     # MỘT lượt replay toàn bộ RBA (~30 phút): mức "bậc thang" của mọi luật cho mọi dòng của mẫu ML
    venv\\Scripts\\python.exe -m ml.rba.rule_tuning tune        # chọn bậc trên train, đo trên val/test/late -> docs/rule-tuning.md + hồ sơ cấu hình luật

THIẾT KẾ (tại sao không chạy lại engine cho từng bộ ngưỡng):

  Mỗi luật có một "bậc thang" (`Ladder`): dãy bộ tham số xếp từ LỎNG đến CHẶT sao cho các lần khớp lồng nhau (khớp ở bậc chặt ⇒ khớp ở mọi bậc lỏng hơn). Engine chạy MỘT lần trên toàn bộ
  luồng RBA; với mỗi dòng thuộc mẫu ML, `collect_levels` hỏi cùng hàm luật ở từng bậc (`RuleEngine.probe`) và ghi lại số bậc mà luật còn khớp. Sau đó chọn bậc là phép tính trên mảng, không
  cần chạy lại engine. Các dòng KHÔNG thuộc mẫu chỉ đi qua `RuleEngine.observe` (cập nhật trạng thái, không chạy luật): 91% số dòng, gồm 45% là lần thử vào tên không tồn tại.

  Đánh giá trên ĐÚNG các dòng, trọng số và định nghĩa dương/âm của khung đánh giá ML (`eval_tasks`): tài khoản có thật trong mẫu phân tầng, trọng số dân số `pop_weight`, dòng tấn công theo
  nhóm IP của giai đoạn. Nhờ đó số của luật và số của mô hình so được trực tiếp, và bảng chồng lấn (rule_overlap.py) dùng cùng dòng.

  Chọn bậc: CHỈ trên phân vùng train — bậc LỎNG NHẤT có tỉ lệ khớp trên dòng bình thường ≤ ngân sách (mặc định 5 lần khớp trên 10.000 đăng nhập hợp lệ thành công, đặt trước khi xem kết quả);
  recall không tham gia chọn (lỏng hơn thì recall không giảm) nên nhãn tấn công/ATO không chọn ngưỡng, chỉ định nghĩa "dòng bình thường". val/test/late/ATO chỉ để báo cáo.

GIỚI HẠN đã biết: quét MỘT chiều cho mỗi luật (các tham số còn lại giữ nguyên mặc định; luật hai điều kiện quét dọc một tia tỉ lệ), số tên khác nhau tối đa 200 (`indexes.CAP`), dòng không nhãn coi là
bình thường nên số khớp trên chúng là cận trên của báo nhầm, và kết quả chỉ nói về RBA (tổng hợp).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable, Mapping, Sequence

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from app.detection.engine import REGISTRY, LoginAttempt, RuleConfig, RuleEngine
from app.detection.engine.replay import rss_mb
from ml.rba import eval_tasks, splits
from ml.rba.build_features import MODEL_TABLE_PARQUET
from ml.rba.rule_replay import rba_rows
from ml.rba.sample import SAMPLE_PARQUET

ARTIFACT_DIR = Path(__file__).resolve().parents[1] / "artifacts" / "rule_tuning"
LEVELS_PARQUET = ARTIFACT_DIR / "levels.parquet"
TUNING_JSON = ARTIFACT_DIR / "tuning.json"
DOCS_DIR = Path(__file__).resolve().parents[3] / "docs"
DOC_PATH = DOCS_DIR / "rule-tuning.md"
PROFILE_PATH = Path(__file__).resolve().parents[2] / "app" / "detection" / "engine" / "profiles" / "rba_train_tuned.json"

BUDGETS = (2.0, 5.0, 10.0)  # số lần khớp trên dòng bình thường cho mỗi 10.000 đăng nhập hợp lệ thành công (chọn trên train)
PRIMARY_BUDGET = 5.0  # đặt trước khi xem kết quả: 14 luật x 5 ≈ tối đa 70/10.000, giữa ngưỡng 0,1% (~11) và 1% (~93) của hybrid
PARTITIONS = ("train", "val", "test", "late")
N_BOOT = 300

_NO_STUFFING_IP = {"min_fails": 100_000, "min_users": 100_000}  # tắt phạm vi IP của credential_stuffing (đưa ngưỡng lên tối đa)
_NO_STUFFING_ASN = {"asn_min_fails": 1_000_000, "asn_min_users": 1_000_000}
_NO_SPRAY_IP = {"min_users": 100_000}
_NO_SPRAY_ASN = {"asn_min_users": 1_000_000}


# ------------------------------------------------------------------------------------------------ bậc thang


@dataclass(frozen=True)
class Ladder:
    """Dãy bộ tham số của MỘT luật (hoặc một phạm vi của luật) từ lỏng đến chặt. `fixed` áp cho mọi bậc (tắt phạm vi còn lại); `default_rung` (từ 1) là bậc trùng với mặc định của luật."""

    name: str
    rule_id: str
    rungs: tuple[Mapping[str, Any], ...]
    default_rung: int | None = None
    fixed: Mapping[str, Any] = field(default_factory=dict)
    scope: str | None = None  # giá trị `evidence["scope"]` của lần khớp thuộc bậc thang này (luật nhiều phạm vi)
    note: str = ""

    def params(self, rung: int) -> dict[str, Any]:
        """Bộ tham số đầy đủ (ghi đè so với mặc định) của bậc `rung` (từ 1)."""
        return {**self.fixed, **self.rungs[rung - 1]}

    def resolved(self, registry=None) -> list[SimpleNamespace]:
        """Tham số đã giải quyết và kiểm tra khoảng hợp lệ (qua `RuleConfig`) của từng bậc."""
        registry = REGISTRY if registry is None else registry
        spec = registry[self.rule_id]
        return [RuleConfig.from_dict({"rules": {self.rule_id: {"params": self.params(r)}}}, registry).resolved_params(spec) for r in range(1, len(self.rungs) + 1)]

    @property
    def column(self) -> str:
        return "L__" + self.name.replace("/", "__")

    def describe(self, rung: int) -> str:
        return ", ".join(f"{k}={v:g}" if isinstance(v, float) else f"{k}={v}" for k, v in self.rungs[rung - 1].items()) or "(không tham số)"


def _ray(names: tuple[str, str], pairs) -> tuple[dict[str, int], ...]:
    return tuple({names[0]: a, names[1]: b} for a, b in pairs)


# Các bậc chỉ dùng tham số "tối thiểu" (điều kiện dạng ≥ ngưỡng, hoặc ≤ ngưỡng với max_share) nên nhất quán đơn điệu; test kiểm tra tính lồng nhau trên lưu lượng ngẫu nhiên.
LADDERS: tuple[Ladder, ...] = (
    Ladder("brute_force", "brute_force", tuple({"threshold": v} for v in (3, 4, 5, 6, 8, 10, 15, 20, 30, 50)), default_rung=3),
    Ladder(
        "credential_stuffing/ip", "credential_stuffing", _ray(("min_fails", "min_users"), [(4, 2), (6, 3), (8, 4), (10, 5), (15, 8), (20, 10), (30, 15), (50, 25), (100, 50)]),
        default_rung=4, fixed=_NO_STUFFING_ASN, scope="ip", note="phạm vi IP; tỉ lệ 2 lần sai : 1 tên như mặc định; phạm vi ASN tắt",
    ),
    Ladder(
        "credential_stuffing/asn", "credential_stuffing",
        _ray(("asn_min_fails", "asn_min_users"), [(20, 10), (30, 15), (40, 20), (60, 30), (80, 40), (120, 60), (160, 80), (240, 120), (400, 200)]),
        default_rung=3, fixed=_NO_STUFFING_IP, scope="asn", note="phạm vi ASN; số tên khác nhau tối đa 200 (CAP); phạm vi IP tắt",
    ),
    Ladder(
        "password_spray_slow/ip", "password_spray_slow", tuple({"min_users": v} for v in (5, 8, 10, 15, 20, 30, 50, 80, 150)),
        default_rung=4, fixed=_NO_SPRAY_ASN, scope="ip", note="phạm vi IP (24 giờ, ≤ 3 lần sai/tài khoản, ≤ 120 lần/giờ); phạm vi ASN tắt",
    ),
    Ladder(
        "password_spray_slow/asn", "password_spray_slow", tuple({"asn_min_users": v} for v in (20, 40, 60, 80, 100, 150, 200)),
        default_rung=2, fixed=_NO_SPRAY_IP, scope="asn", note="phạm vi ASN; số tên khác nhau tối đa 200 (CAP); phạm vi IP tắt",
    ),
    Ladder("distributed_bruteforce", "distributed_bruteforce", _ray(("min_fails", "min_ips"), [(4, 3), (6, 4), (8, 5), (12, 8), (16, 10), (24, 15), (40, 25), (80, 50)]), default_rung=3),
    Ladder("success_after_failures", "success_after_failures", tuple({"min_fails": v} for v in (2, 3, 4, 5, 6, 8, 10, 15, 25)), default_rung=4),
    Ladder("ua_rotation", "ua_rotation", _ray(("min_fails", "min_distinct_ua"), [(4, 3), (6, 4), (8, 5), (12, 7), (16, 10), (24, 15), (40, 25)]), default_rung=3),
    Ladder("dormant_account_login", "dormant_account_login", tuple({"dormant_days": v} for v in (14, 30, 60, 90, 120, 180, 270, 365)), default_rung=4, note="luôn kèm điều kiện quốc gia/thiết bị mới"),
    Ladder(
        "rare_network_login", "rare_network_login", tuple({"max_share": v} for v in (1e-3, 5e-4, 2e-4, 1e-4, 5e-5, 2e-5, 1e-5, 5e-6, 2e-6, 1e-6, 0.0)),
        default_rung=6, note="chặt = tỉ lệ toàn hệ thống của ASN càng nhỏ; 0 = chưa từng thấy",
    ),
    Ladder("multi_context_simultaneous", "multi_context_simultaneous", tuple({"window_s": v} for v in (1800, 900, 600, 300, 120, 60, 30)), default_rung=3, note="chặt = cửa sổ ngắn hơn"),
    Ladder("country_hop", "country_hop", tuple({"min_countries": v} for v in (2, 3, 4, 5, 6)), default_rung=2),
    Ladder("bot_user_agent", "bot_user_agent", ({},), default_rung=1, note="không có tham số"),
    Ladder("scripted_client", "scripted_client", ({},), default_rung=1, note="không có tham số quét được (danh sách chuỗi công cụ cố định)"),
)

# Bậc thang KHÔNG đưa vào hồ sơ cấu hình dù chọn được bậc, kèm lý do. Quyết định này được đưa ra SAU khi thấy chúng không giữ được ngoài train (docs/rule-tuning.md mục 1 nói rõ điều đó và
# đưa số liệu); lý do là cơ chế chứ không phải kết quả test: số tuyệt đối theo nhà mạng phụ thuộc lưu lượng, còn số ngày ngủ đông tăng theo tuổi của log.
PROFILE_EXCLUDED = {
    "credential_stuffing/asn": "số lần sai và số tên tuyệt đối của một nhà mạng phụ thuộc lưu lượng của nó, mà lưu lượng thay đổi theo thời gian; cần điều kiện tương đối (tỉ lệ sai) chứ không phải ngưỡng tuyệt đối",
    "dormant_account_login": "số tài khoản đã có ≥ N ngày lịch sử tăng dần theo tuổi của log nên tỉ lệ khớp tăng dần: ngưỡng chọn trên đoạn đầu của log luôn quá lạc quan",
}

NOT_EVALUABLE = {
    "username_enumeration": "chỉ khớp ở lần thử vào tên không tồn tại; RBA gộp các lần đó vào một user_id (45% số dòng), bị loại khỏi mẫu ML nên không có dòng nào để so với mô hình",
    "regular_rhythm": "dựa vào nhịp cách nhau vài giây, còn timestamp của RBA có thành phần ngẫu nhiên (thẻ dữ liệu)",
    "impossible_travel": "RBA không có toạ độ",
    "tor_exit": "IP của RBA là tổng hợp, danh sách Tor công khai không áp dụng",
    "datacenter_ip": "IP của RBA là tổng hợp, danh sách datacenter công khai không áp dụng",
    "vpn_ip": "IP của RBA là tổng hợp, danh sách VPN công khai không áp dụng",
    "blocklist_hit": "không có mục chặn do quản trị viên đặt",
}


def ladder_by_name() -> dict[str, Ladder]:
    return {ladder.name: ladder for ladder in LADDERS}


# ------------------------------------------------------------------------------------------------ thu thập: một lượt replay


def collect_levels(
    rows: Iterable[tuple[int, LoginAttempt]],
    sample_row_ids: np.ndarray,
    ladders: Sequence[Ladder] = LADDERS,
    *,
    engine: RuleEngine | None = None,
    progress=None,
    progress_every: int = 2_000_000,
) -> np.ndarray:
    """Cho luồng `(row_id, lần thử)` theo thứ tự thời gian, trả mảng uint8 `(số bậc thang, số dòng mẫu)`: `[k, i]` = số bậc (từ 1) mà luật của bậc thang `k` còn khớp ở dòng mẫu thứ `i`
    (thứ tự của `sample_row_ids`); 0 = không khớp ngay cả ở bậc lỏng nhất hoặc luật thiếu dữ liệu. Dòng ngoài mẫu chỉ được `observe`."""
    engine = RuleEngine() if engine is None else engine
    ids = np.asarray(sample_row_ids, dtype=np.int64)
    size = int(ids.max()) + 1 if len(ids) else 0
    index = np.full(size, -1, dtype=np.int32)
    index[ids] = np.arange(len(ids), dtype=np.int32)
    plan = [(engine.registry[ladder.rule_id], ladder.resolved(engine.registry)) for ladder in ladders]
    levels = np.zeros((len(ladders), len(ids)), dtype=np.uint8)
    started, seen = time.perf_counter(), 0

    for row_id, attempt in rows:
        seen += 1
        i = int(index[row_id]) if row_id < size else -1
        if i < 0:
            engine.observe(attempt)
        else:
            with engine.probe(attempt) as probe:
                for k, (spec, resolved) in enumerate(plan):
                    level = 0
                    for rung, params in enumerate(resolved, start=1):
                        if probe.run(spec, params) is None:
                            break
                        level = rung
                    levels[k, i] = level
        if progress is not None and progress_every and seen % progress_every == 0:
            progress(seen, attempt.ts, time.perf_counter() - started)
    return levels


def save_levels(levels: np.ndarray, sample_row_ids: np.ndarray, ladders: Sequence[Ladder] = LADDERS, path: Path = LEVELS_PARQUET) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    table = {"row_id": pa.array(np.asarray(sample_row_ids, dtype=np.int64))}
    for k, ladder in enumerate(ladders):
        table[ladder.column] = pa.array(levels[k])
    pq.write_table(pa.table(table), path, compression="zstd")
    definition = [{"name": l.name, "rule_id": l.rule_id, "rungs": [dict(r) for r in l.rungs], "fixed": dict(l.fixed), "default_rung": l.default_rung} for l in ladders]
    path.with_suffix(".ladders.json").write_text(json.dumps(definition, ensure_ascii=False, indent=1), encoding="utf-8")


# ------------------------------------------------------------------------------------------------ khung dữ liệu và số đo


def load_frame(levels_path: Path = LEVELS_PARQUET, ladders: Sequence[Ladder] = LADDERS) -> pd.DataFrame:
    """Bảng mô hình (chỉ các cột cần), trọng số dân số và mức bậc thang của từng dòng — cùng dòng với khung đánh giá ML."""
    columns = ["row_id", "ts", "user_id", "stratum", "forced", "partition", "weight", "is_attack_ip", "is_ato", "in_warmup", "cur_success", "u_n_success"]
    df = pq.read_table(MODEL_TABLE_PARQUET, columns=columns).to_pandas()
    df = df.merge(pq.read_table(SAMPLE_PARQUET, columns=["row_id", "ip"]).to_pandas(), on="row_id", how="left")
    df = eval_tasks.add_population_weights(df)
    levels = pq.read_table(levels_path).to_pandas()
    missing = [l.column for l in ladders if l.column not in levels]
    if missing:
        raise ValueError(f"tệp mức bậc thang thiếu cột {missing} — chạy lại `python -m ml.rba.rule_tuning collect`")
    return df.merge(levels, on="row_id", how="inner")


class Part:
    """Các mảng của MỘT phân vùng (đã bỏ dòng warm-up) và phép đo tỉ lệ khớp / recall có trọng số dân số, đúng định nghĩa của `eval_tasks.attack_ip/<phân vùng>`."""

    def __init__(self, frame: pd.DataFrame, part: str):
        mask = ((frame["partition"] == part) & ~frame["in_warmup"]).to_numpy()
        sub = frame[mask]
        self.name, self.index = part, np.flatnonzero(mask)  # vị trí trong `frame`, không phải nhãn chỉ số
        self.w = sub["pop_weight"].to_numpy(dtype=float)
        self.attack = sub["is_attack_ip"].to_numpy(dtype=bool)
        self.success = sub["cur_success"].to_numpy() == 1
        self.ip = sub["ip"].to_numpy()
        self.normal = ~self.attack
        self.legit_success = self.normal & self.success
        self.den_fa = float(self.w[self.legit_success].sum())
        self.den_recall = float(self.w[self.attack].sum())

    def metrics(self, flagged: np.ndarray) -> dict[str, float]:
        """`flagged`: mảng bool theo thứ tự của phân vùng. fa10k = trọng số khớp trên dòng bình thường (mọi kết quả) / trọng số đăng nhập hợp lệ thành công x 10.000."""
        w = self.w
        return {
            "fa10k": float(w[flagged & self.normal].sum() / self.den_fa * 10_000) if self.den_fa else float("nan"),
            "fa10k_success": float(w[flagged & self.legit_success].sum() / self.den_fa * 10_000) if self.den_fa else float("nan"),
            "recall": float(w[flagged & self.attack].sum() / self.den_recall) if self.den_recall else float("nan"),
            "n_attack": int(self.attack.sum()),
        }

    def ci(self, flagged: np.ndarray, n_boot: int = N_BOOT, seed: int = 0) -> dict[str, tuple[float, float]]:
        """Khoảng tin cậy 95% (lấy mẫu lại theo cụm IP) của fa10k và recall."""
        codes, _ = pd.factorize(pd.Series(self.ip).fillna("?").to_numpy())
        n = codes.max() + 1
        by = lambda values: np.bincount(codes, weights=values, minlength=n)
        num_fa, den_fa = by(self.w * (flagged & self.normal)), by(self.w * self.legit_success)
        num_rc, den_rc = by(self.w * (flagged & self.attack)), by(self.w * self.attack)
        rng = np.random.default_rng(seed)
        fa, rc = [], []
        for _ in range(n_boot):
            pick = rng.integers(0, n, n)
            fa.append(num_fa[pick].sum() / max(den_fa[pick].sum(), 1e-12) * 10_000)
            rc.append(num_rc[pick].sum() / max(den_rc[pick].sum(), 1e-12))
        return {"fa10k": tuple(np.percentile(fa, [2.5, 97.5])), "recall": tuple(np.percentile(rc, [2.5, 97.5]))}


class AtoSet:
    """Các ca ATO (cả quá khứ lẫn tương lai) và số ca mà một mảng cờ bắt được; trọng số 1 (100% user có ATO được lấy mẫu)."""

    def __init__(self, frame: pd.DataFrame):
        mask = (frame["is_ato"] & ~frame["in_warmup"]).to_numpy()
        sub = frame[mask]
        self.index = np.flatnonzero(mask)
        self.user = sub["user_id"].to_numpy()
        ts = sub["ts"]
        self.groups = {
            "past": (ts < splits.VAL_END).to_numpy(),
            "future": ((ts >= splits.VAL_END) & (ts < splits.TEST_END)).to_numpy(),
            "all": np.ones(len(sub), dtype=bool),
        }

    def counts(self, flagged: np.ndarray) -> dict[str, tuple[int, int]]:
        return {name: (int((flagged & mask).sum()), int(mask.sum())) for name, mask in self.groups.items()}


@dataclass
class RungRow:
    rung: int
    params: str
    by_part: dict[str, dict[str, float]]
    ato: dict[str, tuple[int, int]]


def rung_rows(frame: pd.DataFrame, ladder: Ladder, parts: Mapping[str, Part], ato: AtoSet) -> list[RungRow]:
    levels = frame[ladder.column].to_numpy()
    rows = []
    for rung in range(1, len(ladder.rungs) + 1):
        by_part = {name: part.metrics(levels[part.index] >= rung) for name, part in parts.items()}
        rows.append(RungRow(rung, ladder.describe(rung), by_part, ato.counts(levels[ato.index] >= rung)))
    return rows


def select_rung(rows: Sequence[RungRow], budget: float, parts: Sequence[str] = ("train",)) -> int | None:
    """Bậc LỎNG NHẤT có fa10k ≤ ngân sách ở MỌI phân vùng trong `parts` (mặc định chỉ train — quy trình đặt trước; `("train", "val")` là quy trình sửa, xem docs/rule-tuning.md mục 1);
    None nếu ngay cả bậc chặt nhất vượt ngân sách (luật không dùng được ở ngân sách này)."""
    for row in rows:
        if all(row.by_part[part]["fa10k"] <= budget for part in parts):
            return row.rung
    return None


# ------------------------------------------------------------------------------------------------ hồ sơ cấu hình


def build_profile(selection: Mapping[str, int | None], ladders: Sequence[Ladder] = LADDERS, excluded: Mapping[str, str] = PROFILE_EXCLUDED) -> dict[str, Any]:
    """`RuleConfig` JSON của bộ luật đã tinh chỉnh. Luật nhiều phạm vi gộp tham số của các bậc thang đã chọn; phạm vi không chọn được (hoặc thuộc `excluded`) thì bị tắt bằng cách đưa ngưỡng lên tối đa;
    luật không còn phạm vi nào chuyển sang `shadow` (vẫn ghi nhận để đo, không tạo cảnh báo). Luật không có bậc thang giữ nguyên mặc định."""
    selection = {name: (None if name in excluded else rung) for name, rung in selection.items()}
    by_rule: dict[str, list[Ladder]] = {}
    for ladder in ladders:
        by_rule.setdefault(ladder.rule_id, []).append(ladder)
    rules: dict[str, dict[str, Any]] = {}
    for rule_id, group in by_rule.items():
        chosen = [(l, selection.get(l.name)) for l in group]
        if all(rung is None for _, rung in chosen):
            rules[rule_id] = {"mode": "shadow"}
            continue
        params: dict[str, Any] = {}
        for ladder, rung in chosen:
            if rung is None:
                params.update(ladder.fixed if len(group) == 1 else _disable(ladder, group))
            else:
                params.update(ladder.rungs[rung - 1])
        default_mode = REGISTRY[rule_id].default_mode
        entry: dict[str, Any] = {"params": params}
        if default_mode != "enforce":
            entry["mode"] = default_mode
        rules[rule_id] = entry
    return {"rules": rules}


def _disable(ladder: Ladder, group: Sequence[Ladder]) -> dict[str, Any]:
    """Tham số tắt phạm vi của `ladder`: chính là `fixed` của bậc thang KIA (tắt phạm vi này trong khi quét phạm vi kia)."""
    other = next(l for l in group if l is not ladder)
    return dict(other.fixed)


# ------------------------------------------------------------------------------------------------ chạy


def _progress(seen: int, ts: float, elapsed: float) -> None:
    rss = rss_mb()
    print(f"  {seen:>12,} dòng · {seen / max(elapsed, 1e-9):,.0f}/giây · {elapsed:,.0f}s" + ("" if rss is None else f" · {rss:,.0f} MB"), flush=True)


def cmd_collect(args: argparse.Namespace) -> int:
    ids = np.sort(pq.read_table(MODEL_TABLE_PARQUET, columns=["row_id"]).column("row_id").to_numpy())
    print(f"thu thập mức bậc thang của {len(LADDERS)} bậc thang trên {len(ids):,} dòng mẫu (toàn bộ luồng RBA đi qua engine) …", flush=True)
    started = time.perf_counter()
    levels = collect_levels(rba_rows(start=args.start, end=args.end, limit=args.limit), ids, progress=_progress)
    out = Path(args.out) if args.out else LEVELS_PARQUET
    save_levels(levels, ids, path=out)
    print(f"đã ghi {out} sau {time.perf_counter() - started:,.0f} giây; dòng có ít nhất một luật khớp: {int((levels > 0).any(axis=0).sum()):,}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m ml.rba.rule_tuning", description="Tinh chỉnh ngưỡng luật trên train RBA (MR10).")
    sub = parser.add_subparsers(dest="command", required=True)
    collect = sub.add_parser("collect", help="một lượt replay toàn bộ RBA, ghi mức bậc thang của mọi dòng mẫu")
    collect.add_argument("--start")
    collect.add_argument("--end")
    collect.add_argument("--limit", type=int)
    collect.add_argument("--out", help=f"mặc định {LEVELS_PARQUET}")
    tune = sub.add_parser("tune", help="chọn bậc trên train, đo trên val/test/late, ghi docs/rule-tuning.md và hồ sơ cấu hình")
    tune.add_argument("--levels", help=f"mặc định {LEVELS_PARQUET}")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError, OSError):
        pass
    if args.command == "collect":
        return cmd_collect(args)
    from ml.rba import rule_tuning_report

    return rule_tuning_report.run(Path(args.levels) if args.levels else LEVELS_PARQUET)


if __name__ == "__main__":
    sys.exit(main())
