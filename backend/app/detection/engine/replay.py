"""Bộ replay (MR9): phát lại log đăng nhập lịch sử qua rule engine v2 và đo TỪNG luật.

    cd backend
    venv\\Scripts\\python.exe -m app.detection.engine.replay rba --start 2020-02-03 --end 2020-08-01 --out ../docs/rule-replay.md
    venv\\Scripts\\python.exe -m app.detection.engine.replay db --config rules.json

Luồng: bộ chuyển đổi (RBA, bảng `login_events`, hay bất kỳ danh sách nào) sinh `LoginAttempt` THEO THỨ TỰ THỜI GIAN → `replay()` đưa từng lần thử vào
`RuleEngine.evaluate` (cùng đường chấm với luồng thật và test) → `ReplayReport` với số đo của từng luật.

NHÃN (`LoginAttempt.labels`, ví dụ RBA `is_attack_ip`/`is_ato`) chỉ được ĐỌC Ở ĐÂY để chấm điểm luật sau khi engine đã trả kết quả; engine và luật không bao giờ
thấy chúng (tests/test_rule_engine_engine.py đổi nhãn và kiểm tra kết quả không đổi). Dòng "không nhãn" được coi là hợp lệ — giả định của bộ dữ liệu, không phải sự thật
tuyệt đối. Các con số là ĐO LƯỜNG MÔ TẢ của luật với tham số cho trước, chưa phải kết quả đã tinh chỉnh (tinh chỉnh ngưỡng là MR10).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping

from app.detection.engine.engine import RuleEngine
from app.detection.engine.intel import ThreatIntel
from app.detection.engine.registry import RuleConfig
from app.detection.engine.types import LoginAttempt

SAMPLE_LIMIT = 3  # số ví dụ giữ lại cho mỗi luật (mỗi loại: trên dòng có nhãn / không nhãn)
DAY = 86_400.0
_LATENCY_STEP_MS = 0.05
_LATENCY_BUCKETS = 4_000  # tới 200 ms; chậm hơn dồn vào ô cuối


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def rss_mb() -> float | None:
    """Bộ nhớ (MB) tiến trình đang giữ; None nếu nền tảng không cho biết. Dùng psutil nếu có, không thì Win32/`resource`."""
    try:
        import psutil

        return psutil.Process().memory_info().rss / 2**20
    except ImportError:
        pass
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD), ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t), ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        kernel32, psapi = ctypes.WinDLL("kernel32"), ctypes.WinDLL("psapi")
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        counters = Counters()
        counters.cb = ctypes.sizeof(Counters)
        ok = psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb)
        return counters.WorkingSetSize / 2**20 if ok else None
    try:
        import resource

        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    except ImportError:
        return None


# ------------------------------------------------------------------------------------------------ số đo


@dataclass
class Tally:
    """Số lần khớp của MỘT luật (hoặc của "bất kỳ luật nào") chia theo nhãn của dòng bị khớp."""

    hits: int = 0
    success_hits: int = 0  # khớp ở lần đăng nhập thành công (phần còn lại: ở lần thất bại)
    unlabelled: int = 0  # khớp trên dòng KHÔNG nhãn (coi là báo nhầm)
    unlabelled_success: int = 0
    by_label: Counter = field(default_factory=Counter)  # nhãn -> số dòng mang nhãn đó bị khớp
    ips_by_label: dict[str, set[str]] = field(default_factory=dict)  # nhãn -> IP khác nhau bị khớp ít nhất một lần
    unlabelled_ips: set[str] = field(default_factory=set)  # IP khác nhau bị khớp trên dòng không nhãn: số nguồn báo nhầm, khác với số lần khớp
    by_scope: Counter = field(default_factory=Counter)  # luật có nhiều phạm vi (`evidence["scope"]`: ip/asn) -> số lần khớp theo phạm vi
    unlabelled_by_scope: Counter = field(default_factory=Counter)
    samples: dict[str, list[dict[str, Any]]] = field(default_factory=lambda: {"labelled": [], "unlabelled": []})

    def observe(self, attempt: LoginAttempt, labels: tuple[str, ...], message: str | None = None, scope: str | None = None) -> None:
        self.hits += 1
        if attempt.success:
            self.success_hits += 1
        if scope:
            self.by_scope[scope] += 1
        if labels:
            for name in labels:
                self.by_label[name] += 1
                ips = self.ips_by_label.get(name)
                if ips is None:
                    ips = self.ips_by_label[name] = set()
                ips.add(attempt.ip)
            kind = "labelled"
        else:
            self.unlabelled += 1
            self.unlabelled_ips.add(attempt.ip)
            if attempt.success:
                self.unlabelled_success += 1
            if scope:
                self.unlabelled_by_scope[scope] += 1
            kind = "unlabelled"
        bucket = self.samples[kind]
        if message is not None and len(bucket) < SAMPLE_LIMIT and all(s["ip"] != attempt.ip for s in bucket):  # ví dụ từ các IP khác nhau, không phải ba dòng liền nhau của một IP
            bucket.append({"ts": _iso(attempt.ts), "username": attempt.username, "ip": attempt.ip, "success": attempt.success, "labels": list(labels), "message": message})

    def to_dict(self) -> dict[str, Any]:
        return {
            "hits": self.hits, "success_hits": self.success_hits, "unlabelled": self.unlabelled, "unlabelled_success": self.unlabelled_success,
            "by_label": dict(self.by_label), "ips_by_label": {name: len(ips) for name, ips in self.ips_by_label.items()}, "unlabelled_ips": len(self.unlabelled_ips),
            "by_scope": dict(self.by_scope), "unlabelled_by_scope": dict(self.unlabelled_by_scope), "samples": self.samples,
        }


class LatencyHistogram:
    """Độ trễ engine mỗi lần thử, gom ô 0,05 ms — đủ chính xác cho trung vị/p95/p99 mà không giữ hàng triệu số."""

    def __init__(self) -> None:
        self.counts: Counter[int] = Counter()
        self.n, self.total_ms, self.max_ms = 0, 0.0, 0.0

    def add(self, ms: float) -> None:
        self.n += 1
        self.total_ms += ms
        if ms > self.max_ms:
            self.max_ms = ms
        self.counts[min(int(ms / _LATENCY_STEP_MS), _LATENCY_BUCKETS)] += 1

    def percentile(self, q: float) -> float:
        if not self.n:
            return 0.0
        target, seen = q * self.n, 0
        for bucket in sorted(self.counts):
            seen += self.counts[bucket]
            if seen >= target:
                return (bucket + 1) * _LATENCY_STEP_MS  # cận trên của ô
        return self.max_ms

    def to_dict(self) -> dict[str, float]:
        mean = self.total_ms / self.n if self.n else 0.0
        return {"mean_ms": round(mean, 4), "p50_ms": round(self.percentile(0.5), 3), "p95_ms": round(self.percentile(0.95), 3), "p99_ms": round(self.percentile(0.99), 3), "max_ms": round(self.max_ms, 3)}


@dataclass
class RuleResult:
    id: str
    title: str
    category: str
    mode: str
    techniques: tuple[str, ...]
    evaluated: int = 0  # số lần thử luật thực sự chạy (không bị bỏ qua, không lỗi)
    skipped: int = 0
    errors: int = 0
    skip_reasons: dict[str, int] = field(default_factory=dict)
    first_error: str | None = None
    tally: Tally = field(default_factory=Tally)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "category": self.category, "mode": self.mode, "techniques": list(self.techniques), "evaluated": self.evaluated,
            "skipped": self.skipped, "errors": self.errors, "skip_reasons": self.skip_reasons, "first_error": self.first_error, **self.tally.to_dict(),
        }


@dataclass
class ReplayReport:
    source: str = ""
    events: int = 0
    successes: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    out_of_order: int = 0  # số lần thử có thời gian nhỏ hơn lần trước — nguồn dữ liệu phải sắp theo thời gian
    unlabelled: int = 0
    unlabelled_success: int = 0
    labels: Counter = field(default_factory=Counter)  # nhãn -> số dòng mang nhãn
    label_ips: dict[str, int] = field(default_factory=dict)  # nhãn -> số IP khác nhau
    rules: dict[str, RuleResult] = field(default_factory=dict)
    off_rules: list[str] = field(default_factory=list)  # luật tắt (`off`) trong lần chạy: không chạy nên không có số đo
    any_enforced: Tally = field(default_factory=Tally)  # có ÍT NHẤT MỘT luật enforce khớp
    any_rule: Tally = field(default_factory=Tally)  # có ít nhất một luật khớp (kể cả shadow)
    latency: LatencyHistogram = field(default_factory=LatencyHistogram)
    elapsed_s: float = 0.0
    config: dict[str, Any] = field(default_factory=dict)
    memory: dict[str, Any] = field(default_factory=dict)

    @property
    def days(self) -> float:
        return 0.0 if self.first_ts is None or self.last_ts is None else max((self.last_ts - self.first_ts) / DAY, 1e-9)

    @property
    def events_per_second(self) -> float:
        return self.events / self.elapsed_s if self.elapsed_s else 0.0

    def per_10k(self, count: int) -> float | None:
        """`count` trên 10.000 đăng nhập THÀNH CÔNG không nhãn — cùng mẫu số với các báo cáo mô hình (báo nhầm trên 10.000 đăng nhập hợp lệ)."""
        return None if not self.unlabelled_success else count / self.unlabelled_success * 10_000

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source, "events": self.events, "successes": self.successes, "first_ts": None if self.first_ts is None else _iso(self.first_ts),
            "last_ts": None if self.last_ts is None else _iso(self.last_ts), "days": round(self.days, 3), "out_of_order": self.out_of_order,
            "unlabelled": self.unlabelled, "unlabelled_success": self.unlabelled_success, "labels": dict(self.labels), "label_ips": self.label_ips,
            "elapsed_s": round(self.elapsed_s, 2), "events_per_second": round(self.events_per_second, 1), "latency": self.latency.to_dict(),
            "any_enforced": self.any_enforced.to_dict(), "any_rule": self.any_rule.to_dict(), "rules": {rid: r.to_dict() for rid, r in self.rules.items()},
            "off_rules": self.off_rules, "config": self.config, "memory": self.memory,
        }

    def save_json(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=1), encoding="utf-8")


# ------------------------------------------------------------------------------------------------ chạy


def replay(
    attempts: Iterable[LoginAttempt],
    engine: RuleEngine | None = None,
    *,
    source: str = "",
    limit: int | None = None,
    progress: Callable[[int, float, float], None] | None = None,
    progress_every: int = 250_000,
) -> ReplayReport:
    """Phát lại `attempts` (đã sắp theo thời gian) qua `engine` (mặc định: cấu hình mặc định, chưa nạp danh sách danh tiếng) và trả số đo từng luật.

    `progress(số_lần_thử, thời_gian_sự_kiện, giây_đã_chạy)` được gọi mỗi `progress_every` lần thử; `limit` dừng sau chừng đó lần thử."""
    engine = RuleEngine() if engine is None else engine
    report = ReplayReport(source=source, config=engine.config.to_dict())
    plan = {spec.id: RuleResult(spec.id, spec.title, spec.category, mode, spec.techniques) for spec in engine.registry.values() if (mode := engine.config.mode_of(spec)) != "off"}
    report.rules = plan
    report.off_rules = [spec.id for spec in engine.registry.values() if spec.id not in plan]
    label_ips: dict[str, set[str]] = {}
    started = time.perf_counter()
    previous: float | None = None

    for attempt in attempts:
        if limit is not None and report.events >= limit:
            break
        if previous is not None and attempt.ts < previous:
            report.out_of_order += 1
        previous = attempt.ts if previous is None or attempt.ts > previous else previous
        if report.first_ts is None:
            report.first_ts = attempt.ts

        result = engine.evaluate(attempt)  # engine không bao giờ thấy `labels`

        labels = tuple(name for name, flag in attempt.labels.items() if flag)
        report.events += 1
        report.successes += attempt.success
        report.last_ts = attempt.ts
        if labels:
            for name in labels:
                report.labels[name] += 1
                label_ips.setdefault(name, set()).add(attempt.ip)
        else:
            report.unlabelled += 1
            report.unlabelled_success += attempt.success
        report.latency.add(result.elapsed_ms)

        for rule_id, reason in result.skipped.items():
            entry = plan[rule_id]
            entry.skipped += 1
            entry.skip_reasons[reason] = entry.skip_reasons.get(reason, 0) + 1
        for rule_id, error in result.errors.items():
            entry = plan[rule_id]
            entry.errors += 1
            entry.first_error = entry.first_error or error
        if result.hits:
            enforced = False
            for hit in result.hits:
                plan[hit.rule_id].tally.observe(attempt, labels, hit.message, hit.evidence.get("scope"))
                enforced = enforced or not hit.is_shadow
            report.any_rule.observe(attempt, labels)
            if enforced:
                report.any_enforced.observe(attempt, labels)

        if progress is not None and progress_every and report.events % progress_every == 0:
            progress(report.events, attempt.ts, time.perf_counter() - started)

    report.elapsed_s = time.perf_counter() - started
    report.label_ips = {name: len(ips) for name, ips in label_ips.items()}
    for entry in plan.values():
        entry.evaluated = report.events - entry.skipped - entry.errors
    keys = getattr(engine.store, "keys", None)
    report.memory = {
        "window_keys_at_end": keys() if callable(keys) else None,
        "accounts_in_history": len(engine.history) if hasattr(engine.history, "__len__") else None,
        "process_rss_mb": None if (rss := rss_mb()) is None else round(rss),
    }
    return report


# ------------------------------------------------------------------------------------------------ bộ chuyển đổi: bảng login_events


def attempt_from_event(row: Any) -> LoginAttempt:
    """`LoginEvent` (app/models.py) -> `LoginAttempt`. Bản ghi chưa lưu ASN (thêm ở MR12) nên `asn=None`; nhãn duy nhất là `is_synthetic`."""
    created = row.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)  # SQLite trả về mốc thời gian không múi giờ; hệ thống ghi UTC
    return LoginAttempt.from_request(
        username=row.attempted_username,
        user_id=row.user_id,
        success=row.success,
        ip=row.ip_address,
        user_agent=row.user_agent,
        timestamp=created,
        geo=row,  # LoginEvent có sẵn country/city/latitude/longitude — `from_request` chỉ đọc bốn thuộc tính đó
        labels={"is_synthetic": bool(row.is_synthetic)},
    )


def db_attempts(session, *, start: datetime | None = None, end: datetime | None = None, batch: int = 5_000) -> Iterator[LoginAttempt]:
    """Các lần đăng nhập trong DB theo thứ tự thời gian (`created_at`, rồi `id`), đọc từng lô để không nạp cả bảng vào bộ nhớ."""
    from sqlalchemy import select

    from app.models import LoginEvent

    stmt = select(LoginEvent).order_by(LoginEvent.created_at, LoginEvent.id)
    if start is not None:
        stmt = stmt.where(LoginEvent.created_at >= start)
    if end is not None:
        stmt = stmt.where(LoginEvent.created_at < end)
    for row in session.execute(stmt.execution_options(yield_per=batch)).scalars():
        yield attempt_from_event(row)


# ------------------------------------------------------------------------------------------------ báo cáo Markdown


def _pct(part: int, whole: int, digits: int = 1) -> str:
    return "—" if not whole else f"{part / whole:.{digits}%}"


def _num(value: float | None, digits: int = 1) -> str:
    return "—" if value is None else f"{value:,.{digits}f}"


def to_markdown(report: ReplayReport, *, title: str, caveats: Mapping[str, str] | None = None, notes: Iterable[str] = (), regenerate: str = "") -> str:
    """Báo cáo người đọc được. `caveats`: mã luật -> lưu ý riêng của nguồn dữ liệu (ví dụ "không đánh giá được trên RBA"); `notes`: lưu ý chung."""
    caveats = caveats or {}
    labels = [name for name, _ in report.labels.most_common()]
    lines = [f"# {title}", ""]
    if regenerate:
        lines += [f"> Báo cáo TỰ SINH, đừng sửa tay. Sinh lại: `{regenerate}`", ""]
    latency = report.latency.to_dict()
    lines += [
        "## 1. Dữ liệu và cách chạy",
        "",
        f"- **Nguồn:** {report.source or '—'}",
        f"- **Khoảng thời gian:** {'—' if report.first_ts is None else _iso(report.first_ts)} → {'—' if report.last_ts is None else _iso(report.last_ts)} (UTC), {report.days:,.1f} ngày",
        f"- **Số lần thử:** {report.events:,} ({report.successes:,} thành công, {report.events - report.successes:,} thất bại); không nhãn {report.unlabelled:,} "
        f"(trong đó {report.unlabelled_success:,} đăng nhập thành công không nhãn — mẫu số của cột \"/10.000\")",
    ]
    for name in labels:
        lines.append(f"- **Nhãn `{name}`:** {report.labels[name]:,} dòng từ {report.label_ips.get(name, 0):,} IP khác nhau")
    lines += [
        f"- **Thứ tự thời gian:** {report.out_of_order:,} lần thử có thời gian nhỏ hơn lần trước" + (" (nguồn đã sắp đúng thứ tự)" if not report.out_of_order else " — kết quả có thể lệch, kiểm tra nguồn dữ liệu"),
        f"- **Tốc độ:** {report.events_per_second:,.0f} lần thử/giây trên một tiến trình Python ({report.elapsed_s:,.0f} giây); độ trễ engine mỗi lần thử: "
        f"trung bình {latency['mean_ms']:.2f} ms, p50 {latency['p50_ms']:.2f}, p95 {latency['p95_ms']:.2f}, p99 {latency['p99_ms']:.2f}, lớn nhất {latency['max_ms']:.1f} ms",
    ]
    memory = report.memory
    if memory.get("window_keys_at_end") is not None or memory.get("process_rss_mb") is not None:
        lines.append(
            f"- **Bộ nhớ khi kết thúc:** {memory.get('window_keys_at_end') or 0:,} khoá cửa sổ còn giữ (khoá quá hạn được dọn), "
            f"{memory.get('accounts_in_history') or 0:,} tài khoản trong lịch sử, tiến trình {memory.get('process_rss_mb') or 0:,} MB"
        )
    overrides = report.config.get("rules", {})
    lines.append("- **Cấu hình:** " + (f"ghi đè {json.dumps(overrides, ensure_ascii=False)}" if overrides else "mặc định của sổ đăng ký (chưa tinh chỉnh)"))
    for note in notes:
        lines.append(f"- {note}")

    rules = list(report.rules.values())
    lines += [
        "",
        "## 2. Số lần khớp và báo nhầm",
        "",
        "\"Báo nhầm\" = khớp trên dòng KHÔNG nhãn (giả định hợp lệ). \"/10.000\" = số lần khớp trên dòng không nhãn, chia cho số đăng nhập thành công không nhãn, nhân 10.000. "
        "Một luật khớp tối đa một lần cho mỗi lần thử; chưa gộp cảnh báo trùng (MR13), nên luật báo ở MỖI lần thất bại sau khi chạm ngưỡng cho số lớn — cột \"IP không nhãn bị khớp\" (số nguồn khác nhau) phản ánh khối lượng cảnh báo sau khi gộp theo IP.",
        "",
        "| Luật | Chế độ | Chạy | Bỏ qua | Khớp | Khớp: thành công / thất bại | Khớp trên dòng không nhãn | IP không nhãn bị khớp | /10.000 | Khớp/ngày (không nhãn) |",
        "|---|---|---:|---:|---:|---|---:|---:|---:|---:|",
    ]
    for r in rules:
        t = r.tally
        skipped = f"{r.skipped:,}" + (" ⚠️" if r.skipped == report.events else "")
        lines.append(
            f"| `{r.id}` | {r.mode} | {r.evaluated:,} | {skipped} | {t.hits:,} | {t.success_hits:,} / {t.hits - t.success_hits:,} | {t.unlabelled:,} | {len(t.unlabelled_ips):,} | "
            f"{_num(report.per_10k(t.unlabelled))} | {_num(t.unlabelled / report.days if report.days else None, 0)} |"
        )
    for label, tally in (("bất kỳ luật `enforce` nào", report.any_enforced), ("bất kỳ luật nào (kể cả shadow)", report.any_rule)):
        lines.append(
            f"| **{label}** | — | {report.events:,} | — | {tally.hits:,} | {tally.success_hits:,} / {tally.hits - tally.success_hits:,} | {tally.unlabelled:,} | {len(tally.unlabelled_ips):,} | "
            f"{_num(report.per_10k(tally.unlabelled))} | {_num(tally.unlabelled / report.days if report.days else None, 0)} |"
        )

    scoped = [r for r in rules if r.tally.by_scope]
    if scoped:
        lines += ["", "Luật có nhiều phạm vi (IP, ASN) — số lần khớp chia theo phạm vi:", "", "| Luật | Phạm vi | Khớp | Trên dòng không nhãn | Tỉ lệ không nhãn |", "|---|---|---:|---:|---:|"]
        for r in scoped:
            for scope, count in sorted(r.tally.by_scope.items(), key=lambda kv: -kv[1]):
                unlabelled = r.tally.unlabelled_by_scope.get(scope, 0)
                lines.append(f"| `{r.id}` | {scope} | {count:,} | {unlabelled:,} | {_pct(unlabelled, count)} |")

    if labels:
        lines += [
            "",
            "## 3. Phát hiện theo nhãn",
            "",
            "\"Dòng\" = tỉ lệ dòng mang nhãn mà luật khớp; \"IP\" = tỉ lệ IP mang nhãn mà luật khớp ÍT NHẤT MỘT lần (thước đo dễ tính hơn: luật chỉ cần bắt một lần để kịp chặn). "
            "Độ phủ của một luật trên dòng có nhãn KHÔNG phải độ chính xác: xem cột \"/10.000\" ở mục 2.",
            "",
            "| Luật | " + " | ".join(f"`{name}`: dòng | `{name}`: IP" for name in labels) + " |",
            "|---|" + "---:|---:|" * len(labels),
        ]
        rows = [(f"`{r.id}`", r.tally) for r in rules] + [("**bất kỳ luật `enforce` nào**", report.any_enforced), ("**bất kỳ luật nào (kể cả shadow)**", report.any_rule)]
        for name_cell, t in rows:
            cells = []
            for label in labels:
                cells.append(f"{_pct(t.by_label.get(label, 0), report.labels[label])} ({t.by_label.get(label, 0):,})")
                cells.append(_pct(len(t.ips_by_label.get(label, ())), report.label_ips.get(label, 0)))
            lines.append(f"| {name_cell} | " + " | ".join(cells) + " |")

    skipped_rules = [r for r in rules if r.skipped]
    lines += ["", "## 4. Luật bị bỏ qua hoặc lỗi", ""]
    if not skipped_rules and not any(r.errors for r in rules):
        lines.append("Không có luật nào bị bỏ qua hay lỗi.")
    else:
        lines += ["| Luật | Số lần bỏ qua | Lý do | Lỗi |", "|---|---:|---|---|"]
        for r in rules:
            if r.skipped or r.errors:
                reasons = "; ".join(f"{reason} ({count:,})" for reason, count in sorted(r.skip_reasons.items(), key=lambda kv: -kv[1]))
                failure = f"{r.first_error} ({r.errors:,} lần)" if r.errors else "—"
                lines.append(f"| `{r.id}` | {r.skipped:,} | {reasons or '—'} | {failure} |")
    if report.off_rules:
        lines += ["", "Luật tắt (`off`) trong lần chạy này, không được chạy: " + ", ".join(f"`{i}`" for i in report.off_rules) + "."]

    if caveats:
        lines += ["", "## 5. Lưu ý riêng của nguồn dữ liệu", "", "| Luật | Lưu ý |", "|---|---|"]
        for rule_id in report.rules:
            if rule_id in caveats:
                lines.append(f"| `{rule_id}` | {caveats[rule_id]} |")

    lines += ["", "## 6. Ví dụ (đọc để hiểu luật khớp ở đâu, không phải mẫu đại diện)", ""]
    shown = False
    for r in rules:
        for kind, heading in (("labelled", "trên dòng có nhãn"), ("unlabelled", "trên dòng không nhãn — báo nhầm")):
            for sample in r.tally.samples[kind]:
                shown = True
                lines.append(f"- `{r.id}` ({heading}) {sample['ts']} · {sample['ip']} · `{sample['username']}` · {'thành công' if sample['success'] else 'thất bại'} — {sample['message']}")
    if not shown:
        lines.append("Không có luật nào khớp.")
    return "\n".join(lines).rstrip("\n") + "\n"


# ------------------------------------------------------------------------------------------------ dòng lệnh


def _progress_printer(total_label: str = "") -> Callable[[int, float, float], None]:
    def show(done: int, ts: float, elapsed: float) -> None:
        rss = rss_mb()
        print(f"  {done:>12,} lần thử · sự kiện đến {_iso(ts)} · {done / max(elapsed, 1e-9):,.0f}/giây · {elapsed:,.0f}s" + ("" if rss is None else f" · {rss:,.0f} MB"), flush=True)

    return show


def _canonical_command(argv: list[str]) -> str:
    """Lệnh sinh lại báo cáo ghi trong tiêu đề: chỉ giữ tham số xác định DỮ LIỆU và LUẬT, bỏ đường dẫn đầu ra và tiến độ (chúng thay đổi theo máy/lần chạy)."""
    ignored, kept, skip_next = {"--out", "--json", "--progress"}, [], False
    for token in argv:
        if skip_next:
            skip_next = False
        elif token.split("=", 1)[0] in ignored:
            skip_next = "=" not in token
        else:
            kept.append(token)
    return "python -m app.detection.engine.replay " + " ".join(kept) + " --out <tệp.md>"


def _build_engine(args: argparse.Namespace) -> RuleEngine:
    config = RuleConfig.from_file(Path(args.config)) if args.config else RuleConfig()
    intel = ThreatIntel.load(Path(args.intel)) if args.intel else ThreatIntel()
    return RuleEngine(config, intel=intel)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.detection.engine.replay", description="Phát lại log đăng nhập lịch sử qua rule engine v2 và đo từng luật.")
    sub = parser.add_subparsers(dest="source", required=True)
    for name, help_text in (("rba", "bộ dữ liệu RBA (parquet đã chạy ETL)"), ("db", "bảng login_events của cơ sở dữ liệu ứng dụng")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--start", help="từ thời điểm này (UTC, ví dụ 2020-02-03), gồm cả mốc")
        p.add_argument("--end", help="đến thời điểm này (UTC), không gồm mốc")
        p.add_argument("--limit", type=int, help="dừng sau chừng này lần thử")
        p.add_argument("--config", help="tệp JSON ghi đè chế độ/tham số luật (RuleConfig.from_file)")
        p.add_argument("--intel", help="thư mục danh sách Tor/datacenter/VPN (mặc định: không nạp — các luật hạ tầng bị bỏ qua)")
        p.add_argument("--out", help="ghi báo cáo Markdown vào tệp này")
        p.add_argument("--json", help="ghi số đo dạng JSON vào tệp này")
        p.add_argument("--progress", type=int, default=500_000, help="in tiến độ mỗi chừng này lần thử (0 = tắt)")
        if name == "rba":
            p.add_argument("--parquet", help="đường dẫn rba_full.parquet (mặc định: backend/ml/data/rba/rba_full.parquet)")
            p.add_argument("--sort", action="store_true", help="sắp lại theo (thời gian, row_id) trong DuckDB — chỉ cần với tệp không rõ thứ tự (tốn bộ nhớ)")
            p.add_argument(
                "--unknown-names", choices=("attempt", "ip"), default="attempt",
                help="tên giả cho lần thử vào tên không tồn tại (RBA gộp chúng): attempt = mỗi lần một tên (mặc định, cận trên số tên khác nhau); ip = mỗi IP một tên (cận dưới)",
            )
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # in tiếng Việt đúng trên console Windows
    except (AttributeError, ValueError, OSError):
        pass  # luồng đầu ra bị thay (ví dụ khi chạy dưới pytest): giữ nguyên
    engine = _build_engine(args)

    if args.source == "rba":
        from ml.rba.rule_replay import rba_attempts, rba_caveats, rba_notes

        stream = rba_attempts(Path(args.parquet) if args.parquet else None, start=args.start, end=args.end, limit=args.limit, sort=args.sort, unknown_names=args.unknown_names)
        source, caveats, notes, title = "RBA (tổng hợp, không phải log thật) — rba_full.parquet", rba_caveats(args.unknown_names), rba_notes(args.unknown_names), "Replay rule engine v2 trên RBA"
    else:
        from app.database import SessionLocal

        session = SessionLocal()
        parse = lambda text: None if text is None else datetime.fromisoformat(text).replace(tzinfo=timezone.utc)  # noqa: E731
        stream = db_attempts(session, start=parse(args.start), end=parse(args.end))
        source, caveats, notes, title = "bảng `login_events` của cơ sở dữ liệu ứng dụng", {}, [], "Replay rule engine v2 trên log trong CSDL"

    print(f"replay {source} …", flush=True)
    report = replay(stream, engine, source=source, limit=args.limit, progress=_progress_printer() if args.progress else None, progress_every=args.progress)
    text = to_markdown(report, title=title, caveats=caveats, notes=notes, regenerate=_canonical_command(sys.argv[1:] if argv is None else argv))
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8", newline="\n")
        print(f"đã ghi {args.out}")
    if args.json:
        report.save_json(Path(args.json))
        print(f"đã ghi {args.json}")
    if not args.out:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
