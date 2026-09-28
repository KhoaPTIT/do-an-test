"""Soak test — tải nhẹ nhưng LIÊN TỤC lên POST /login trong nhiều phút, tìm dấu hiệu suy giảm theo thời gian (rò rỉ
bộ nhớ/kết nối, độ trễ tăng dần, tỉ lệ lỗi tăng dần) mà benchmark ngắn (`scripts/benchmark_login.py`) không thấy được
(MR19 — trước đó dự án chưa có loại kiểm thử này).

Chạy (backend phải đang chạy ở port 8000, cần 30 tài khoản demo user001-030/Demo@12345 — xem `docs/getting-started.md`):
    cd backend
    venv\\Scripts\\python.exe -m scripts.soak_test --minutes 15

Thiết kế để KHÔNG tự gây nhiễu cho chính phép đo:
  - Luân phiên đều qua 30 tài khoản demo (không dùng lặp lại MỘT tài khoản như `benchmark_login.py` — tránh vừa đo
    vừa làm phình lịch sử của chính tài khoản đang đo, xem phát hiện ở `docs/performance.md` mục "Đo lại sau MR9-18").
  - 90% mật khẩu ĐÚNG / 10% SAI, rải đều qua nhiều tài khoản — đủ để tạo hỗn hợp thật nhưng không tài khoản nào gần
    ngưỡng brute_force (5 sai/5 phút) nên không tự khoá tài khoản giữa chừng (khoá thật KHÔNG phải lỗi, nhưng sẽ làm
    "tỉ lệ lỗi" đo được lẫn giữa lỗi hệ thống và hành vi phát hiện ĐÚNG như thiết kế).
  - Nhịp mặc định 1 request/giây — đủ chậm để không tự tạo tải giả tạo, đủ lâu để thấy xu hướng theo thời gian.
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

LOGIN_URL = "http://localhost:8000/login"
HEALTH_URL = "http://localhost:8000/health"
ACCOUNTS = [f"user{i:03d}" for i in range(1, 31)]
CORRECT_PASSWORD = "Demo@12345"
WRONG_PASSWORD = "sai_mat_khau_co_y"
WRONG_RATE = 0.10

REPORT_PATH = Path(__file__).resolve().parents[2] / "docs" / "soak-test.md"
RAW_PATH = Path(__file__).resolve().parent / "_soak_test_raw.json"


@dataclass
class Sample:
    t_sec: float
    kind: str  # "login" | "health"
    status: int
    latency_ms: float
    expected_lock: bool = False


@dataclass
class Result:
    samples: list[Sample] = field(default_factory=list)


def _one_login(client: httpx.Client, rng: random.Random, t0: float) -> Sample:
    username = rng.choice(ACCOUNTS)
    wrong = rng.random() < WRONG_RATE
    password = WRONG_PASSWORD if wrong else CORRECT_PASSWORD
    start = time.perf_counter()
    try:
        resp = client.post(LOGIN_URL, json={"username": username, "password": password}, timeout=10.0)
        status = resp.status_code
    except httpx.HTTPError:
        status = -1
    latency_ms = (time.perf_counter() - start) * 1000
    return Sample(t_sec=start - t0, kind="login", status=status, latency_ms=latency_ms)


def _one_health(client: httpx.Client, t0: float) -> Sample:
    start = time.perf_counter()
    try:
        resp = client.get(HEALTH_URL, timeout=10.0)
        status = resp.status_code
    except httpx.HTTPError:
        status = -1
    latency_ms = (time.perf_counter() - start) * 1000
    return Sample(t_sec=start - t0, kind="health", status=status, latency_ms=latency_ms)


def run(minutes: float, rps: float) -> Result:
    rng = random.Random(0)
    result = Result()
    interval = 1.0 / rps
    deadline = time.perf_counter() + minutes * 60
    t0 = time.perf_counter()
    n = 0
    with httpx.Client() as client:
        while time.perf_counter() < deadline:
            loop_start = time.perf_counter()
            n += 1
            if n % 10 == 0:
                result.samples.append(_one_health(client, t0))
            result.samples.append(_one_login(client, rng, t0))
            elapsed = time.perf_counter() - loop_start
            if elapsed < interval:
                time.sleep(interval - elapsed)
    return result


def _bucket_stats(samples: list[Sample], bucket_seconds: float) -> list[dict]:
    logins = [s for s in samples if s.kind == "login"]
    if not logins:
        return []
    max_t = max(s.t_sec for s in logins)
    n_buckets = int(max_t // bucket_seconds) + 1
    buckets: list[dict] = []
    for i in range(n_buckets):
        lo, hi = i * bucket_seconds, (i + 1) * bucket_seconds
        bucket = [s for s in logins if lo <= s.t_sec < hi]
        if not bucket:
            continue
        lat = sorted(s.latency_ms for s in bucket)
        errors = [s for s in bucket if s.status not in (200, 401, 423)]
        buckets.append({
            "window_start_min": round(lo / 60, 1),
            "n": len(bucket),
            "median_ms": round(statistics.median(lat), 1),
            "p95_ms": round(lat[min(len(lat) - 1, int(len(lat) * 0.95))], 1),
            "n_unexpected_status": len(errors),
            "n_locked_423": len([s for s in bucket if s.status == 423]),
        })
    return buckets


def render(samples: list[Sample], minutes: float, rps: float) -> str:
    logins = [s for s in samples if s.kind == "login"]
    healths = [s for s in samples if s.kind == "health"]
    buckets = _bucket_stats(samples, bucket_seconds=120.0)
    unexpected = [s for s in logins if s.status not in (200, 401, 423)]
    health_bad = [s for s in healths if s.status != 200]

    medians = [b["median_ms"] for b in buckets]
    trend = "—"
    if len(medians) >= 3:
        first_third = medians[: max(1, len(medians) // 3)]
        last_third = medians[-max(1, len(medians) // 3):]
        delta = statistics.mean(last_third) - statistics.mean(first_third)
        trend = f"{'+' if delta >= 0 else ''}{delta:.1f} ms (median cửa sổ cuối trừ cửa sổ đầu)"

    lines = [
        "# Soak test — tải nhẹ liên tục (MR19)",
        "",
        f"Chạy thật {minutes:.0f} phút, nhịp mục tiêu {rps:g} request/giây, luân phiên 30 tài khoản demo "
        f"(user001-030), 90% mật khẩu đúng / 10% sai — không dùng lại một tài khoản như `benchmark_login.py` để "
        "tránh tự làm phình lịch sử của chính tài khoản đang đo (xem `docs/performance.md`).",
        "",
        "## Tổng quan",
        "",
        f"- Tổng số request `/login`: **{len(logins)}**",
        f"- Tổng số request `/health` (xen kẽ, 1/10 vòng lặp): **{len(healths)}**",
        f"- Request `/login` có status KHÔNG mong đợi (khác 200/401/423): **{len(unexpected)}**"
        + (f" — {sorted({s.status for s in unexpected})}" if unexpected else ""),
        f"- Request `/health` khác 200: **{len(health_bad)}**",
        f"- Số lần bị khoá (423 — hành vi ĐÚNG như thiết kế nếu brute_force vô tình chạm ngưỡng, không tính là lỗi): "
        f"**{len([s for s in logins if s.status == 423])}**",
        f"- Xu hướng độ trễ median theo thời gian (cửa sổ 2 phút, so cụm đầu với cụm cuối): **{trend}**",
        "",
        "## Theo cửa sổ 2 phút",
        "",
        "| Phút bắt đầu | Số request | Median (ms) | p95 (ms) | Bị khoá (423) | Status lạ |",
        "|---|---|---|---|---|---|",
    ]
    for b in buckets:
        lines.append(
            f"| {b['window_start_min']} | {b['n']} | {b['median_ms']} | {b['p95_ms']} | "
            f"{b['n_locked_423']} | {b['n_unexpected_status']} |"
        )
    lines += [
        "",
        "## Đọc kết quả",
        "",
        "- **Tỉ lệ lỗi thật** = status không mong đợi (khác 200 thành công / 401 sai mật khẩu / 423 khoá đúng thiết "
        "kế) chia cho tổng request — 0 nghĩa là không có request nào thất bại ngoài dự kiến trong suốt phiên.",
        "- **Rò rỉ/suy giảm** biểu hiện qua median TĂNG DẦN đơn điệu qua các cửa sổ — một vài cửa sổ nhiễu cao hơn "
        "cửa sổ khác là bình thường (GC, cache miss định kỳ của `GlobalCountsCache`, xem `docs/performance.md`), "
        "xu hướng tăng liên tục nhiều cửa sổ liên tiếp mới đáng lo.",
        "- Đây là tải THẤP có chủ đích (khác benchmark tải cao ngắn hạn) — mục tiêu là phát hiện suy giảm theo "
        "THỜI GIAN, không phải theo TẢI (đã đo riêng ở `docs/performance.md`).",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--minutes", type=float, default=15.0)
    parser.add_argument("--rps", type=float, default=1.0)
    args = parser.parse_args()

    print(f"Soak test: {args.minutes:.0f} phut, {args.rps:g} req/s, ghi vao {REPORT_PATH}", flush=True)
    result = run(args.minutes, args.rps)

    RAW_PATH.write_text(
        json.dumps([s.__dict__ for s in result.samples], ensure_ascii=False, indent=2), encoding="utf-8"
    )
    REPORT_PATH.write_text(render(result.samples, args.minutes, args.rps), encoding="utf-8")
    print(f"Xong — {len(result.samples)} mau, bao cao: {REPORT_PATH}", flush=True)


if __name__ == "__main__":
    main()
