"""Đo thời gian phản hồi POST /login (nhiệm vụ 5.2) — chạy trước và sau khi
tối ưu để so sánh. KHÔNG tự tối ưu gì — chỉ đo.

Chạy (backend phải đang chạy ở port 8000, có sẵn user 'alice'/'CorrectHorse123'):
    cd backend
    venv\\Scripts\\python.exe -m scripts.benchmark_login --n 50
    venv\\Scripts\\python.exe -m scripts.benchmark_login --n 200 --concurrency 20   # tải: 20 request đồng thời (MR12)
    venv\\Scripts\\python.exe -m scripts.benchmark_login --pipeline                  # kèm độ trễ pipeline nền (MR12, xem ghi chú dưới)

MR12 thêm p99 (bên cạnh p95 sẵn có) và `--concurrency` để đo "tải" theo đúng yêu cầu checklist ("đo độ trễ p50/p95/p99
và tải"), không chỉ độ trễ tuần tự. `--concurrency N > 1` gửi N request cùng lúc bằng `httpx.Client` với một
`ThreadPoolExecutor` (đơn giản hơn asyncio cho một script CLI ngắn, đủ để tạo tải thật lên server).

`--pipeline` in kèm độ trễ pipeline NỀN đo được ở server (`app/detection/perf.py`, endpoint chẩn đoán `GET /health`
không lộ số này — script gọi thẳng qua import, chỉ dùng được khi chạy CÙNG máy/tiến trình Python có thể import
`app.detection.perf`; khi benchmark nhắm một server đang chạy Ở TIẾN TRÌNH KHÁC, cờ này không có gì để in vì độ trễ
nền nằm trong bộ nhớ của tiến trình server, không phải của script — xem `docs/realtime-integration.md` mục đo đạc)."""

from __future__ import annotations

import argparse
import statistics
import time
from concurrent.futures import ThreadPoolExecutor

import httpx

URL = "http://localhost:8000/login"
PAYLOAD = {"username": "alice", "password": "CorrectHorse123"}


def _percentile(sorted_values: list[float], q: float) -> float:
    idx = min(len(sorted_values) - 1, int(len(sorted_values) * q))
    return sorted_values[idx]


def _one_request(client: httpx.Client) -> float:
    start = time.perf_counter()
    client.post(URL, json=PAYLOAD)
    return (time.perf_counter() - start) * 1000


def run(n: int, concurrency: int) -> list[float]:
    with httpx.Client(timeout=10.0) as client:
        if concurrency <= 1:
            return [_one_request(client) for _ in range(n)]
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            return list(pool.map(lambda _: _one_request(client), range(n)))


def report(durations_ms: list[float], n: int, concurrency: int) -> None:
    durations_ms = sorted(durations_ms)
    label = f"N = {n} request tới {URL}" + (f", {concurrency} request đồng thời (tải)" if concurrency > 1 else " (tuần tự)")
    print(label)
    print(f"  min    = {durations_ms[0]:.1f} ms")
    print(f"  avg    = {statistics.mean(durations_ms):.1f} ms")
    print(f"  median = {statistics.median(durations_ms):.1f} ms")
    print(f"  p95    = {_percentile(durations_ms, 0.95):.1f} ms")
    print(f"  p99    = {_percentile(durations_ms, 0.99):.1f} ms")
    print(f"  max    = {durations_ms[-1]:.1f} ms")


def main(n: int, concurrency: int, show_pipeline: bool) -> None:
    report(run(n, concurrency), n, concurrency)

    if show_pipeline:
        try:
            from app.detection import perf

            snapshot = perf.snapshot()
        except Exception as exc:  # noqa: BLE001 — script chẩn đoán, không được sập vì lý do phụ
            print(f"\n(không đọc được độ trễ pipeline nền: {exc})")
            return
        if not snapshot:
            print("\n(chưa có số đo pipeline nền trong tiến trình này — --pipeline chỉ có ý nghĩa khi chạy CÙNG tiến trình server, xem docstring)")
            return
        print("\nĐộ trễ pipeline nền đo được TRONG TIẾN TRÌNH NÀY (app.detection.perf, không phải của riêng lần chạy benchmark này):")
        for stage, stats in snapshot.items():
            print(f"  {stage:12} n={stats['count']:>5}  mean={stats['mean_ms']:>7.2f}ms  p50={stats['p50_ms']:>7.2f}ms  p95={stats['p95_ms']:>7.2f}ms  p99={stats['p99_ms']:>7.2f}ms  max={stats['max_ms']:>7.2f}ms")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=50)
    parser.add_argument("--concurrency", type=int, default=1, help="số request gửi đồng thời (1 = tuần tự, mặc định)")
    parser.add_argument("--pipeline", action="store_true", dest="show_pipeline", help="in kèm độ trễ pipeline nền (chỉ có ý nghĩa khi import được app.detection.perf của CÙNG tiến trình)")
    args = parser.parse_args()
    main(n=args.n, concurrency=args.concurrency, show_pipeline=args.show_pipeline)
