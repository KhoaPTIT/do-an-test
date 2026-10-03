"""Ma trận đặc trưng + chia tập theo THỜI GIAN (Phase 4.1 — ML2).

    python -m ml.build_features     # ml/data/v3/events.csv -> features.csv + splits/{train,validation,test}.csv

Đặc trưng trích bằng `ml.features.extract_offline` — CÙNG đặc tả với runtime (test parity bắt buộc). Chỉ lần đăng nhập
THÀNH CÔNG của hồ sơ trưởng thành có dòng đặc trưng (đúng phạm vi model chấm lúc chạy thật).

Chia theo thời gian toàn cục (mọi tài khoản cùng mốc), KHÔNG xáo trộn: train = trước ngày `TRAIN_END_DAY` của kỳ mô phỏng
(kể cả phần lịch sử trước kỳ), validation = [`TRAIN_END_DAY`, `VALIDATION_END_DAY`), test = từ `VALIDATION_END_DAY`.
Validation chỉ dùng để CHỌN NGƯỠNG; test chỉ dùng để đánh giá cuối.

Các file đặc trưng/chia tập KHÔNG chứa nhãn — nhãn nằm riêng ở `labels.csv`."""

from __future__ import annotations

import argparse
import csv
from datetime import timedelta
from pathlib import Path

from ml.dataset import DATA_DIR, read_events
from ml.features import FEATURE_NAMES, extract_offline
from verification.scenarios import T0

TRAIN_END_DAY = 18
VALIDATION_END_DAY = 24
SPLITS = ("train", "validation", "test")


def split_of(ts) -> str:
    if ts < T0 + timedelta(days=TRAIN_END_DAY):
        return "train"
    if ts < T0 + timedelta(days=VALIDATION_END_DAY):
        return "validation"
    return "test"


def build(data_dir: Path = DATA_DIR) -> dict[str, int]:
    events = read_events(data_dir / "events.csv")
    ts_of = {e.event_id: e.ts for e in events}
    rows = extract_offline(events)
    header = ["event_id", *FEATURE_NAMES]
    writers, files = {}, []
    (data_dir / "splits").mkdir(parents=True, exist_ok=True)
    counts = {name: 0 for name in SPLITS}
    with (data_dir / "features.csv").open("w", newline="", encoding="utf-8") as all_f:
        all_w = csv.writer(all_f, lineterminator="\n")
        all_w.writerow(header)
        for name in SPLITS:
            f = (data_dir / "splits" / f"{name}.csv").open("w", newline="", encoding="utf-8")
            files.append(f)
            writers[name] = csv.writer(f, lineterminator="\n")
            writers[name].writerow(header)
        try:
            for event_id, features in rows:
                line = [event_id, *(repr(float(features[n])) for n in FEATURE_NAMES)]
                all_w.writerow(line)
                split = split_of(ts_of[event_id])
                writers[split].writerow(line)
                counts[split] += 1
        finally:
            for f in files:
                f.close()
    return counts


def read_split(path: Path) -> tuple[list[int], list[list[float]]]:
    ids, matrix = [], []
    with path.open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            ids.append(int(row["event_id"]))
            matrix.append([float(row[n]) for n in FEATURE_NAMES])
    return ids, matrix


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-dir", default=str(DATA_DIR))
    args = parser.parse_args(argv)
    counts = build(Path(args.data_dir))
    print(f"đặc trưng: {sum(counts.values())} dòng — " + ", ".join(f"{k} {v}" for k, v in counts.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
