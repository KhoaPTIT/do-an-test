"""Dataset TỔNG HỢP, TẤT ĐỊNH cho mô hình bất thường (Phase 4.1 — ML2). Không cần DB, không dùng `datetime.now()`.

    python -m ml.dataset            # -> ml/data/v3/events.csv + labels.csv

  - Hành vi BÌNH THƯỜNG: chính bộ sinh lưu lượng bình thường v3 của Phase 3 (`verification/normal_traffic.py`) với seed
    `DATASET_SEED` — KHÁC seed của harness kiểm chứng (20260302), nên dataset huấn luyện không trùng lưu lượng dùng để đo
    luật/ML ở Phase 3 và ML4. Vị trí/ASN của IP tra bằng GeoIP TEST FIXTURE như harness.
  - BẤT THƯỜNG được CHÈN (kẻ có mật khẩu đúng đăng nhập thành công) theo danh mục kiểu bất thường của tầng 3:
    giờ lạ, vị trí lạ, thiết bị lạ, thiết bị + vị trí lạ, di chuyển bất khả thi, đợt đăng nhập dồn dập. Vị trí/thiết bị/giờ
    "quen" của từng tài khoản suy từ CHÍNH sự kiện đã sinh (không đọc nội bộ bộ sinh).
  - `events.csv` KHÔNG có nhãn; nhãn ở `labels.csv` riêng, chỉ dùng để ĐÁNH GIÁ (chọn ngưỡng trên validation, đo trên test).

⚠️ Dữ liệu tổng hợp: kết quả trên dataset này không phải hiệu năng trên người dùng/tấn công thật."""

from __future__ import annotations

import argparse
import csv
import math
import random
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from ml.features import RawLogin, device_family_for_user_agent
from verification.fixtures import fixture_lookup_ip
from verification.normal_traffic import generate as generate_normal_traffic
from verification.scenarios import DAY, FOREIGN_POOLS, ROTATION_UAS, T0

DATASET_SEED = 41_001  # ≠ seed harness Phase 3 (20260302)
N_USERS = 320  # + 13 người dùng các nhóm Milestone C của bộ sinh v3
SIM_DAYS = 30
DATA_DIR = Path(__file__).resolve().parent / "data" / "v3"

# Số bất thường chèn theo kiểu (đợt dồn dập: số ĐỢT, mỗi đợt 8–12 sự kiện)
ANOMALY_PLAN = {  # chốt TRƯỚC khi train: ~20+ mẫu mỗi kiểu rơi vào tập test, tỉ lệ bất thường ~3%
    "unusual_hour": 120,
    "unusual_location": 120,
    "unusual_device": 120,
    "new_device_and_location": 100,
    "impossible_travel": 100,
    "login_burst": 30,
}
EVENT_FIELDS = ("event_id", "username", "ts", "success", "ip", "user_agent", "country", "city", "latitude", "longitude")
LABEL_FIELDS = ("event_id", "is_anomaly", "anomaly_type")


@dataclass
class _Event:
    username: str
    ts: datetime
    success: bool
    ip: str
    user_agent: str | None
    anomaly_type: str | None = None


def _profile(events: list[_Event]) -> dict:
    """Thói quen QUAN SÁT được của một tài khoản: giờ trung bình vòng tròn, IP/UA hay dùng, quốc gia, họ thiết bị."""
    ok = [e for e in events if e.success]
    s = sum(math.sin(2 * math.pi * (e.ts.hour + e.ts.minute / 60) / 24) for e in ok)
    c = sum(math.cos(2 * math.pi * (e.ts.hour + e.ts.minute / 60) / 24) for e in ok)
    geo = [fixture_lookup_ip(e.ip) for e in ok]
    return {
        "hour": (math.degrees(math.atan2(s, c)) % 360) / 15.0,
        "ip": Counter(e.ip for e in ok).most_common(1)[0][0],
        "ua": Counter(e.user_agent for e in ok).most_common(1)[0][0],
        "countries": {g.country for g in geo if g is not None},
        "families": {device_family_for_user_agent(e.user_agent) for e in ok},
        "successes": ok,
    }


def _at_hour(day: float, hour: float) -> datetime:
    return T0.replace(hour=0, minute=0, second=0) + timedelta(days=int(day), hours=hour % 24)


def _foreign_ip(rng: random.Random, countries: set[str]) -> str:
    pools = [p for p in FOREIGN_POOLS if fixture_lookup_ip(p[0]).country not in countries]
    return rng.choice(rng.choice(pools))


def _new_device_ua(rng: random.Random, families: set[str]) -> str:
    return rng.choice([ua for ua in ROTATION_UAS if device_family_for_user_agent(ua) not in families])


def _inject(rng: random.Random, by_user: dict[str, list[_Event]], days: int) -> list[_Event]:
    """Sự kiện bất thường. Chỉ chèn vào tài khoản có hồ sơ đủ dày (≥ 20 lần thành công) và vào kỳ mô phỏng (ngày 1 → `days`)."""
    candidates = sorted(u for u, evs in by_user.items() if sum(e.success for e in evs) >= 20)
    injected: list[_Event] = []
    for kind, count in ANOMALY_PLAN.items():
        for _ in range(count):
            user = rng.choice(candidates)
            p = _profile(by_user[user])
            day = rng.uniform(1, days - 0.01)
            if kind == "unusual_hour":
                injected.append(_Event(user, _at_hour(day, p["hour"] + 12 + rng.uniform(-1.5, 1.5)), True, p["ip"], p["ua"], kind))
            elif kind == "unusual_location":
                injected.append(_Event(user, _at_hour(day, p["hour"] + rng.uniform(-1, 1)), True, _foreign_ip(rng, p["countries"]), p["ua"], kind))
            elif kind == "unusual_device":
                injected.append(_Event(user, _at_hour(day, p["hour"] + rng.uniform(-1, 1)), True, p["ip"], _new_device_ua(rng, p["families"]), kind))
            elif kind == "new_device_and_location":
                injected.append(_Event(
                    user, _at_hour(day, p["hour"] + rng.uniform(-1, 1)), True, _foreign_ip(rng, p["countries"]), _new_device_ua(rng, p["families"]), kind,
                ))
            elif kind == "impossible_travel":  # vài phút sau một lần đăng nhập THẬT, từ một nước xa
                anchor = rng.choice([e for e in p["successes"] if e.ts >= T0 + timedelta(days=1)] or p["successes"])
                injected.append(_Event(user, anchor.ts + timedelta(minutes=rng.uniform(5, 30)), True, _foreign_ip(rng, p["countries"]), p["ua"], kind))
            else:  # login_burst — 8–12 lần thành công trong ~10 phút
                start = _at_hour(day, p["hour"] + rng.uniform(-1, 1))
                for k in range(rng.randint(8, 12)):
                    injected.append(_Event(user, start + timedelta(seconds=k * rng.uniform(30, 70)), True, p["ip"], p["ua"], kind))
    return injected


def build(seed: int = DATASET_SEED, n_users: int = N_USERS, days: int = SIM_DAYS) -> tuple[list[RawLogin], dict[int, str | None]]:
    """(sự kiện thô sắp theo thời gian, nhãn theo event_id: loại bất thường hoặc None). Tất định theo `seed`."""
    traffic = generate_normal_traffic(seed, n_users=n_users, days=days)
    events = [_Event(h.username, T0 + timedelta(seconds=h.offset_s), h.success, h.ip, h.user_agent) for h in traffic.history]
    events += [_Event(s.username, T0 + timedelta(seconds=s.offset_s), s.success, s.ip, s.user_agent) for s in traffic.steps]
    by_user: dict[str, list[_Event]] = {}
    for e in events:
        by_user.setdefault(e.username, []).append(e)
    events += _inject(random.Random(f"{seed}:anomalies"), by_user, days)
    events.sort(key=lambda e: (e.ts, e.username, e.anomaly_type or "", e.ip))

    raws, labels = [], {}
    for i, e in enumerate(events, start=1):
        g = fixture_lookup_ip(e.ip)
        raws.append(RawLogin(
            i, e.username, e.ts, e.success, g.country if g else None, g.city if g else None, g.latitude if g else None, g.longitude if g else None,
            e.user_agent, e.ip,
        ))
        labels[i] = e.anomaly_type
    return raws, labels


def write(raws: list[RawLogin], labels: dict[int, str | None], out_dir: Path = DATA_DIR) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {"events": out_dir / "events.csv", "labels": out_dir / "labels.csv"}
    with paths["events"].open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(EVENT_FIELDS)
        for r in raws:
            w.writerow([r.event_id, r.username, r.ts.isoformat(), int(r.success), r.ip or "", r.user_agent or "", r.country or "", r.city or "",
                        "" if r.latitude is None else repr(r.latitude), "" if r.longitude is None else repr(r.longitude)])
    with paths["labels"].open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(LABEL_FIELDS)
        for event_id in sorted(labels):
            w.writerow([event_id, int(labels[event_id] is not None), labels[event_id] or ""])
    return paths


def read_events(path: Path) -> list[RawLogin]:
    out = []
    with path.open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            out.append(RawLogin(
                int(row["event_id"]), row["username"], datetime.fromisoformat(row["ts"]), row["success"] == "1",
                row["country"] or None, row["city"] or None, float(row["latitude"]) if row["latitude"] else None,
                float(row["longitude"]) if row["longitude"] else None, row["user_agent"] or None, row["ip"] or None,
            ))
    return out


def read_labels(path: Path) -> dict[int, str | None]:
    with path.open(encoding="utf-8") as f:
        return {int(row["event_id"]): (row["anomaly_type"] or None) for row in csv.DictReader(f)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seed", type=int, default=DATASET_SEED)
    parser.add_argument("--out-dir", default=str(DATA_DIR))
    args = parser.parse_args(argv)
    raws, labels = build(args.seed)
    paths = write(raws, labels, Path(args.out_dir))
    n_anom = sum(v is not None for v in labels.values())
    print(f"{len(raws)} sự kiện ({sum(r.success for r in raws)} thành công), {len({r.username for r in raws})} tài khoản, {n_anom} sự kiện bất thường chèn vào")
    print(f"-> {paths['events']}\n-> {paths['labels']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
