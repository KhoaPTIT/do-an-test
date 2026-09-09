"""Tái hiện dòng sự kiện theo đúng thứ tự thời gian để tính đặc trưng.

Vì sao cần module này thay vì tính đặc trưng bằng vài phép groupby của pandas:

Đặc trưng của một sự kiện phải chỉ được tính từ những gì XẢY RA TRƯỚC nó.
Nếu dùng groupby trên toàn bộ bảng, ví dụ "số quốc gia mà user từng dùng",
thì giá trị đó đã bao gồm cả thông tin của tương lai. Mô hình huấn luyện
trên đặc trưng như vậy sẽ cho kết quả rất đẹp trên giấy nhưng sụp đổ khi
chạy thật. Đây là lỗi data leakage, cũng là lỗi thường gặp nhất trong
các đồ án dùng học máy.

Cách làm ở đây: duyệt sự kiện theo thứ tự thời gian tăng dần, giữ trạng thái
lịch sử trong bộ nhớ, tính đặc trưng cho từng sự kiện rồi mới cập nhật lịch sử.
"""
import csv
import sys
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import THRESHOLD_CHALLENGE
from app.detection.features import (FEATURE_NAMES, EventData, compute_context,
                                    extract_features)
from app.detection.rules import run_rules
from app.utils.device import fingerprint, parse_ua
from app.utils.geoip import lookup_ip

MAX_HISTORY = 500


class Replayer:
    """Giữ trạng thái lịch sử và sinh (đặc trưng, bối cảnh) cho từng sự kiện."""

    def __init__(self, lookback_days: int = 90):
        self.lookback = timedelta(days=lookback_days)
        self.success_history = defaultdict(list)   # username -> [EventData]
        self.failed_times = defaultdict(deque)     # username -> [datetime]
        self.ip_users = defaultdict(deque)         # ip -> [(datetime, username)]

    def _prune(self, event: EventData):
        cutoff = event.timestamp - self.lookback
        h = self.success_history[event.username]
        while h and h[-1].timestamp < cutoff:
            h.pop()
        if len(h) > MAX_HISTORY:
            del h[MAX_HISTORY:]

        f = self.failed_times[event.username]
        limit = event.timestamp - timedelta(minutes=15)
        while f and f[0] < limit:
            f.popleft()

        iu = self.ip_users[event.ip_address]
        limit_1h = event.timestamp - timedelta(hours=1)
        while iu and iu[0][0] < limit_1h:
            iu.popleft()

    def process(self, event: EventData):
        """Trả về (vector đặc trưng, bối cảnh) rồi cập nhật trạng thái."""
        self._prune(event)

        history = self.success_history[event.username]        # mới nhất trước
        failed_15 = len(self.failed_times[event.username])
        distinct_users = len({u for _, u in self.ip_users[event.ip_address]})

        ctx = compute_context(event, history, failed_15, distinct_users)
        feats = extract_features(event, ctx)

        # Cập nhật trạng thái SAU khi đã tính đặc trưng.
        #
        # Chỉ những lần đăng nhập đáng tin mới được vào hồ sơ hành vi:
        # thành công và không bị rule engine gắn cờ. Quy tắc này phải khớp
        # chính xác với bộ lọc trong build_context_from_db(), nếu không
        # mô hình sẽ được huấn luyện trên một định nghĩa lịch sử khác với
        # định nghĩa lúc chạy thật.
        if event.login_successful:
            rule_score = min(sum(h.score for h in run_rules(event, ctx)), 100.0)
            if rule_score < THRESHOLD_CHALLENGE:
                history.insert(0, event)
        else:
            self.failed_times[event.username].append(event.timestamp)
        self.ip_users[event.ip_address].append((event.timestamp, event.username))

        return feats, ctx


def event_from_csv_row(r: dict) -> EventData:
    """Bổ sung thông tin địa lý và thiết bị cho một dòng CSV thô."""
    geo = lookup_ip(r["ip_address"])
    dev = parse_ua(r["user_agent"])
    return EventData(
        username=r["username"],
        ip_address=r["ip_address"],
        timestamp=datetime.fromisoformat(r["timestamp"]),
        login_successful=bool(int(r["login_successful"])),
        country=geo["country"], city=geo["city"],
        latitude=geo["lat"], longitude=geo["lon"],
        network_type=geo["network_type"],
        device_fingerprint=fingerprint(r["user_agent"], r["ip_address"]),
        device_type=dev["device_type"],
        user_agent=r["user_agent"],
        is_attack=bool(int(r.get("is_attack", 0))),
        attack_type=r.get("attack_type") or None,
    )


def build_dataset(csv_path: str, lookback_days: int = 90):
    """Đọc CSV thô, trả về (X, y, events, contexts).

    X: danh sách vector đặc trưng, cùng thứ tự với FEATURE_NAMES
    y: nhãn 0/1
    """
    rows = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append(r)

    rows.sort(key=lambda r: r["timestamp"])

    replayer = Replayer(lookback_days)
    X, y, events, contexts = [], [], [], []

    for r in rows:
        ev = event_from_csv_row(r)
        feats, ctx = replayer.process(ev)
        X.append(feats)
        y.append(1 if ev.is_attack else 0)
        events.append(ev)
        contexts.append(ctx)

    return X, y, events, contexts


if __name__ == "__main__":
    import numpy as np
    path = sys.argv[1] if len(sys.argv) > 1 else "data/login_events.csv"
    X, y, ev, ctx = build_dataset(path)
    X = np.array(X)
    print(f"Đã tính đặc trưng cho {len(X)} sự kiện, {X.shape[1]} chiều")
    print(f"Số mẫu tấn công: {sum(y)}")
    for i, name in enumerate(FEATURE_NAMES):
        print(f"  {name:30s} trung bình {X[:, i].mean():8.3f}  "
              f"lệch chuẩn {X[:, i].std():8.3f}")
