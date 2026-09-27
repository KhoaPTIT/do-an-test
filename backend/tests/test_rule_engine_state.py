"""MR9 — kho cửa sổ thời gian: MỘT bộ test cho hai cài đặt (bộ nhớ và Redis) chứng minh cùng hợp đồng."""

import fakeredis
import pytest

from app.detection.engine.state import KEY_PREFIX, MemoryStore, RedisStore

TTL = 3600.0


@pytest.fixture(params=["memory", "redis"])
def store(request):
    if request.param == "memory":
        return MemoryStore()
    return RedisStore(fakeredis.FakeRedis(server=fakeredis.FakeServer(), decode_responses=True))


# ------------------------------------------------------------------------------------------------ nhật ký


def test_log_counts_only_events_strictly_after_since(store):
    for ts in (100.0, 200.0, 300.0):
        store.log_add("k", ts, TTL)
    assert store.log_count("k", 99.9) == 3
    assert store.log_count("k", 100.0) == 2  # mốc đúng bằng `since` không được tính (cửa sổ mở ở đầu cũ)
    assert store.log_count("k", 250.0) == 1
    assert store.log_count("k", 300.0) == 0
    assert store.log_count("missing", 0.0) == 0


def test_log_events_at_the_same_instant_are_kept_separately(store):
    for _ in range(3):
        store.log_add("k", 500.0, TTL)
    assert store.log_count("k", 499.0) == 3


def test_log_recent_returns_the_latest_n_in_ascending_order(store):
    for ts in range(1, 11):
        store.log_add("k", float(ts), TTL)
    assert store.log_recent("k", 3) == [8.0, 9.0, 10.0]
    assert store.log_recent("k", 50) == [float(t) for t in range(1, 11)]
    assert store.log_recent("k", 0) == [] and store.log_recent("missing", 5) == []


def test_log_drops_events_older_than_the_ttl(store):
    store.log_add("k", 0.0, 50.0)
    store.log_add("k", 10.0, 50.0)
    store.log_add("k", 100.0, 50.0)  # 0 và 10 cũ hơn 100 − 50 = 50 → bị bỏ
    assert store.log_count("k", -1.0) == 1 and store.log_recent("k", 10) == [100.0]
    store.log_add("k", 150.0, 50.0)  # đúng bằng ts − ttl thì còn giữ (chỉ bỏ mốc NHỎ HƠN)
    assert store.log_recent("k", 10) == [100.0, 150.0]


def test_log_keys_are_independent(store):
    store.log_add("a", 1.0, TTL)
    store.log_add("b", 1.0, TTL)
    store.log_add("b", 2.0, TTL)
    assert store.log_count("a", 0.0) == 1 and store.log_count("b", 0.0) == 2


# ------------------------------------------------------------------------------------------------ tập


def test_set_counts_distinct_values_by_last_seen_time(store):
    store.set_add("s", 1.0, "a", TTL)
    store.set_add("s", 2.0, "b", TTL)
    store.set_add("s", 3.0, "a", TTL)  # a được thấy lại: chỉ đếm một lần, lần thấy cuối là 3
    assert store.set_count("s", 0.0) == 2
    assert store.set_count("s", 1.5) == 2  # b (2) và a (3)
    assert store.set_count("s", 2.5) == 1  # chỉ a
    assert store.set_count("s", 3.0) == 0
    assert store.set_count("missing", 0.0) == 0


def test_set_count_cap_limits_the_answer(store):
    for i in range(10):
        store.set_add("s", float(i + 1), f"v{i}", TTL)
    assert store.set_count("s", 0.0) == 10
    assert store.set_count("s", 0.0, cap=3) == 3
    assert store.set_count("s", 0.0, cap=50) == 10
    assert store.set_count("s", 8.0, cap=5) == 2  # chỉ v8 (9) và v9 (10)


def test_set_values_are_newest_first_and_respect_since_and_limit(store):
    for i in range(1, 6):
        store.set_add("s", float(i), f"v{i}", TTL)
    assert store.set_values("s", 0.0, limit=3) == ["v5", "v4", "v3"]
    assert store.set_values("s", 3.0) == ["v5", "v4"]
    assert store.set_values("s", 5.0) == [] and store.set_values("missing", 0.0) == []


def test_set_drops_values_last_seen_before_the_ttl(store):
    store.set_add("s", 0.0, "old", 50.0)
    store.set_add("s", 60.0, "new", 50.0)  # old (0) < 60 − 50 → bị bỏ
    assert store.set_values("s", -1.0) == ["new"]
    store.set_add("s", 100.0, "edge", 50.0)  # new (60) ≥ 50 → còn
    assert store.set_count("s", -1.0) == 2


def test_set_refreshing_a_value_keeps_it_alive_past_its_first_ttl(store):
    store.set_add("s", 0.0, "a", 100.0)
    store.set_add("s", 90.0, "a", 100.0)
    store.set_add("s", 150.0, "b", 100.0)  # a lần đầu (0) đã quá hạn nhưng lần thấy cuối (90) còn trong 100 giây
    assert store.set_count("s", -1.0) == 2


# ------------------------------------------------------------------------------------------------ riêng từng cài đặt


def test_memory_store_keeps_the_log_ordered_when_a_timestamp_arrives_late():
    store = MemoryStore()
    store.log_add("k", 10.0, TTL)
    store.log_add("k", 5.0, TTL)  # trễ vài mili-giây giữa hai tiến trình
    assert store.log_recent("k", 5) == [5.0, 10.0] and store.log_count("k", 7.0) == 1


def test_memory_store_counts_a_huge_set_quickly_thanks_to_the_cap():
    store = MemoryStore()
    for i in range(50_000):
        store.set_add("s", float(i), f"v{i}", 10**9)
    assert store.set_count("s", -1.0, cap=20) == 20  # dừng ngay khi đủ cap, không quét cả 50.000 giá trị
    assert store.keys() == 1


def test_redis_store_uses_its_own_key_prefix_and_sets_an_expiry():
    client = fakeredis.FakeRedis(server=fakeredis.FakeServer(), decode_responses=True)
    store = RedisStore(client)
    store.log_add("fail:ip:1.1.1.1", 1.0, 300.0)
    store.set_add("fu:ip:1.1.1.1", 1.0, "alice", 300.0)
    assert sorted(client.keys("*")) == [f"{KEY_PREFIX}fail:ip:1.1.1.1", f"{KEY_PREFIX}fu:ip:1.1.1.1"]  # không đụng khoá `fail:*` của rate_counter.py
    assert all(0 < client.ttl(k) <= 360 for k in client.keys("*"))  # ttl + 60 giây dự phòng: khoá không bao giờ rò bộ nhớ


# ------------------------------------------------------------------------------------------------ dọn khoá quá hạn (chỉ MemoryStore)


def test_sweep_drops_only_the_keys_whose_every_event_is_expired():
    store = MemoryStore(sweep_every=0)
    store.log_add("old", 0.0, 100.0)
    store.set_add("old-set", 10.0, "v", 100.0)
    store.log_add("fresh", 1000.0, 100.0)
    assert store.keys() == 3
    assert store.sweep() == 2  # đồng hồ = 1000: hạn của "old" (100) và "old-set" (110) đều nhỏ hơn 1000 − 60
    assert store.keys() == 1 and store.log_count("fresh", 0.0) == 1
    assert store.log_count("old", -1.0) == 0 and store.set_count("old-set", -1.0) == 0


def test_sweep_keeps_a_key_until_its_slack_has_passed():
    store = MemoryStore(sweep_every=0)
    store.log_add("k", 0.0, 100.0)  # hạn 100
    store.log_add("other", 159.0, 100.0)  # đồng hồ 159 → giới hạn 99 < 100: còn giữ (độ trễ cho phép giống expire của Redis)
    assert store.sweep() == 0 and store.keys() == 2
    store.log_add("other", 161.0, 100.0)  # giới hạn 101 > 100: bỏ
    assert store.sweep() == 1 and store.keys() == 1


def test_memory_stays_bounded_when_keys_keep_appearing_and_expiring():
    store = MemoryStore(sweep_every=100)
    for i in range(20_000):
        store.log_add(f"ip:{i}", float(i), 10.0)  # mỗi khoá một sự kiện, hết hạn sau 10 giây (+ độ trễ 60 giây)
    assert store.keys() < 400  # không dọn thì 20.000 khoá


def test_sweeping_never_changes_an_answer():
    import random

    rng = random.Random(7)
    swept, plain = MemoryStore(sweep_every=25), MemoryStore(sweep_every=0)
    ttl, t = 300.0, 0.0
    for _ in range(4_000):
        t += rng.expovariate(1 / 8.0)
        if rng.random() < 0.5:
            key = f"log{rng.randrange(60)}"
            for s in (swept, plain):
                s.log_add(key, t, ttl)
            assert swept.log_recent(key, 3) == plain.log_recent(key, 3)  # khoá vừa ghi luôn còn nguyên
        else:
            key, value = f"set{rng.randrange(60)}", f"v{rng.randrange(30)}"
            for s in (swept, plain):
                s.set_add(key, t, value, ttl)
        window = rng.choice([30.0, 120.0, 300.0])  # cửa sổ không vượt ttl, đúng như tham số của các luật
        log_probe, set_probe = f"log{rng.randrange(60)}", f"set{rng.randrange(60)}"
        assert swept.log_count(log_probe, t - window) == plain.log_count(log_probe, t - window)
        assert swept.set_count(set_probe, t - window) == plain.set_count(set_probe, t - window)
        assert swept.set_values(set_probe, t - window, 10) == plain.set_values(set_probe, t - window, 10)
    assert swept.keys() < plain.keys()
