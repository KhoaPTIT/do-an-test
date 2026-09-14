"""Kiểm tra nhiệm vụ 3.2 — sliding window đếm fail bằng Redis (fakeredis)."""

from app.detection.rate_counter import FAIL_WINDOW_SECONDS, check_fail_count, record_fail


def test_counter_increments_exactly_n_times(fake_redis):
    key = "fail:test-user"
    for i in range(7):
        count = record_fail(key, client=fake_redis, now=1_000_000 + i)
    assert count == 7
    assert check_fail_count(key, client=fake_redis, now=1_000_006) == 7


def test_counter_resets_after_window_expires(fake_redis):
    key = "fail:test-user"
    base = 2_000_000
    record_fail(key, client=fake_redis, now=base)
    record_fail(key, client=fake_redis, now=base + 1)

    # Vẫn còn trong cửa sổ
    assert check_fail_count(key, client=fake_redis, now=base + 10) == 2

    # Sau khi hết cửa sổ (FAIL_WINDOW_SECONDS), 2 lần fail cũ phải bị loại
    later = base + FAIL_WINDOW_SECONDS + 10
    assert check_fail_count(key, client=fake_redis, now=later) == 0


def test_key_has_ttl_and_does_not_live_forever(fake_redis):
    key = "fail:ttl-user"
    record_fail(key, client=fake_redis, now=3_000_000)

    ttl = fake_redis.ttl(key)
    assert ttl > 0  # có TTL, không phải -1 (vĩnh viễn)
    assert ttl <= FAIL_WINDOW_SECONDS + 60
