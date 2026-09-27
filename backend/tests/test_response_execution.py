"""MR16 — app/detection/response_execution.py: quyết định khoá tài khoản/IP, sinh + xác thực mã OTP (thuần, không DB)."""

from app.detection.response_execution import OTP_CODE_LENGTH, generate_otp_code, hash_otp_code, lock_kind_and_value, otp_code_matches


def test_lock_targets_the_account_when_it_exists():
    assert lock_kind_and_value(user_id=1, username="alice", ip="1.2.3.4") == ("username", "alice")


def test_lock_targets_the_ip_when_the_account_does_not_exist():
    assert lock_kind_and_value(user_id=None, username="ghost", ip="1.2.3.4") == ("ip", "1.2.3.4")


def test_generated_otp_code_has_the_right_length_and_is_numeric():
    code = generate_otp_code()
    assert len(code) == OTP_CODE_LENGTH and code.isdigit()


def test_generated_codes_are_not_all_identical():
    codes = {generate_otp_code() for _ in range(20)}
    assert len(codes) > 1  # xác suất 20 mã 6 số trùng hết gần như 0 nếu thật sự ngẫu nhiên


def test_hash_and_verify_round_trip():
    code = "042857"
    hashed = hash_otp_code(code)
    assert code not in hashed  # không lưu bản rõ
    assert otp_code_matches(code, hashed) is True
    assert otp_code_matches("000000", hashed) is False
