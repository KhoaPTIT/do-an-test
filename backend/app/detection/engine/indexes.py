"""Chỉ mục cửa sổ thời gian: engine GHI cho mỗi lần thử, các luật ĐỌC — tên khoá nằm ở một chỗ để hai phía không lệch nhau.

Quy ước tên khoá: `<loại>:<đối tượng>:<giá trị>`. Loại nhật ký (`log`) đếm số lần; loại tập (`set`) đếm giá trị khác nhau.

| Khoá                 | Loại | Nội dung                                              | Ghi khi           |
|----------------------|------|-------------------------------------------------------|-------------------|
| `fail:u:<tên>`       | log  | mỗi lần THẤT BẠI vào tên đăng nhập                    | thất bại          |
| `fi:u:<tên>`         | set  | IP đã thất bại vào tên đăng nhập                      | thất bại          |
| `fail:ip:<ip>`       | log  | mỗi lần thất bại từ IP                                | thất bại          |
| `fu:ip:<ip>`         | set  | tên đăng nhập đã thất bại từ IP                       | thất bại          |
| `fua:ip:<ip>`        | set  | User-Agent (băm) đã thất bại từ IP                    | thất bại, có UA   |
| `fuf:ip:<ip>`        | set  | HỌ User-Agent chuẩn hoá (bỏ phiên bản) thất bại từ IP | thất bại, có UA   |
| `nx:ip:<ip>`         | set  | tên KHÔNG tồn tại đã thử từ IP                        | thất bại, tên bịa |
| `fail:asn:<asn>`     | log  | mỗi lần thất bại từ ASN                               | thất bại, có ASN  |
| `fu:asn:<asn>`       | set  | tên đăng nhập đã thất bại từ ASN                      | thất bại, có ASN  |
| `ok:ip:<ip>`         | log  | mỗi lần THÀNH CÔNG từ IP                              | thành công        |
| `ok:asn:<asn>`       | log  | mỗi lần thành công từ ASN                             | thành công, có ASN|
| `ctx:u:<tài khoản>`  | set  | `quốc gia|ip` của đăng nhập thành công                | thành công, có TK |
| `ok:u:<tài khoản>`   | log  | mỗi lần THÀNH CÔNG vào tài khoản (vận tốc đăng nhập)  | thành công, có TK |
| `cc:u:<tên>`         | set  | quốc gia của MỌI lần thử vào tên đăng nhập            | có quốc gia       |
| `fcc:u:<tên>`        | set  | quốc gia của các lần THẤT BẠI vào tên đăng nhập       | thất bại, có QG   |

Giữ 24 giờ (`RETENTION_SHORT`); riêng `cc:u`/`fcc:u` giữ 7 ngày (`RETENTION_LONG`). Tham số cửa sổ của luật bị chặn ở đúng hai mức này (`Param.maximum`).
"""

from __future__ import annotations

from app.detection.engine.state import WindowStore
from app.detection.engine.types import LoginAttempt

RETENTION_SHORT = 24 * 3600.0
RETENTION_LONG = 7 * 24 * 3600.0
CAP = 200  # chặn chi phí đếm giá trị khác nhau ở MemoryStore: luật chỉ cần biết "≥ ngưỡng" (ngưỡng luôn nhỏ hơn CAP)


def fail_user(username: str) -> str:
    return f"fail:u:{username}"


def fail_ips_of_user(username: str) -> str:
    return f"fi:u:{username}"


def fail_ip(ip: str) -> str:
    return f"fail:ip:{ip}"


def fail_users_of_ip(ip: str) -> str:
    return f"fu:ip:{ip}"


def fail_agents_of_ip(ip: str) -> str:
    return f"fua:ip:{ip}"


def fail_agent_families_of_ip(ip: str) -> str:
    return f"fuf:ip:{ip}"


def unknown_users_of_ip(ip: str) -> str:
    return f"nx:ip:{ip}"


def fail_asn(asn: int) -> str:
    return f"fail:asn:{asn}"


def fail_users_of_asn(asn: int) -> str:
    return f"fu:asn:{asn}"


def ok_ip(ip: str) -> str:
    return f"ok:ip:{ip}"


def ok_asn(asn: int) -> str:
    return f"ok:asn:{asn}"


def ok_user(user_key: str) -> str:
    return f"ok:u:{user_key}"


def contexts_of_user(user_key: str) -> str:
    return f"ctx:u:{user_key}"


def countries_of_username(username: str) -> str:
    return f"cc:u:{username}"


def fail_countries_of_username(username: str) -> str:
    return f"fcc:u:{username}"


def context_value(country: str | None, ip: str) -> str:
    return f"{country or '?'}|{ip}"


def record(store: WindowStore, a: LoginAttempt) -> None:
    """Ghi MỘT lần thử vào mọi chỉ mục liên quan. Gọi TRƯỚC khi chấm luật, nên số đếm đã gồm chính lần thử này."""
    if a.success:
        store.log_add(ok_ip(a.ip), a.ts, RETENTION_SHORT)
        if a.asn is not None:
            store.log_add(ok_asn(a.asn), a.ts, RETENTION_SHORT)
        if a.user_key is not None:
            store.set_add(contexts_of_user(a.user_key), a.ts, context_value(a.country, a.ip), RETENTION_SHORT)
            store.log_add(ok_user(a.user_key), a.ts, RETENTION_SHORT)
    else:
        store.log_add(fail_user(a.username), a.ts, RETENTION_SHORT)
        store.set_add(fail_ips_of_user(a.username), a.ts, a.ip, RETENTION_SHORT)
        store.log_add(fail_ip(a.ip), a.ts, RETENTION_SHORT)
        store.set_add(fail_users_of_ip(a.ip), a.ts, a.username, RETENTION_SHORT)
        if a.ua_hash:
            store.set_add(fail_agents_of_ip(a.ip), a.ts, a.ua_hash, RETENTION_SHORT)
        if a.device_family:
            store.set_add(fail_agent_families_of_ip(a.ip), a.ts, a.device_family, RETENTION_SHORT)
        if a.user_key is None:
            store.set_add(unknown_users_of_ip(a.ip), a.ts, a.username, RETENTION_SHORT)
        if a.asn is not None:
            store.log_add(fail_asn(a.asn), a.ts, RETENTION_SHORT)
            store.set_add(fail_users_of_asn(a.asn), a.ts, a.username, RETENTION_SHORT)
    if a.country:
        store.set_add(countries_of_username(a.username), a.ts, a.country, RETENTION_LONG)
        if not a.success:
            store.set_add(fail_countries_of_username(a.username), a.ts, a.country, RETENTION_LONG)
