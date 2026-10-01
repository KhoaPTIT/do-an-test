"""Bộ sinh kịch bản kiểm chứng (Phase 3, Milestone A) — THUẦN, không đụng DB/pipeline.

Mỗi hành vi có hai bộ sinh `positive(rng, i)` / `negative(rng, i)`; runner gọi mỗi bộ 20 lần với `random.Random(seed)`
cố định (tái lập được). Biến thể lấy ngẫu nhiên tham số (số lần thử, khoảng cách, IP trong đúng vùng địa lý fixture,
User-Agent trình duyệt/kịch bản...) — dương tính luôn THOẢ định nghĩa hành vi (kể cả ngay sát ngưỡng), âm tính gồm
các ca SÁT NGƯỠNG (ngưỡng − 1, vượt cửa sổ thời gian) và các ca bình thường dễ nhầm (gõ sai, NAT văn phòng...).

⚠️ `Scenario.behavior`/`kind` là NHÃN ĐÁNH GIÁ: chỉ runner đọc để chấm điểm. Không trường nào ở đây được truyền vào
pipeline — pipeline chỉ nhận (tên đăng nhập, kết quả, IP, User-Agent, thời điểm), đúng như luồng /login thật.

⚠️ Giới hạn tự thừa nhận: kịch bản do chính người viết detector thiết kế dựa trên ngưỡng đã biết — recall cao ở đây
chứng minh IMPLEMENTATION + PIPELINE + QUY KẾT đúng, KHÔNG chứng minh hiệu quả trên tấn công thật ngoài đời.
"""

from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from app.detection.engine.registry import REGISTRY
from app.detection.rules import haversine_distance
from verification.fixtures import fixture_lookup_asn, fixture_lookup_ip, ips_in
from verification.harness import CHROME_UA, CURL_UA, EDGE_UA, FIREFOX_UA, MOBILE_UA, PY_REQUESTS_UA, SAFARI_UA

T0 = datetime(2026, 3, 2, 9, 0, 0, tzinfo=timezone.utc)
DAY = 86_400.0

BROWSERS = (CHROME_UA, FIREFOX_UA, EDGE_UA, SAFARI_UA, MOBILE_UA)
SCRIPTED = (CURL_UA, PY_REQUESTS_UA)

# Vùng IP trong TEST FIXTURE (verification/fixtures/geoip.json)
HOME_POOL = ips_in("192.0.2.0/26")  # VN Hà Nội, nhà mạng cố định
MOBILE_POOL = ips_in("192.0.2.64/26")  # VN Hà Nội, di động
HCM_POOL = ips_in("192.0.2.128/27")
HAIPHONG_POOL = ips_in("192.0.2.160/27")
DANANG_POOL = ips_in("192.0.2.192/27")
OFFICE_POOL = ips_in("192.0.2.224/27")
TOR_LIST = [f"198.51.100.{i}" for i in range(1, 41)]  # đúng nội dung verification/fixtures/threat_intel/tor_exit_ips.txt
TOR_NEIGHBOURS = [f"198.51.100.{i}" for i in range(41, 63)]
DATACENTER_POOL = ips_in("198.51.100.64/26")
VPN_POOL = ips_in("198.51.100.128/26")
US_NY_POOL = ips_in("198.51.100.192/26")
JP_POOL = ips_in("203.0.113.0/26")
FR_POOL = ips_in("203.0.113.64/26")
BR_POOL = ips_in("203.0.113.128/26")
US_LA_POOL = ips_in("203.0.113.192/26")
FOREIGN_POOLS = (US_NY_POOL, JP_POOL, FR_POOL, BR_POOL, US_LA_POOL)
VN_OTHER_POOLS = (HCM_POOL, DANANG_POOL)


def param(rule_id: str, name: str):
    return next(p.default for p in REGISTRY[rule_id].params if p.name == name)


@dataclass(frozen=True)
class Step:
    username: str
    success: bool
    ip: str
    offset_s: float
    user_agent: str | None = CHROME_UA


@dataclass(frozen=True)
class HistoryLogin:
    username: str
    ip: str
    offset_s: float  # âm = trước T0
    user_agent: str = CHROME_UA
    success: bool = True


@dataclass(frozen=True)
class Block:
    kind: str
    value: str
    expires_offset_s: float | None = None  # None = vĩnh viễn


@dataclass
class Scenario:
    behavior: str  # NHÃN ĐÁNH GIÁ — chỉ runner đọc
    kind: str  # "positive" | "negative" — NHÃN ĐÁNH GIÁ
    variant: str
    accounts: list[str] = field(default_factory=list)
    history: list[HistoryLogin] = field(default_factory=list)
    blocks: list[Block] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)


# ------------------------------------------------------------------------------------------------ tiện ích


def _pick(rng: random.Random, pool):
    return rng.choice(pool)


def _foreign_ip(rng):
    return rng.choice(rng.choice(FOREIGN_POOLS))


def _ua(rng, scripted_share=0.5):
    return rng.choice(SCRIPTED) if rng.random() < scripted_share else rng.choice(BROWSERS)


def _names(rng, prefix, n):
    tag = rng.randrange(10**6)
    return [f"{prefix}{tag}_{k:02d}" for k in range(n)]


def _seed(sc: Scenario, username: str, *, days: int = 7, ip: str | None = None, ua: str = CHROME_UA, end_offset_s: float = 0.0, hour_jitter_s: float = 0.0):
    """`days` lần đăng nhập thành công/ngày kết thúc 1 ngày trước `end_offset_s` — lịch sử quen thuộc của tài khoản."""
    sc.accounts.append(username)
    ip = ip or HOME_POOL[0]
    for d in range(days, 0, -1):
        sc.history.append(HistoryLogin(username, ip, end_offset_s - d * DAY + hour_jitter_s, ua))


def _km(ip_a: str, ip_b: str) -> float:
    a, b = fixture_lookup_ip(ip_a), fixture_lookup_ip(ip_b)
    return haversine_distance(a.latitude, a.longitude, b.latitude, b.longitude)


# ------------------------------------------------------------------------------------------------ username_enumeration


def enum_positive(rng, i):
    sc = Scenario("username_enumeration", "positive", "")
    n = rng.randint(param("username_enumeration", "min_usernames"), 14)
    gap = rng.uniform(35, min(75, 590 / (n - 1)))  # ≥35s: không đủ 10 lần/300s của credential_stuffing
    ip, ua = _foreign_ip(rng) if rng.random() < 0.7 else _pick(rng, rng.choice(VN_OTHER_POOLS)), _ua(rng)
    for k, name in enumerate(_names(rng, "ghost", n)):
        sc.steps.append(Step(name, False, ip, k * gap, ua))
    sc.variant = f"{n} tên không tồn tại, cách {gap:.0f}s, UA={'kịch bản' if ua in SCRIPTED else 'trình duyệt'}"
    return sc


def enum_negative(rng, i):
    sc = Scenario("username_enumeration", "negative", "")
    kind = i % 5
    ip = _foreign_ip(rng)
    if kind == 0:  # ngưỡng − 1
        n, gap = param("username_enumeration", "min_usernames") - 1, rng.uniform(30, 80)
        sc.steps += [Step(name, False, ip, k * gap) for k, name in enumerate(_names(rng, "ghost", n))]
        sc.variant = f"{n} tên không tồn tại trong cửa sổ (ngưỡng − 1)"
    elif kind == 1:  # chủ tài khoản gõ sai tên vài lần rồi đúng
        home = _pick(rng, HOME_POOL)
        _seed(sc, "owner", ip=home)
        typos = rng.randint(1, 3)
        sc.steps += [Step(f"ownr{k}", False, home, k * 15) for k in range(typos)]
        sc.steps.append(Step("owner", True, home, typos * 15 + 10))
        sc.variant = f"gõ sai tên đăng nhập {typos} lần rồi đăng nhập đúng"
    elif kind == 2:  # đủ số tên nhưng dàn ra quá cửa sổ 600s
        n, gap = param("username_enumeration", "min_usernames"), rng.uniform(88, 130)
        sc.steps += [Step(name, False, ip, k * gap) for k, name in enumerate(_names(rng, "ghost", n))]
        sc.variant = f"{n} tên, cách {gap:.0f}s (vượt cửa sổ)"
    elif kind == 3:  # nhiều người gõ sai tên, mỗi người một IP khác
        n = rng.randint(8, 12)
        sc.steps += [Step(name, False, _pick(rng, HOME_POOL + MOBILE_POOL), k * 40) for k, name in enumerate(_names(rng, "typo", n))]
        sc.variant = f"{n} tên sai từ {n} IP khác nhau"
    else:  # tên CÓ tồn tại (không phải dò danh sách)
        names = _names(rng, "real", 8)
        for name in names:
            _seed(sc, name, days=2)
        sc.steps += [Step(name, False, ip, k * 50) for k, name in enumerate(names)]
        sc.variant = "8 tài khoản CÓ THẬT sai một lần từ một IP (dưới ngưỡng nhồi)"
    return sc


# ------------------------------------------------------------------------------------------------ password_spray_slow


def spray_positive(rng, i):
    sc = Scenario("password_spray_slow", "positive", "")
    n = rng.randint(param("password_spray_slow", "min_users"), 24)
    second_round = rng.randint(0, n // 2) if rng.random() < 0.3 else 0
    total = n + second_round
    gap_min = rng.uniform(6, min(55, 1400 / total))  # ≥6 phút: không bao giờ 10 lần/5 phút
    ip, ua = _foreign_ip(rng), _ua(rng)
    names = _names(rng, "sp", n)
    for name in names:
        _seed(sc, name, days=3)
    order = names + names[:second_round]
    sc.steps += [Step(name, False, ip, k * gap_min * 60, ua) for k, name in enumerate(order)]
    sc.variant = f"{n} tài khoản ({total} lần sai), cách {gap_min:.0f} phút"
    return sc


def spray_negative(rng, i):
    sc = Scenario("password_spray_slow", "negative", "")
    kind = i % 5
    ip = _foreign_ip(rng)
    if kind == 0:
        names = _names(rng, "sp", param("password_spray_slow", "min_users") - 1)
        for name in names:
            _seed(sc, name, days=2)
        gap = rng.uniform(6, 60)
        sc.steps += [Step(name, False, ip, k * gap * 60) for k, name in enumerate(names)]
        sc.variant = "14 tài khoản (ngưỡng − 1)"
    elif kind == 1:  # NAT văn phòng
        office = _pick(rng, OFFICE_POOL)
        names = _names(rng, "nv", rng.randint(5, 9))
        for k, name in enumerate(names):
            _seed(sc, name, days=3, ip=office)
            sc.steps.append(Step(name, False, office, k * 400))
            sc.steps.append(Step(name, True, office, k * 400 + 30))
        sc.variant = f"NAT văn phòng: {len(names)} nhân viên gõ sai 1 lần rồi đúng"
    elif kind == 2:  # vượt 24h
        names = _names(rng, "sp", param("password_spray_slow", "min_users"))
        for name in names:
            _seed(sc, name, days=2)
        gap = rng.uniform(104, 130)
        sc.steps += [Step(name, False, ip, k * gap * 60) for k, name in enumerate(names)]
        sc.variant = f"15 tài khoản cách {gap:.0f} phút (vượt cửa sổ 24h)"
    elif kind == 3:  # dồn nhiều lần vào từng tài khoản
        names = _names(rng, "sp", 15)
        for name in names:
            _seed(sc, name, days=2)
        t = 0.0
        for name in names:
            for _ in range(4):
                sc.steps.append(Step(name, False, ip, t))
                t += rng.uniform(3, 6) * 60
        sc.variant = "15 tài khoản × 4 lần sai tuần tự (không rải mỏng)"
    else:  # gia đình dùng chung IP nhà
        home = _pick(rng, HOME_POOL)
        names = _names(rng, "fam", 3)
        for k, name in enumerate(names):
            _seed(sc, name, days=5, ip=home)
            sc.steps.append(Step(name, False, home, k * 3600))
            sc.steps.append(Step(name, True, home, k * 3600 + 20))
        sc.variant = "3 người trong nhà gõ sai 1 lần"
    return sc


# ------------------------------------------------------------------------------------------------ distributed_bruteforce


def _region_ips(rng, k):
    pool = rng.choice((HOME_POOL, MOBILE_POOL, HOME_POOL + MOBILE_POOL + HCM_POOL))
    return rng.sample(pool[1:], k)


def dist_positive(rng, i):
    sc = Scenario("distributed_bruteforce", "positive", "")
    _seed(sc, "victim", ip=HOME_POOL[0])
    n = rng.randint(param("distributed_bruteforce", "min_fails"), 14)
    k = rng.randint(param("distributed_bruteforce", "min_ips"), n)
    ips = _region_ips(rng, k)
    fast = rng.random() < 0.3
    gap = rng.uniform(15, 40) if fast else rng.uniform(80, min(250, 3500 / (n - 1)))
    sc.steps += [Step("victim", False, ips[j % k], j * gap, rng.choice(BROWSERS)) for j in range(n)]
    sc.variant = f"{n} lần sai từ {k} IP cùng khu vực, cách {gap:.0f}s" + (" (nhanh: brute_force cũng khớp)" if fast else "")
    return sc


def dist_negative(rng, i):
    sc = Scenario("distributed_bruteforce", "negative", "")
    _seed(sc, "victim", ip=HOME_POOL[0])
    kind = i % 4
    if kind == 0:
        n = param("distributed_bruteforce", "min_fails") - 1
        ips = _region_ips(rng, rng.randint(5, n))
        gap = rng.uniform(80, 400)
        sc.steps += [Step("victim", False, ips[j % len(ips)], j * gap) for j in range(n)]
        sc.variant = "7 lần sai từ nhiều IP (ngưỡng − 1)"
    elif kind == 1:
        n = rng.randint(8, 12)
        ips = _region_ips(rng, param("distributed_bruteforce", "min_ips") - 1)
        gap = rng.uniform(80, 250)
        sc.steps += [Step("victim", False, ips[j % len(ips)], j * gap) for j in range(n)]
        sc.variant = f"{n} lần sai nhưng chỉ 4 IP"
    elif kind == 2:
        typos = rng.randint(2, 3)
        sc.steps += [Step("victim", False, rng.choice((HOME_POOL[0], MOBILE_POOL[0])), j * 60) for j in range(typos)]
        sc.steps.append(Step("victim", True, HOME_POOL[0], typos * 60 + 30))
        sc.variant = f"chủ tài khoản gõ sai {typos} lần (nhà + di động) rồi đúng"
    else:
        n = param("distributed_bruteforce", "min_fails")
        ips = _region_ips(rng, n)
        gap = rng.uniform(17, 25) * 60
        sc.steps += [Step("victim", False, ips[j], j * gap) for j in range(n)]
        sc.variant = f"8 lần sai từ 8 IP, cách {gap / 60:.0f} phút (vượt cửa sổ 1h)"
    return sc


# ------------------------------------------------------------------------------------------------ success_after_failures


def saf_positive(rng, i):
    sc = Scenario("success_after_failures", "positive", "")
    _seed(sc, "victim", ip=HOME_POOL[0])
    n = rng.randint(param("success_after_failures", "min_fails"), 9)
    delay = rng.uniform(5, 60)
    gap = rng.uniform(10, min(90, (560 - delay) / n))
    ip = _foreign_ip(rng) if rng.random() < 0.6 else _pick(rng, rng.choice(VN_OTHER_POOLS))
    ua = _ua(rng, 0.3)
    sc.steps += [Step("victim", False, ip, j * gap, ua) for j in range(n)]
    sc.steps.append(Step("victim", True, ip, (n - 1) * gap + delay, ua))
    sc.variant = f"{n} lần sai cách {gap:.0f}s rồi đúng sau {delay:.0f}s"
    return sc


def saf_negative(rng, i):
    sc = Scenario("success_after_failures", "negative", "")
    _seed(sc, "victim", ip=HOME_POOL[0])
    kind = i % 4
    ip = _foreign_ip(rng)
    if kind == 0:
        n = param("success_after_failures", "min_fails") - 1
        sc.steps += [Step("victim", False, ip, j * 30) for j in range(n)]
        sc.steps.append(Step("victim", True, ip, n * 30 + 10))
        sc.variant = "4 lần sai rồi đúng (ngưỡng − 1)"
    elif kind == 1:
        n = rng.randint(1, 2)
        sc.steps += [Step("victim", False, HOME_POOL[0], j * 15) for j in range(n)]
        sc.steps.append(Step("victim", True, HOME_POOL[0], n * 15 + 10))
        sc.variant = f"chủ tài khoản gõ sai {n} lần rồi đúng"
    elif kind == 2:
        n = rng.randint(5, 7)
        sc.steps += [Step("victim", False, ip, j * 20) for j in range(n)]
        sc.steps.append(Step("victim", True, ip, (n - 1) * 20 + rng.uniform(620, 1500)))
        sc.variant = f"{n} lần sai, thành công sau hơn 10 phút"
    else:
        n = rng.randint(6, 9)
        sc.steps += [Step("victim", False, ip, j * 30) for j in range(n)]
        sc.variant = f"{n} lần sai, không thành công"
    return sc


# ------------------------------------------------------------------------------------------------ dormant_account_login


def dormant_positive(rng, i):
    sc = Scenario("dormant_account_login", "positive", "")
    idle = rng.uniform(param("dormant_account_login", "dormant_days"), 400) * DAY + 3600
    _seed(sc, "sleeper", days=rng.randint(3, 10), ip=HOME_POOL[0], ua=CHROME_UA, end_offset_s=-idle + DAY)
    change = rng.choice(("device", "device", "device", "country", "both"))
    ip = _foreign_ip(rng) if change in ("country", "both") else HOME_POOL[0]
    ua = rng.choice((FIREFOX_UA, SAFARI_UA, MOBILE_UA, EDGE_UA)) if change in ("device", "both") else CHROME_UA
    sc.steps.append(Step("sleeper", True, ip, 0, ua))
    sc.variant = f"ngủ đông {idle / DAY:.0f} ngày, đổi {change}"
    return sc


def dormant_negative(rng, i):
    sc = Scenario("dormant_account_login", "negative", "")
    kind = i % 4
    if kind == 0:
        idle = rng.uniform(60, param("dormant_account_login", "dormant_days") - 0.5) * DAY
        _seed(sc, "sleeper", days=5, ip=HOME_POOL[0], end_offset_s=-idle + DAY)
        sc.steps.append(Step("sleeper", True, HOME_POOL[0], 0, SAFARI_UA))
        sc.variant = f"nghỉ {idle / DAY:.1f} ngày (< 90) + thiết bị mới"
    elif kind == 1:
        idle = rng.uniform(90, 400) * DAY + 3600
        _seed(sc, "sleeper", days=5, ip=HOME_POOL[0], end_offset_s=-idle + DAY)
        sc.steps.append(Step("sleeper", True, _pick(rng, HOME_POOL), 0, CHROME_UA))
        sc.variant = f"ngủ đông {idle / DAY:.0f} ngày, CÙNG thiết bị và quốc gia"
    elif kind == 2:
        _seed(sc, "active", days=rng.randint(10, 30), ip=HOME_POOL[0])
        sc.steps.append(Step("active", True, HOME_POOL[0], 0, rng.choice((SAFARI_UA, MOBILE_UA))))
        sc.variant = "tài khoản hoạt động hằng ngày + thiết bị mới"
    else:
        idle = rng.uniform(90, 400) * DAY + 3600
        _seed(sc, "sleeper", days=5, ip=HOME_POOL[0], end_offset_s=-idle + DAY)
        sc.steps.append(Step("sleeper", False, _foreign_ip(rng), 0, SAFARI_UA))
        sc.variant = "ngủ đông nhưng lần thử THẤT BẠI"
    return sc


# ------------------------------------------------------------------------------------------------ tor_exit


def tor_positive(rng, i):
    sc = Scenario("tor_exit", "positive", "")
    ip, ua = _pick(rng, TOR_LIST), _ua(rng, 0.3)
    kind = i % 3
    if kind == 0:
        _seed(sc, "alice", ip=HOME_POOL[0])
        sc.steps.append(Step("alice", True, ip, 0, ua))
        sc.variant = f"đăng nhập thành công qua Tor ({ip})"
    elif kind == 1:
        _seed(sc, "alice", ip=HOME_POOL[0])
        sc.steps.append(Step("alice", False, ip, 0, ua))
        sc.variant = f"thử sai một lần qua Tor ({ip})"
    else:
        sc.steps.append(Step(_names(rng, "ghost", 1)[0], False, ip, 0, ua))
        sc.variant = f"tên không tồn tại qua Tor ({ip})"
    return sc


def tor_negative(rng, i):
    sc = Scenario("tor_exit", "negative", "")
    pool, label = [(TOR_NEIGHBOURS, "cùng dải hosting, không trong danh sách"), (HOME_POOL, "IP nhà"), (DATACENTER_POOL, "datacenter (không phải Tor)"), (VPN_POOL, "VPN (không phải Tor)")][i % 4]
    ip = _pick(rng, pool)
    _seed(sc, "alice", ip=HOME_POOL[0])
    sc.steps.append(Step("alice", rng.random() < 0.7, ip, 0, rng.choice(BROWSERS)))
    sc.variant = f"{label} ({ip})"
    return sc


# ------------------------------------------------------------------------------------------------ brute_force


def bf_positive(rng, i):
    sc = Scenario("brute_force", "positive", "")
    user = "victim" if rng.random() < 0.8 else _names(rng, "ghost", 1)[0]
    if user == "victim":
        _seed(sc, "victim", ip=HOME_POOL[0])
    n = rng.randint(param("brute_force", "threshold"), 12)
    gap = rng.uniform(3, 70)  # 5 lần liên tiếp luôn nằm trong 300s
    ip = _foreign_ip(rng) if rng.random() < 0.7 else _pick(rng, rng.choice(VN_OTHER_POOLS))
    ua = _ua(rng, 0.3)
    sc.steps += [Step(user, False, ip, j * gap, ua) for j in range(n)]
    sc.variant = f"{n} lần sai cách {gap:.0f}s" + ("" if user == "victim" else " (tên không tồn tại)")
    return sc


def bf_negative(rng, i):
    sc = Scenario("brute_force", "negative", "")
    _seed(sc, "victim", ip=HOME_POOL[0])
    ip = _foreign_ip(rng)
    kind = i % 4
    if kind == 0:
        n = param("brute_force", "threshold") - 1
        sc.steps += [Step("victim", False, ip, j * rng.uniform(5, 60)) for j in range(n)]
        sc.variant = "4 lần sai (ngưỡng − 1)"
    elif kind == 1:
        n = rng.randint(1, 2)
        sc.steps += [Step("victim", False, HOME_POOL[0], j * 20) for j in range(n)]
        sc.steps.append(Step("victim", True, HOME_POOL[0], n * 20 + 10))
        sc.variant = f"gõ sai {n} lần rồi đúng"
    elif kind == 2:
        gap = rng.uniform(80, 150)
        sc.steps += [Step("victim", False, ip, j * gap) for j in range(param("brute_force", "threshold"))]
        sc.variant = f"5 lần sai cách {gap:.0f}s (vượt cửa sổ)"
    else:
        others = _names(rng, "u", 3)
        for name in others:
            _seed(sc, name, days=2)
        sc.steps += [Step(name, False, ip, j * 30) for j, name in enumerate(others)]
        sc.variant = "3 tài khoản khác nhau mỗi cái sai 1 lần"
    return sc


# ------------------------------------------------------------------------------------------------ credential_stuffing


def cs_positive(rng, i):
    sc = Scenario("credential_stuffing", "positive", "")
    m = rng.randint(param("credential_stuffing", "min_users"), 12)
    real = rng.random() < 0.7
    names = _names(rng, "kh" if real else "leak", m)
    if real:
        for name in names:
            _seed(sc, name, days=2)
    n = rng.randint(max(param("credential_stuffing", "min_fails"), m), min(20, 4 * m))
    gap = rng.uniform(3, 290 / (n - 1))
    ip, ua = _foreign_ip(rng), _ua(rng)
    sc.steps += [Step(names[j % m], False, ip, j * gap, ua) for j in range(n)]
    sc.variant = f"{n} lần sai / {m} tài khoản {'có thật' if real else 'không tồn tại'}, cách {gap:.0f}s"
    return sc


def cs_negative(rng, i):
    sc = Scenario("credential_stuffing", "negative", "")
    ip = _foreign_ip(rng)
    kind = i % 4
    if kind == 0:
        names = _names(rng, "kh", rng.randint(5, 8))
        for name in names:
            _seed(sc, name, days=2)
        n = param("credential_stuffing", "min_fails") - 1
        sc.steps += [Step(names[j % len(names)], False, ip, j * 25) for j in range(n)]
        sc.variant = "9 lần sai / nhiều tài khoản (ngưỡng − 1)"
    elif kind == 1:
        names = _names(rng, "kh", param("credential_stuffing", "min_users") - 1)
        for name in names:
            _seed(sc, name, days=2)
        n = rng.randint(10, 14)
        sc.steps += [Step(names[j % len(names)], False, ip, j * 20) for j in range(n)]
        sc.variant = f"{n} lần sai nhưng chỉ 4 tài khoản"
    elif kind == 2:
        office = _pick(rng, OFFICE_POOL)
        names = _names(rng, "nv", 10)
        for k, name in enumerate(names):
            _seed(sc, name, days=3, ip=office)
            sc.steps.append(Step(name, True, office, k * 25))
            if k < 6:
                sc.steps.append(Step(name, False, office, k * 25 + 5))
        sc.variant = "NAT văn phòng: 10 thành công, 6 lần gõ sai"
    else:
        names = _names(rng, "kh", 5)
        for name in names:
            _seed(sc, name, days=2)
        gap = rng.uniform(35, 60)
        sc.steps += [Step(names[j % 5], False, ip, j * gap) for j in range(10)]
        sc.variant = f"10 lần sai / 5 tài khoản cách {gap:.0f}s (vượt cửa sổ)"
    return sc


# ------------------------------------------------------------------------------------------------ blocklist_hit


def bl_positive(rng, i):
    sc = Scenario("blocklist_hit", "positive", "")
    _seed(sc, "victim", ip=HOME_POOL[0])
    ip = _foreign_ip(rng)
    kind = ("ip", "cidr", "asn", "username")[i % 4]
    value = {"ip": ip, "cidr": str(ipaddress.ip_network(f"{ip}/26", strict=False)), "asn": str(fixture_lookup_asn(ip).asn), "username": "victim"}[kind]
    expires = None if rng.random() < 0.5 else rng.uniform(60, 7 * DAY)
    sc.blocks.append(Block(kind, value, expires))
    sc.steps.append(Step("victim", rng.random() < 0.5, ip, 0, rng.choice(BROWSERS)))
    sc.variant = f"chặn {kind}={value}" + (" (có hạn)" if expires else "")
    return sc


def bl_negative(rng, i):
    sc = Scenario("blocklist_hit", "negative", "")
    _seed(sc, "victim", ip=HOME_POOL[0])
    ip = _foreign_ip(rng)
    kind = i % 4
    if kind == 0:
        sc.blocks.append(Block("ip", ip, -rng.uniform(1, 3600)))
        sc.variant = "mục chặn đã HẾT HẠN"
    elif kind == 1:
        other = _foreign_ip(rng)
        while other == ip:
            other = _foreign_ip(rng)
        sc.blocks.append(Block("ip", other))
        sc.variant = "chặn IP khác"
    elif kind == 2:
        sc.blocks.append(Block("username", "nguoi_khac"))
        sc.variant = "chặn tên đăng nhập khác"
    else:
        sc.blocks.append(Block("asn", "65000"))
        sc.variant = "chặn ASN khác"
    sc.steps.append(Step("victim", rng.random() < 0.5, ip, 0, rng.choice(BROWSERS)))
    return sc


# ------------------------------------------------------------------------------------------------ impossible_travel


def it_positive(rng, i):
    sc = Scenario("impossible_travel", "positive", "")
    home = HOME_POOL[0]
    _seed(sc, "victim", ip=home)
    dest = _foreign_ip(rng)
    km = _km(home, dest)
    max_s = km / (param("impossible_travel", "max_speed_kmh") * 1.1) * 3600
    delta = rng.uniform(60, max_s)
    sc.steps += [Step("victim", True, home, 0), Step("victim", True, dest, delta, rng.choice(BROWSERS))]
    sc.variant = f"{km:.0f}km trong {delta / 60:.0f} phút (~{km / (delta / 3600):,.0f} km/h)"
    return sc


def it_negative(rng, i):
    sc = Scenario("impossible_travel", "negative", "")
    home = HOME_POOL[0]
    _seed(sc, "victim", ip=home)
    kind = i % 4
    if kind == 0:
        dest = _pick(rng, rng.choice((HAIPHONG_POOL, HCM_POOL, DANANG_POOL)))
        km = _km(home, dest)
        delta = max(km / (param("impossible_travel", "max_speed_kmh") * 0.8) * 3600, 1800) * rng.uniform(1.0, 3.0)
        sc.steps += [Step("victim", True, home, 0), Step("victim", True, dest, delta)]
        sc.variant = f"trong nước {km:.0f}km sau {delta / 3600:.1f}h"
    elif kind == 1:
        dest = _foreign_ip(rng)
        km = _km(home, dest)
        delta = km / (param("impossible_travel", "max_speed_kmh") * rng.uniform(0.5, 0.9)) * 3600
        sc.steps += [Step("victim", True, home, 0), Step("victim", True, dest, delta)]
        sc.variant = f"bay thật {km:.0f}km sau {delta / 3600:.1f}h"
    elif kind == 2:
        dest = _foreign_ip(rng)
        sc.steps.append(Step("victim", True, home, 0))
        sc.steps += [Step("victim", False, dest, 120 + j * 40) for j in range(rng.randint(1, 4))]
        sc.variant = "thành công ở nhà rồi THỬ SAI từ nước ngoài"
    else:
        dest = _foreign_ip(rng)
        sc.steps += [Step("victim", False, dest, 0), Step("victim", True, home, rng.uniform(60, 600))]
        sc.variant = "thử sai từ nước ngoài rồi chủ tài khoản đăng nhập ở nhà"
    return sc


# ------------------------------------------------------------------------------------------------ country_hop (Milestone B)

COUNTRY_POOLS = {
    "US": US_NY_POOL + US_LA_POOL, "JP": JP_POOL, "FR": FR_POOL, "BR": BR_POOL,
    "DE": TOR_NEIGHBOURS,  # FIXTURE: DE, cùng dải với exit node nhưng KHÔNG nằm trong danh sách Tor
    "VN": HCM_POOL + DANANG_POOL,
}


def hop_positive(rng, i):
    sc = Scenario("country_hop", "positive", "")
    _seed(sc, "victim", ip=HOME_POOL[0])
    k = rng.randint(param("country_hop", "min_countries"), 5)
    countries = rng.sample(sorted(COUNTRY_POOLS), k)
    attempts = [c for c in countries for _ in range(rng.randint(1, 2))]
    rng.shuffle(attempts)
    gap = rng.uniform(20 * 60, min(5 * 3600, 23 * 3600 / max(len(attempts) - 1, 1)))  # ≥20 phút: không chạm brute_force/dò phân tán
    ua = _ua(rng, 0.3)
    sc.steps += [Step("victim", False, rng.choice(COUNTRY_POOLS[c]), j * gap, ua) for j, c in enumerate(attempts)]
    sc.variant = f"{len(attempts)} lần sai từ {k} quốc gia ({', '.join(countries)}), cách {gap / 3600:.1f}h"
    return sc


def hop_negative(rng, i):
    sc = Scenario("country_hop", "negative", "")
    _seed(sc, "victim", ip=HOME_POOL[0])
    kind = i % 4
    if kind == 0:  # 2 quốc gia (ngưỡng − 1)
        countries = rng.sample(sorted(COUNTRY_POOLS), 2)
        n = rng.randint(2, 6)
        gap = rng.uniform(20 * 60, 3 * 3600)
        sc.steps += [Step("victim", False, rng.choice(COUNTRY_POOLS[countries[j % 2]]), j * gap) for j in range(n)]
        sc.variant = f"{n} lần sai từ 2 quốc gia ({', '.join(countries)})"
    elif kind == 1:  # đi công tác: đăng nhập ĐÚNG ở 3 nước, gõ sai một lần ở một nước
        legs = [HOME_POOL[0], rng.choice(JP_POOL), rng.choice(FR_POOL)]
        times = [0.0, rng.uniform(7, 9) * 3600, rng.uniform(21, 23) * 3600]
        typo_leg = rng.randrange(3)
        for leg, (ip, at) in enumerate(zip(legs, times)):
            if leg == typo_leg:
                sc.steps.append(Step("victim", False, ip, at - 30))
            sc.steps.append(Step("victim", True, ip, at))
        sc.variant = "công tác VN → JP → FR, đăng nhập đúng (1 lần gõ sai)"
    elif kind == 2:  # 3 quốc gia nhưng quá 24h
        countries = rng.sample(sorted(COUNTRY_POOLS), 3)
        times = [0.0, rng.uniform(10, 20) * 3600, rng.uniform(24.5, 30) * 3600]
        sc.steps += [Step("victim", False, rng.choice(COUNTRY_POOLS[c]), t) for c, t in zip(countries, times)]
        sc.variant = f"3 quốc gia ({', '.join(countries)}) trải hơn 24h"
    else:  # chủ tài khoản gõ sai nhiều lần từ trong nước
        n = rng.randint(3, 8)
        sc.steps += [Step("victim", False, rng.choice((HOME_POOL[0], MOBILE_POOL[0])), j * rng.uniform(600, 7200)) for j in range(n)]
        sc.variant = f"{n} lần gõ sai, chỉ trong nước"
    sc.steps.sort(key=lambda st: st.offset_s)
    return sc


# ------------------------------------------------------------------------------------------------ ua_rotation (Milestone B)

ROTATION_UAS = (  # 12 HỌ khác nhau sau chuẩn hoá (loại thiết bị | HĐH | trình duyệt) — kiểm bằng device_family_of
    CHROME_UA, FIREFOX_UA, SAFARI_UA, EDGE_UA, MOBILE_UA,
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    "Mozilla/5.0 (Linux; Android 13; SAMSUNG SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
)


def chrome_version_ua(major: int) -> str:
    return f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.{6000 + major}.85 Safari/537.36"


def rot_positive(rng, i):
    """Công cụ xoay UA khi CHƯA chạm ngưỡng của một hành vi cụ thể hơn (nhồi thông tin/brute force — khi chạm, hành vi đó
    làm detector chính và ua_rotation là tín hiệu phụ: xem test chéo). Miền tham số: 1–4 tài khoản; 2 tài khoản thì cách
    40–85s, còn lại 76–85s (≤4 lần sai/300s nên không chạm brute force/nhồi thông tin), luôn ≥8 lần sai trong 10 phút."""
    sc = Scenario("ua_rotation", "positive", "")
    m = rng.choice((1, 2, 2, 3, 4))
    real = rng.random() < 0.6
    names = _names(rng, "rot" if real else "ghost", m)
    if real:
        for name in names:
            _seed(sc, name, days=3)
    gap = rng.uniform(40, 85) if m == 2 else rng.uniform(76, 85)
    k = rng.randint(param("ua_rotation", "min_distinct_ua"), 8)
    agents = rng.sample(ROTATION_UAS, k)
    n = rng.randint(param("ua_rotation", "min_fails"), 12)
    ip = _foreign_ip(rng)
    sc.steps += [Step(names[j % m], False, ip, j * gap, agents[j % k]) for j in range(n)]
    sc.variant = f"{n} lần sai, {k} họ UA, {m} tài khoản{'' if real else ' (không tồn tại)'}, cách {gap:.0f}s"
    return sc


def rot_negative(rng, i):
    sc = Scenario("ua_rotation", "negative", "")
    kind = i % 5
    if kind == 0:  # Chrome -> Firefox
        _seed(sc, "owner", ip=HOME_POOL[0])
        sc.steps += [Step("owner", False, HOME_POOL[0], 0, CHROME_UA), Step("owner", False, HOME_POOL[0], 40, FIREFOX_UA), Step("owner", True, HOME_POOL[0], 70, FIREFOX_UA)]
        sc.variant = "đổi Chrome → Firefox, gõ sai 2 lần rồi đúng"
    elif kind == 1:  # laptop -> mobile
        _seed(sc, "owner", ip=HOME_POOL[0])
        n = rng.randint(1, 3)
        sc.steps += [Step("owner", False, HOME_POOL[0], j * 30, CHROME_UA) for j in range(n)]
        sc.steps += [Step("owner", False, MOBILE_POOL[0], n * 30 + 60, MOBILE_UA), Step("owner", True, MOBILE_POOL[0], n * 30 + 90, MOBILE_UA)]
        sc.variant = f"laptop sai {n} lần → điện thoại sai 1 lần rồi đúng"
    elif kind == 2:  # nhiều phiên bản Chrome (cùng họ)
        names = _names(rng, "u", 2)
        for name in names:
            _seed(sc, name, days=3)
        n = rng.randint(8, 12)
        ip = _foreign_ip(rng)
        sc.steps += [Step(names[j % 2], False, ip, j * rng.uniform(40, 70), chrome_version_ua(115 + j)) for j in range(n)]
        sc.variant = f"{n} lần sai, {n} phiên bản Chrome (một họ)"
    elif kind == 3:  # 2–3 trình duyệt hợp lệ / ngưỡng − 1 họ
        if rng.random() < 0.5:
            _seed(sc, "owner", ip=HOME_POOL[0])
            browsers = rng.sample((CHROME_UA, FIREFOX_UA, EDGE_UA), rng.randint(2, 3))
            n = rng.randint(3, 6)
            sc.steps += [Step("owner", False, HOME_POOL[0], j * 60, browsers[j % len(browsers)]) for j in range(n)]
            sc.steps.append(Step("owner", True, HOME_POOL[0], n * 60 + 20, browsers[0]))
            sc.variant = f"{len(browsers)} trình duyệt hợp lệ, {n} lần sai rồi đúng"
        else:
            names = _names(rng, "u", 2)
            for name in names:
                _seed(sc, name, days=3)
            agents = rng.sample(ROTATION_UAS, param("ua_rotation", "min_distinct_ua") - 1)
            ip = _foreign_ip(rng)
            sc.steps += [Step(names[j % 2], False, ip, j * rng.uniform(40, 70), agents[j % len(agents)]) for j in range(rng.randint(8, 12))]
            sc.variant = "≥8 lần sai nhưng chỉ 4 họ UA (ngưỡng − 1)"
    else:  # NAT dùng chung
        office = _pick(rng, OFFICE_POOL)
        names = _names(rng, "nv", rng.randint(8, 12))
        for k, name in enumerate(names):
            ua = ROTATION_UAS[k % len(ROTATION_UAS)]
            _seed(sc, name, days=3, ip=office, ua=ua)
            sc.steps += [Step(name, False, office, k * 40, ua), Step(name, True, office, k * 40 + 15, ua)]
        sc.variant = f"NAT văn phòng: {len(names)} người, nhiều trình duyệt, mỗi người gõ sai 1 lần rồi đúng"
    return sc


# ------------------------------------------------------------------------------------------------ scripted_client (Milestone B)

SCRIPTED_TOOL_UAS = (
    "python-requests/2.31.0", "curl/8.7.1", "Wget/1.21.4", "HTTPie/3.2.2", "Go-http-client/1.1", "python-httpx/0.27.0",
    "Python/3.11 aiohttp/3.9.3", "libwww-perl/6.72", "Java/17.0.9", "Apache-HttpClient/4.5.14 (Java/17.0.9)",
)
LEGIT_CLIENT_UAS = BROWSERS + (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "okhttp/4.12.0",  # thư viện HTTP của ứng dụng Android thật — cố ý KHÔNG coi là client kịch bản
)


def scripted_positive(rng, i):
    sc = Scenario("scripted_client", "positive", "")
    ua = SCRIPTED_TOOL_UAS[i % len(SCRIPTED_TOOL_UAS)]
    ip = _foreign_ip(rng) if rng.random() < 0.5 else _pick(rng, HOME_POOL + MOBILE_POOL)
    kind = rng.randrange(3)
    if kind == 0:
        _seed(sc, "alice", ip=HOME_POOL[0])
        sc.steps.append(Step("alice", True, ip, 0, ua))
        sc.variant = f"đăng nhập thành công bằng {ua}"
    elif kind == 1:
        _seed(sc, "alice", ip=HOME_POOL[0])
        n = rng.randint(1, 3)
        sc.steps += [Step("alice", False, ip, j * rng.uniform(60, 300), ua) for j in range(n)]
        sc.variant = f"{n} lần thử sai bằng {ua}"
    else:
        sc.steps.append(Step(_names(rng, "ghost", 1)[0], False, ip, 0, ua))
        sc.variant = f"tên không tồn tại, {ua}"
    return sc


def scripted_negative(rng, i):
    sc = Scenario("scripted_client", "negative", "")
    _seed(sc, "alice", ip=HOME_POOL[0])
    options = LEGIT_CLIENT_UAS + (None, "")
    ua = options[i % len(options)]
    sc.steps.append(Step("alice", rng.random() < 0.7, _pick(rng, HOME_POOL + MOBILE_POOL), 0, ua))
    sc.variant = f"UA {'trống' if not ua else ua[:40]}"
    return sc


GENERATORS: dict[str, tuple[Callable, Callable]] = {
    "username_enumeration": (enum_positive, enum_negative),
    "password_spray_slow": (spray_positive, spray_negative),
    "distributed_bruteforce": (dist_positive, dist_negative),
    "success_after_failures": (saf_positive, saf_negative),
    "dormant_account_login": (dormant_positive, dormant_negative),
    "tor_exit": (tor_positive, tor_negative),
    "brute_force": (bf_positive, bf_negative),
    "credential_stuffing": (cs_positive, cs_negative),
    "blocklist_hit": (bl_positive, bl_negative),
    "impossible_travel": (it_positive, it_negative),
    "country_hop": (hop_positive, hop_negative),
    "ua_rotation": (rot_positive, rot_negative),
    "scripted_client": (scripted_positive, scripted_negative),
}
