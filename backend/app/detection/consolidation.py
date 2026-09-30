"""Gộp cảnh báo theo CHIẾN DỊCH (Phase 3 — Milestone B, B0.3/B0.4): tác nhân/mục tiêu + cửa sổ thời gian + nhóm hành vi
+ độ đặc hiệu của detector. Hàm THUẦN (pipeline truy vấn ứng viên rồi gọi `pick_campaign`).

Vấn đề đo được ở Milestone A: một đợt rải mật khẩu sinh hàng trăm cảnh báo `scripted_client` riêng lẻ (mỗi tài khoản nạn
nhân một cái) cộng cảnh báo `password_spray_slow`; dò danh sách tài khoản báo trước rồi nhồi thông tin báo sau thành hai
cảnh báo; brute force báo trước dò phân tán. Cả ba đều là MỘT chuỗi sự kiện.

Quy tắc — một lần thử có detector chính P được gộp vào cảnh báo đang mở C (detector chính Q) nếu CÙNG CHIẾN DỊCH:
  - P == Q và cùng tác nhân theo phạm vi của luật (IP nguồn cho luật theo IP, tài khoản cho luật theo tài khoản); hoặc
  - P hoặc Q là tín hiệu ĐÁNH DẤU (tự động hoá / danh tiếng hạ tầng — mô tả CÁCH tấn công, không phải hành vi) và hai
    bên chung IP nguồn HOẶC chung tài khoản mục tiêu; hoặc
  - P và Q cùng NHÓM hành vi (`CAMPAIGN_GROUPS`) và cùng tác nhân theo phạm vi của nhóm;
  và C còn hoạt động trong cửa sổ TRƯỢT (`last_seen_at` — không phải thời điểm tạo) = max(15 phút, cửa sổ của chính các
  luật đó; ≥ 1 giờ khi có tín hiệu đánh dấu).
Khi gộp: detector ĐẶC HIỆU HƠN (thứ tự `attribution.PRIORITY`) làm detector chính của cảnh báo; bên kia vào
`secondary_signals` (nâng cấp: Q vào `superseded_detectors`). Không mất bằng chứng: mọi luật đã khớp được giữ lại.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable

from app.detection.attribution import PRIORITY
from app.detection.engine.registry import REGISTRY

DETECTION_ALERT_TYPES = ("hybrid_risk", "behavior_anomaly")
BEHAVIORAL_CATEGORY = "Hồ sơ hành vi"  # luật hồ sơ hành vi -> alert_type "behavior_anomaly"
MARKER_CATEGORIES = ("Tự động hoá", "Danh tiếng hạ tầng")

CONSOLIDATION_FLOOR = timedelta(minutes=15)  # = alert_intelligence.DEDUP_WINDOW (MR13)
MARKER_WINDOW = timedelta(hours=1)

# Nhóm hành vi cùng một chuỗi sự kiện, kèm phạm vi tác nhân của nhóm.
CAMPAIGN_GROUPS: dict[str, tuple[str, frozenset[str]]] = {
    "ip_credential_attack": ("ip", frozenset({"credential_stuffing", "password_spray_slow", "username_enumeration"})),
    "account_password_attack": ("account", frozenset({"success_after_failures", "distributed_bruteforce", "brute_force"})),
    "account_context": ("account", frozenset({"impossible_travel", "multi_context_simultaneous", "dormant_account_login", "country_hop", "rare_network_login", "unusual_device"})),
}
_IP_SCOPED_RULES = frozenset({"credential_stuffing", "password_spray_slow", "username_enumeration"})
_RANK = {r: i for i, r in enumerate(PRIORITY)}


def is_marker(rule_id: str) -> bool:
    spec = REGISTRY.get(rule_id)
    return spec is not None and spec.category in MARKER_CATEGORIES


def alert_type_for(rule_id: str | None) -> str:
    spec = REGISTRY.get(rule_id) if rule_id else None
    return "behavior_anomaly" if spec is not None and spec.category == BEHAVIORAL_CATEGORY else "hybrid_risk"


def _group_of(rule_id: str) -> str | None:
    return next((name for name, (_, members) in CAMPAIGN_GROUPS.items() if rule_id in members), None)


def _rule_window(rule_id: str) -> timedelta:
    spec = REGISTRY.get(rule_id)
    seconds = next((p.default for p in spec.params if p.name == "window_s"), 0) if spec is not None else 0
    return timedelta(seconds=seconds)


def window_for(new_rule: str, old_rule: str) -> timedelta:
    window = max(CONSOLIDATION_FLOOR, _rule_window(new_rule), _rule_window(old_rule))
    if is_marker(new_rule) or is_marker(old_rule):
        window = max(window, MARKER_WINDOW)
    return window


def related(new_rule: str, old_rule: str, *, same_ip: bool, same_account: bool) -> bool:
    if is_marker(new_rule) or is_marker(old_rule):
        return same_ip or same_account
    if new_rule == old_rule:
        return same_ip if new_rule in _IP_SCOPED_RULES else same_account
    group_new, group_old = _group_of(new_rule), _group_of(old_rule)
    if group_new is None or group_new != group_old:
        return False
    scope = CAMPAIGN_GROUPS[group_new][0]
    return same_ip if scope == "ip" else same_account


def more_specific(a: str, b: str) -> bool:
    """True nếu detector `a` đặc hiệu hơn (ưu tiên cao hơn) `b`."""
    return _RANK.get(a, len(PRIORITY)) < _RANK.get(b, len(PRIORITY))


@dataclass(frozen=True)
class Candidate:
    alert: Any  # hàng Alert (ORM) — module này không đụng tới thuộc tính nào ngoài rule_id
    rule_id: str
    ip: str | None
    account_key: tuple[str, Any]
    last_seen: datetime


def pick_campaign(new_rule: str, *, ip: str, account_key: tuple[str, Any], now: datetime, candidates: Iterable[Candidate]) -> Candidate | None:
    """Cảnh báo đang mở thuộc CÙNG CHIẾN DỊCH với lần thử này (detector chính `new_rule`), hoặc None. Nhiều ứng viên thì
    chọn detector đặc hiệu nhất, rồi mới nhất."""
    matches = [
        c for c in candidates
        if now - c.last_seen <= window_for(new_rule, c.rule_id)
        and related(new_rule, c.rule_id, same_ip=(c.ip is not None and c.ip == ip), same_account=(c.account_key == account_key))
    ]
    if not matches:
        return None
    return min(matches, key=lambda c: (_RANK.get(c.rule_id, len(PRIORITY)), -c.last_seen.timestamp()))
