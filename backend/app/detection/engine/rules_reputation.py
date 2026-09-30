"""Nhóm "Danh tiếng hạ tầng": Tor, datacenter, VPN thương mại và blocklist của quản trị viên.

Nguồn: danh sách công khai (backend/threat_intel/, tải bằng scripts/update_threat_feeds.py) và Blocklist trong bộ nhớ (MR12 lưu DB). Thiếu danh sách thì
luật bị BỎ QUA với lý do rõ ràng (engine ghi vào `Evaluation.skipped`), không báo động sai.
"""

from __future__ import annotations

from app.detection.engine.registry import RuleContext, rule
from app.detection.engine.types import Finding

CATEGORY = "Danh tiếng hạ tầng"


def _outcome(success: bool) -> str:
    return "thành công" if success else "thất bại"


@rule(
    id="tor_exit",
    verification="verified",  # Milestone A — artifacts/behavior_verification/tor_exit.json
    title="Đăng nhập từ Tor exit node",
    category=CATEGORY,
    severity="medium",
    techniques=("T1090.003",),
    description="IP nguồn nằm trong danh sách exit node chính thức của Tor Project — lưu lượng bị ẩn nguồn gốc qua nhiều chặng.",
    needs=("tor_list",),
    notes="Tor có người dùng hợp lệ (riêng tư, kiểm duyệt) nên chỉ mức trung bình; danh sách là bản chụp, exit node đổi hằng ngày.",
)
def tor_exit(ctx: RuleContext) -> Finding | None:
    a = ctx.attempt
    if not ctx.intel.is_tor(a.ip):
        return None
    return Finding(f"IP {a.ip} là Tor exit node (đăng nhập {_outcome(a.success)}).", {"ip": a.ip, "list": "tor"})


@rule(
    id="datacenter_ip",
    title="Đăng nhập từ dải IP datacenter",
    category=CATEGORY,
    severity="low",
    techniques=("T1090.002",),
    description="IP nguồn thuộc dải của nhà cung cấp hosting/đám mây — người dùng thật hiếm khi đăng nhập từ máy chủ; kẻ tấn công thuê VPS/proxy thì thường.",
    needs=("datacenter_list",),
    default_mode="shadow",
    notes="Danh sách cộng đồng (X4BNet lists_vpn) KHÔNG đầy đủ và báo nhầm với VPN/đám mây của chính người dùng (làm việc từ xa); chế độ shadow đến khi đo được tỉ lệ báo nhầm trên log thật.",
)
def datacenter_ip(ctx: RuleContext) -> Finding | None:
    a = ctx.attempt
    if not ctx.intel.in_datacenter(a.ip):
        return None
    return Finding(f"IP {a.ip} thuộc dải datacenter/hosting (đăng nhập {_outcome(a.success)}).", {"ip": a.ip, "list": "datacenter"})


@rule(
    id="vpn_ip",
    title="Đăng nhập từ dải IP VPN thương mại",
    category=CATEGORY,
    severity="low",
    techniques=("T1090",),
    description="IP nguồn thuộc dải của dịch vụ VPN thương mại — che vị trí thật, thường thấy khi kẻ tấn công muốn 'ở cùng nước' với nạn nhân.",
    needs=("vpn_list",),
    default_mode="shadow",
    notes="Nhiều người dùng thật dùng VPN; chỉ có ý nghĩa khi kết hợp với tín hiệu khác (đổi quốc gia, thiết bị mới). Chế độ shadow mặc định.",
)
def vpn_ip(ctx: RuleContext) -> Finding | None:
    a = ctx.attempt
    if not ctx.intel.in_vpn(a.ip):
        return None
    return Finding(f"IP {a.ip} thuộc dải VPN thương mại (đăng nhập {_outcome(a.success)}).", {"ip": a.ip, "list": "vpn"})


@rule(
    id="blocklist_hit",
    verification="verified",  # Milestone A — artifacts/behavior_verification/blocklist_hit.json
    title="Nguồn nằm trong blocklist",
    category=CATEGORY,
    severity="high",
    description="IP, dải CIDR, ASN hoặc tên đăng nhập của lần thử nằm trong blocklist do quản trị viên đặt (còn hiệu lực).",
    notes="Quyết định của con người nên không ánh xạ kỹ thuật MITRE cụ thể. Hạn dùng của mục chặn so với thời gian của sự kiện. MR16 bổ sung hành động chặn thật.",
)
def blocklist_hit(ctx: RuleContext) -> Finding | None:
    entry = ctx.blocklist.match(ctx.attempt)
    if entry is None:
        return None
    reason = f" — {entry.reason}" if entry.reason else ""
    return Finding(
        f"Nguồn nằm trong blocklist ({entry.kind} {entry.value}){reason}.",
        {"kind": entry.kind, "value": entry.value, "reason": entry.reason, "added_by": entry.added_by},
    )
