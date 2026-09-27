"""MR14 — "Tương quan chiến dịch": gom nhiều `Alert` được coi là CÙNG một đợt tấn công dùng chung hạ tầng (IP/ASN)
NHẮM VÀO NHIỀU TÀI KHOẢN KHÁC NHAU — khác chống trùng lặp của MR13 (`alert_intelligence.py`, chỉ gộp CÙNG một
tài khoản/IP lặp lại nhiều lần).

Thuật toán: NỐI hai sự kiện nếu (CÙNG IP HOẶC CÙNG ASN) VÀ cách nhau không quá `window` — rồi lấy các THÀNH PHẦN LIÊN
THÔNG (Union-Find). Tại sao nối theo đồ thị thay vì gom trực tiếp theo (ASN, khung giờ cố định): hai sự kiện A-B cách
5 ngày cùng IP, B-C cách 5 ngày cùng ASN (không cùng IP với A) vẫn nên CÙNG một chiến dịch (chuỗi bắc cầu qua B) dù A-C
không có điểm chung trực tiếp nào trong `window` — cách gom "khung giờ cố định" (vd theo ngày) sẽ bỏ lỡ ca này.

Dùng CHUNG cho hai nơi: (1) `ml/rba/campaign_correlation_eval.py` — kiểm chứng trên 141 ATO thật của RBA (không phải
giả thuyết: đo trực tiếp coi thuật toán có phục hồi được các cụm nhiều nạn nhân dùng chung hạ tầng đã biết hay không);
(2) `app/detection/pipeline.py` — gán `Alert.campaign_id` cho luồng thật (chỉ MỞ RỘNG chiến dịch đang có khi có alert
mới khớp, KHÔNG gộp lại hai chiến dịch đã tách nếu có alert bắc cầu đến sau — xem giới hạn ở `docs/campaign-correlation.md`).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta


# Cửa sổ dùng cho LUỒNG THẬT (app/detection/pipeline.py) — KHÁC cửa sổ dùng khi kiểm chứng trên RBA
# (ml/rba/campaign_correlation_eval.py quét 1-90 NGÀY vì 141 ATO rải suốt gần 1 năm). Ở đây cần "có nên gộp NGAY hôm
# nay không" để chiến dịch còn hữu ích cho giám sát — 24 giờ đủ dài để bắt một đợt tấn công đang diễn ra trong ngày,
# đủ ngắn để không giữ một chiến dịch "mở" cả tháng trời vì tình cờ trùng ASN với một alert cũ đã nguội.
LIVE_CAMPAIGN_WINDOW = timedelta(hours=24)


@dataclass(frozen=True)
class CorrelationNode:
    """Một sự kiện có thể tương quan — `id` là bất kỳ khoá duy nhất nào (Alert.id thật hoặc row_id của RBA)."""

    id: int
    ts: float  # epoch giây
    ip: str | None
    asn: int | None


def _shares_infra(a: CorrelationNode, b: CorrelationNode) -> bool:
    return (a.ip is not None and a.ip == b.ip) or (a.asn is not None and a.asn == b.asn)


class _UnionFind:
    def __init__(self, ids: list[int]) -> None:
        self._parent = {i: i for i in ids}

    def find(self, x: int) -> int:
        while self._parent[x] != x:
            self._parent[x] = self._parent[self._parent[x]]  # path halving
            x = self._parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[ra] = rb


def correlate(nodes: list[CorrelationNode], *, window: timedelta) -> dict[int, int]:
    """`{node.id: mã thành phần liên thông}` — hai node CÙNG mã khi và chỉ khi có một CHUỖI node trung gian, mỗi bước
    liền kề CÙNG hạ tầng (IP hoặc ASN) và cách nhau không quá `window`.

    Cài đặt: sắp theo thời gian, quét một CỬA SỔ TRƯỢT (node có ts nằm trong `window` TRƯỚC node hiện tại) — so mỗi
    node mới với các node CÒN TRONG cửa sổ thay vì so mọi cặp (n²), đúng tinh thần "không quét toàn bộ nếu tránh
    được" đã theo xuyên suốt dự án; ở quy mô hiện tại (vài trăm alert/141 ATO) n² cũng đủ nhanh, nhưng cách này không
    cần đổi lại nếu dữ liệu lớn hơn."""
    if not nodes:
        return {}
    ordered = sorted(nodes, key=lambda n: n.ts)
    uf = _UnionFind([n.id for n in ordered])
    window_s = window.total_seconds()

    active: list[CorrelationNode] = []  # cửa sổ trượt, luôn có ts >= current.ts - window_s
    for node in ordered:
        active = [n for n in active if node.ts - n.ts <= window_s]
        for other in active:
            if _shares_infra(node, other):
                uf.union(node.id, other.id)
        active.append(node)

    return {n.id: uf.find(n.id) for n in ordered}


@dataclass
class CorrelationCluster:
    """Một thành phần liên thông đã gán mã — dùng chung cho cả báo cáo RBA lẫn luồng thật. ĐẶT TÊN có chủ đích KHÁC
    `app.models.Campaign` (bảng ORM): đây chỉ là kết quả THUẦN của `correlate()`, chưa phải một hàng `Campaign` thật
    trong DB (tránh trùng tên giữa hai khái niệm gần nhau nhưng không giống nhau)."""

    component_id: int
    node_ids: list[int]

    @property
    def size(self) -> int:
        return len(self.node_ids)


def group_by_component(components: dict[int, int]) -> list[CorrelationCluster]:
    """`correlate()` trả về map phẳng — gộp lại thành danh sách `CorrelationCluster` (thành phần chỉ có 1 node vẫn
    được liệt kê, gọi là "chiến dịch đơn lẻ": không dùng chung hạ tầng với ai khác trong `window`)."""
    groups: dict[int, list[int]] = defaultdict(list)
    for node_id, component_id in components.items():
        groups[component_id].append(node_id)
    return [CorrelationCluster(cid, sorted(ids)) for cid, ids in groups.items()]
