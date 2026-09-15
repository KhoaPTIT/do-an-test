"""Fingerprint thiết bị đơn giản (dùng ở nhiệm vụ 4.1).

⚠️ Giả định — checklist không nói rõ cách tính fingerprint. Dự án không
triển khai fingerprint phía client (canvas/WebGL...) vì web app mẫu không
yêu cầu, nên dùng hash của User-Agent làm fingerprint xấp xỉ. Đủ để phân
biệt "thiết bị/trình duyệt mới" ở mức cơ bản — không chính xác bằng
fingerprint thật (2 người dùng cùng loại máy + cùng trình duyệt sẽ trùng
fingerprint).
"""

from __future__ import annotations

import hashlib


def compute_device_fingerprint(user_agent: str | None) -> str | None:
    if not user_agent:
        return None
    return hashlib.sha256(user_agent.encode("utf-8")).hexdigest()[:32]
