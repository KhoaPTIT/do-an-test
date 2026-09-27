"""Định dạng ngắn cho thông điệp cảnh báo của các luật (tiếng Việt, cùng phong cách chuỗi cảnh báo hiện có)."""

from __future__ import annotations


def window_text(seconds: float) -> str:
    """300 -> '5 phút', 86400 -> '24 giờ', 45 -> '45 giây'."""
    if seconds < 90:
        return f"{seconds:g} giây"
    if seconds < 5_400:
        return f"{seconds / 60:g} phút"
    if seconds < 129_600:
        return f"{seconds / 3_600:g} giờ"
    return f"{seconds / 86_400:g} ngày"


def short(text: str | None, limit: int = 50) -> str:
    """Rút gọn chuỗi dài (User-Agent...) để thông điệp không phình ra."""
    text = (text or "").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"
