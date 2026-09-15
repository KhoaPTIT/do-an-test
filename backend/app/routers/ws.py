"""WebSocket /ws/alerts — đẩy cảnh báo real-time cho dashboard admin
(nhiệm vụ 5.1 xác thực + 5.3 real-time).

Xác thực bằng JWT admin qua query param `?token=...` KHI HANDSHAKE — không
có token hoặc token không hợp lệ thì đóng kết nối ngay lập tức, không nhận
được dữ liệu (đúng yêu cầu checklist mục 5.1).
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from app.security import decode_admin_access_token
from app.ws_manager import ws_manager

router = APIRouter()


@router.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket, token: str | None = None):
    if token is None or decode_admin_access_token(token) is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await ws_manager.connect(websocket)
    try:
        while True:
            # Client không cần gửi gì lên — chỉ dùng receive() để phát hiện
            # khi nào client ngắt kết nối (đóng tab, mất mạng...).
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
