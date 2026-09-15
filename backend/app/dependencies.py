"""FastAPI dependency dùng chung — xác thực JWT cho route quản trị (nhiệm vụ 5.1)."""

from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.security import decode_admin_access_token

_bearer_scheme = HTTPBearer(auto_error=False)


def require_admin(credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme)) -> dict:
    """Áp vào route quản trị: `Depends(require_admin)`.

    Không có token / token sai / hết hạn / không phải role admin -> 401,
    không trả dữ liệu (đúng yêu cầu checklist mục 5.1).
    """
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Thiếu Authorization header")

    payload = decode_admin_access_token(credentials.credentials)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token không hợp lệ hoặc đã hết hạn")

    return payload
