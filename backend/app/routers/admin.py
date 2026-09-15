"""POST /admin/login — đăng nhập quản trị viên (nhiệm vụ 5.1).

Hoàn toàn tách biệt khỏi POST /login (web app mẫu): bảng `admins` riêng,
không có logic detection/log login_events cho luồng này (đây là backend
office, không phải mục tiêu giám sát).
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Admin
from app.schemas import AdminLoginRequest, AdminLoginResponse
from app.security import create_admin_access_token, verify_password

router = APIRouter()


@router.post("/admin/login", response_model=AdminLoginResponse)
def admin_login(payload: AdminLoginRequest, db: Session = Depends(get_db)):
    admin = db.query(Admin).filter(Admin.username == payload.username).first()

    if admin is None or not verify_password(payload.password, admin.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sai tài khoản hoặc mật khẩu quản trị")

    token = create_admin_access_token(admin.id, admin.username)
    return AdminLoginResponse(access_token=token, token_type="bearer")
