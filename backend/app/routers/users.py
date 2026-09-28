"""GET /users/{id}/profile — checklist MR17 "hồ sơ rủi ro theo user (timeline, alert, thiết bị/quốc gia quen)":
gộp dữ liệu đã có sẵn rải rác (`login_events`, `alerts`, `known_devices`, `known_locations`, `user_risk_profiles`)
thành MỘT view cho một tài khoản — trước MR17 các bảng này chỉ được TỰ GHI bởi pipeline (Tuần 4, MR12, MR15), không có
endpoint nào ĐỌC LẠI riêng theo user để admin xem.

Không phân trang (khác `GET /login-events`/`GET /alerts`) — đây là một "hồ sơ" xem nhanh, giới hạn CỨNG số dòng gần
nhất thay vì phân trang đầy đủ; muốn xem toàn bộ lịch sử chi tiết thì dùng `GET /login-events?username=`/`GET /alerts`
(đã có bộ lọc riêng).

Yêu cầu JWT admin hợp lệ (nhiệm vụ 5.1).
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_admin
from app.models import Alert, KnownDevice, KnownLocation, LoginEvent, User, UserRiskProfile
from app.schemas import UserProfileOut

router = APIRouter()

TIMELINE_LIMIT = 50
ALERTS_LIMIT = 20


@router.get("/users/{user_id}/profile", response_model=UserProfileOut)
def get_user_profile(user_id: int, db: Session = Depends(get_db), _admin: dict = Depends(require_admin)):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Không thấy tài khoản")

    timeline = db.query(LoginEvent).filter(LoginEvent.user_id == user_id).order_by(LoginEvent.created_at.desc()).limit(TIMELINE_LIMIT).all()
    alerts = db.query(Alert).filter(Alert.user_id == user_id).order_by(Alert.created_at.desc()).limit(ALERTS_LIMIT).all()
    known_devices = db.query(KnownDevice).filter(KnownDevice.user_id == user_id).order_by(KnownDevice.last_seen_at.desc()).all()
    known_locations = db.query(KnownLocation).filter(KnownLocation.user_id == user_id).order_by(KnownLocation.last_seen_at.desc()).all()
    risk_profile = db.get(UserRiskProfile, user_id)

    return UserProfileOut(
        id=user.id, username=user.username, created_at=user.created_at, importance=user.importance,
        timeline=timeline, alerts=alerts, known_devices=known_devices, known_locations=known_locations,
        risk_profile=risk_profile,
    )
