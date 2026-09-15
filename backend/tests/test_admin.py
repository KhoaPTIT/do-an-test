"""Kiểm tra nhiệm vụ 5.1 — JWT cho admin & WebSocket."""

from app.models import Admin
from app.security import hash_password

ADMIN_PASSWORD = "MatKhauQuanTri123!"


def _create_admin(db_session, username="admin"):
    admin = Admin(username=username, password_hash=hash_password(ADMIN_PASSWORD))
    db_session.add(admin)
    db_session.commit()
    return admin


def test_admin_login_success_returns_token(client, db_session):
    _create_admin(db_session)

    response = client.post("/admin/login", json={"username": "admin", "password": ADMIN_PASSWORD})

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert len(body["access_token"]) > 20


def test_admin_login_wrong_password_returns_401(client, db_session):
    _create_admin(db_session)

    response = client.post("/admin/login", json={"username": "admin", "password": "sai"})
    assert response.status_code == 401


def test_admin_route_without_token_returns_401(client, db_session):
    response = client.get("/login-events")
    assert response.status_code == 401
    assert response.json() == {} or "detail" in response.json()


def test_admin_route_with_valid_token_returns_200(client, db_session):
    _create_admin(db_session)
    login = client.post("/admin/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    token = login.json()["access_token"]

    response = client.get("/login-events", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    body = response.json()
    assert "items" in body and "total" in body


def test_alerts_route_without_token_returns_401(client, db_session):
    response = client.get("/alerts")
    assert response.status_code == 401


def test_admin_route_with_garbage_token_returns_401(client, db_session):
    response = client.get("/login-events", headers={"Authorization": "Bearer khong-phai-jwt-hop-le"})
    assert response.status_code == 401


def test_websocket_rejects_connection_without_token(client, db_session):
    from starlette.websockets import WebSocketDisconnect

    try:
        with client.websocket_connect("/ws/alerts"):
            raise AssertionError("Kết nối không có token đáng lẽ phải bị từ chối")
    except WebSocketDisconnect:
        pass  # đúng như mong đợi — server đóng kết nối ngay


def test_websocket_accepts_connection_with_valid_token(client, db_session):
    _create_admin(db_session)
    login = client.post("/admin/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    token = login.json()["access_token"]

    with client.websocket_connect(f"/ws/alerts?token={token}") as ws:
        # Kết nối thành công — không raise là đủ để xác nhận.
        assert ws is not None
