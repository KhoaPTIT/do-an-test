"""Fixture dùng chung: DB SQLite in-memory + Redis giả lập (fakeredis)
riêng cho mỗi test, tách biệt hoàn toàn khỏi Postgres/Redis dev — test
không cần Docker đang chạy.
"""

import fakeredis
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app


@pytest.fixture(autouse=True)
def fake_redis(monkeypatch):
    """Thay redis_client thật bằng fakeredis cho MỌI test — brute force,
    credential stuffing đều dùng chung module app.detection.rate_counter.
    """
    client = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr("app.detection.rate_counter.redis_client", client)
    yield client
    client.flushall()


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
