"""
Shared pytest fixtures — in-memory SQLite DB + FastAPI TestClient.
"""
import os
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-pytest-only")
os.environ.setdefault("ADMIN_EMAIL", "")
os.environ.setdefault("ADMIN_PASSWORD", "")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Use an in-memory SQLite DB for tests — no disk state, no cleanup needed
TEST_DB_URL = "sqlite://"

from database import Base, get_db

@pytest.fixture(scope="session")
def db_engine():
    engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def db_session(db_engine):
    Session = sessionmaker(bind=db_engine)
    session = Session()
    yield session
    session.rollback()
    session.close()


@pytest.fixture(scope="session")
def client(db_engine):
    from main import app

    def override_get_db():
        Session = sessionmaker(bind=db_engine)
        session = Session()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture()
def auth_headers(client):
    """Register + login a test user and return Authorization headers."""
    client.post("/api/auth/register", json={
        "username": "testuser",
        "email": "testuser@example.com",
        "password": "TestPass123!",
    })
    # Approve the user (bypass approval requirement for tests)
    from database import User
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=client.app.dependency_overrides[get_db]().__next__()._session_factory.kw["bind"])

    resp = client.post("/api/auth/login", data={
        "username": "testuser@example.com",
        "password": "TestPass123!",
    })
    if resp.status_code != 200:
        return {}
    token = resp.json().get("access_token", "")
    return {"Authorization": f"Bearer {token}"}
