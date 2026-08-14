from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from gm_auth import AuthService, AuthSettings, create_auth_router


def service():
    engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    auth = AuthService(engine, AuthSettings("x" * 48))
    auth.create_schema()
    auth.create_organization(organization_id="ballet", slug="ballet", name="Ballet")
    auth.create_user(email="admin@example.com", name="Admin", password="correct horse", organization_id="ballet", roles={"admin"}, permissions={"users.read", "agent.use"})
    return auth


def test_login_identity_refresh_rotation_and_logout():
    auth = service()
    tokens = auth.login(email="admin@example.com", password="correct horse")
    assert tokens is not None
    assert tokens.identity.organization_id == "ballet"
    assert tokens.identity.roles == {"admin"}
    assert auth.identity_from_access_token(tokens.access_token).permissions == {"users.read", "agent.use"}
    rotated = auth.refresh(tokens.refresh_token)
    assert rotated is not None and rotated.refresh_token != tokens.refresh_token
    assert auth.refresh(tokens.refresh_token) is None
    auth.logout(rotated.refresh_token)
    assert auth.refresh(rotated.refresh_token) is None


def test_password_reset_invalidates_refresh_session():
    auth = service()
    tokens = auth.login(email="admin@example.com", password="correct horse")
    reset = auth.request_password_reset("admin@example.com")
    assert reset
    assert auth.reset_password(reset, "new password")
    assert auth.login(email="admin@example.com", password="correct horse") is None
    assert auth.login(email="admin@example.com", password="new password") is not None
    assert auth.refresh(tokens.refresh_token) is None
    assert not auth.reset_password(reset, "another password")


def test_fastapi_router_exposes_identity_and_generic_reset_response():
    auth = service()
    app = FastAPI()
    app.include_router(create_auth_router(auth))
    client = TestClient(app)
    response = client.post("/auth/login", json={"email": "admin@example.com", "password": "correct horse"})
    assert response.status_code == 200
    token = response.json()["access_token"]
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).json()["organization_id"] == "ballet"
    assert client.post("/auth/password-reset/request", json={"email": "missing@example.com"}).json()["status"].startswith("If the account")
