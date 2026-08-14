from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .dependencies import identity_dependency
from .models import AuthIdentity
from .service import AuthService


class LoginInput(BaseModel):
    email: str
    password: str
    organization_id: str | None = None


class RefreshInput(BaseModel):
    refresh_token: str


class ResetRequest(BaseModel):
    email: str


class ResetConfirm(BaseModel):
    token: str
    password: str = Field(min_length=8)


def _tokens(tokens) -> dict:
    return {"access_token": tokens.access_token, "refresh_token": tokens.refresh_token, "token_type": "bearer", "expires_in": tokens.expires_in, "identity": tokens.identity.as_dict()}


def create_auth_router(service: AuthService, *, prefix: str = "/auth") -> APIRouter:
    router = APIRouter(prefix=prefix, tags=["auth"])

    @router.post("/login")
    def login(payload: LoginInput):
        tokens = service.login(email=str(payload.email), password=payload.password, organization_id=payload.organization_id)
        if tokens is None:
            raise HTTPException(status_code=401, detail="Invalid credentials or organization.")
        return _tokens(tokens)

    @router.post("/refresh")
    def refresh(payload: RefreshInput):
        tokens = service.refresh(payload.refresh_token)
        if tokens is None:
            raise HTTPException(status_code=401, detail="Invalid refresh token.")
        return _tokens(tokens)

    @router.post("/logout", status_code=204)
    def logout(payload: RefreshInput):
        service.logout(payload.refresh_token)

    @router.get("/me")
    def me(identity: AuthIdentity = Depends(identity_dependency(service))):
        return identity.as_dict()

    @router.post("/password-reset/request")
    def request_reset(payload: ResetRequest):
        service.request_password_reset(str(payload.email))
        return {"status": "If the account exists, reset instructions will be sent."}

    @router.post("/password-reset/confirm")
    def confirm_reset(payload: ResetConfirm):
        if not service.reset_password(payload.token, payload.password):
            raise HTTPException(status_code=400, detail="Invalid or expired reset token.")
        return {"status": "Password updated."}

    return router
