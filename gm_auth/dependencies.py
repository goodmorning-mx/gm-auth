from __future__ import annotations

from typing import Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .models import AuthIdentity
from .service import AuthService

bearer = HTTPBearer(auto_error=False)


def current_identity(service: AuthService, credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> AuthIdentity:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")
    try:
        return service.identity_from_access_token(credentials.credentials)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token.") from exc


def identity_dependency(service: AuthService) -> Callable:
    def dependency(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> AuthIdentity:
        return current_identity(service, credentials)
    return dependency


def require_permissions(service: AuthService, *required: str) -> Callable:
    def dependency(identity: AuthIdentity = Depends(identity_dependency(service))):
        if not set(required) <= identity.permissions:
            raise HTTPException(status_code=403, detail="Insufficient permissions.")
        return identity
    return dependency


def require_roles(service: AuthService, *required: str) -> Callable:
    def dependency(identity: AuthIdentity = Depends(identity_dependency(service))):
        if not set(required) & identity.roles:
            raise HTTPException(status_code=403, detail="Insufficient role.")
        return identity
    return dependency
