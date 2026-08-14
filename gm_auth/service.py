from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from uuid import uuid4

import jwt
from sqlalchemy import and_, select, update

from .models import AuthIdentity, AuthTokens, audit_events, memberships, organizations, password_resets, refresh_sessions, users
from .passwords import hash_password, verify_password


@dataclass(frozen=True, slots=True)
class AuthSettings:
    jwt_secret: str
    access_minutes: int = 15
    refresh_days: int = 30
    reset_minutes: int = 30
    issuer: str = "goodmorning-auth"
    legacy_password_verifier: Callable[[str, str, str], bool] | None = None


AuditHook = Callable[[str, AuthIdentity | None, dict[str, Any]], None]


class AuthService:
    def __init__(self, engine: Any, settings: AuthSettings, audit_hook: AuditHook | None = None) -> None:
        if not settings.jwt_secret or len(settings.jwt_secret) < 32:
            raise ValueError("jwt_secret must contain at least 32 characters.")
        self.engine = engine
        self.settings = settings
        self.audit_hook = audit_hook

    def create_schema(self) -> None:
        from .models import metadata
        metadata.create_all(self.engine)

    def create_organization(self, *, organization_id: str, slug: str, name: str) -> None:
        now = datetime.now(timezone.utc)
        with self.engine.begin() as connection:
            connection.execute(organizations.insert().values(id=organization_id, slug=slug, name=name, created_at=now))

    def create_user(self, *, email: str, name: str, password: str, organization_id: str, roles: set[str] | None = None, permissions: set[str] | None = None, user_id: str | None = None) -> AuthIdentity:
        user_id = user_id or str(uuid4())
        now = datetime.now(timezone.utc)
        identity = AuthIdentity(user_id, organization_id, frozenset(roles or set()), frozenset(permissions or set()), email, name)
        with self.engine.begin() as connection:
            connection.execute(users.insert().values(id=user_id, email=email.lower(), name=name, password_hash=hash_password(password), is_active=True, created_at=now))
            connection.execute(memberships.insert().values(user_id=user_id, organization_id=organization_id, roles=sorted(identity.roles), permissions=sorted(identity.permissions), created_at=now))
        self._audit("user.created", identity, {})
        return identity

    def set_membership(self, *, user_id: str, organization_id: str, roles: set[str], permissions: set[str]) -> None:
        with self.engine.begin() as connection:
            existing = connection.execute(select(memberships).where(and_(memberships.c.user_id == user_id, memberships.c.organization_id == organization_id))).first()
            values = {"user_id": user_id, "organization_id": organization_id, "roles": sorted(roles), "permissions": sorted(permissions), "created_at": datetime.now(timezone.utc)}
            if existing:
                connection.execute(update(memberships).where(and_(memberships.c.user_id == user_id, memberships.c.organization_id == organization_id)).values(roles=values["roles"], permissions=values["permissions"]))
            else:
                connection.execute(memberships.insert().values(**values))

    def login(self, *, email: str, password: str, organization_id: str | None = None) -> AuthTokens | None:
        with self.engine.connect() as connection:
            row = connection.execute(select(users).where(users.c.email == email.lower(), users.c.is_active.is_(True))).mappings().first()
            legacy_match = False
            if row is not None and not verify_password(password, row["password_hash"]) and self.settings.legacy_password_verifier:
                legacy_match = self.settings.legacy_password_verifier(email.lower(), password, str(row["password_hash"]))
            if row is None or (not verify_password(password, row["password_hash"]) and not legacy_match):
                self._audit("login.failed", None, {"email": email.lower()})
                return None
            if legacy_match:
                with self.engine.begin() as write_connection:
                    write_connection.execute(update(users).where(users.c.id == row["id"]).values(password_hash=hash_password(password)))
            query = select(memberships).where(memberships.c.user_id == row["id"])
            if organization_id:
                query = query.where(memberships.c.organization_id == organization_id)
            membership = connection.execute(query).mappings().first()
        if membership is None:
            return None
        identity = self._identity(row, membership)
        tokens = self._issue(identity)
        self._audit("login.succeeded", identity, {})
        return tokens

    def refresh(self, refresh_token: str) -> AuthTokens | None:
        now = datetime.now(timezone.utc)
        token_hash = self._hash_token(refresh_token)
        with self.engine.begin() as connection:
            row = connection.execute(select(refresh_sessions).where(refresh_sessions.c.token_hash == token_hash, refresh_sessions.c.revoked_at.is_(None))).mappings().first()
            if row is None or self._expired(row["expires_at"], now):
                return None
            connection.execute(update(refresh_sessions).where(refresh_sessions.c.id == row["id"]).values(revoked_at=now))
            user = connection.execute(select(users).where(users.c.id == row["user_id"], users.c.is_active.is_(True))).mappings().first()
            membership = connection.execute(select(memberships).where(and_(memberships.c.user_id == row["user_id"], memberships.c.organization_id == row["organization_id"]))).mappings().first()
        if user is None or membership is None:
            return None
        return self._issue(self._identity(user, membership))

    def logout(self, refresh_token: str) -> None:
        with self.engine.begin() as connection:
            connection.execute(update(refresh_sessions).where(refresh_sessions.c.token_hash == self._hash_token(refresh_token)).values(revoked_at=datetime.now(timezone.utc)))

    def identity_from_access_token(self, access_token: str) -> AuthIdentity:
        try:
            payload = jwt.decode(access_token, self.settings.jwt_secret, algorithms=["HS256"], issuer=self.settings.issuer)
            if payload.get("type") != "access":
                raise ValueError
            return AuthIdentity(str(payload["sub"]), str(payload["org"]), frozenset(payload.get("roles", [])), frozenset(payload.get("permissions", [])), payload.get("email"), payload.get("name"))
        except (jwt.PyJWTError, KeyError, TypeError, ValueError) as exc:
            raise ValueError("Invalid access token.") from exc

    def request_password_reset(self, email: str) -> str | None:
        with self.engine.connect() as connection:
            user = connection.execute(select(users).where(users.c.email == email.lower(), users.c.is_active.is_(True))).mappings().first()
        if user is None:
            return None
        token = secrets.token_urlsafe(32)
        with self.engine.begin() as connection:
            connection.execute(password_resets.insert().values(id=str(uuid4()), user_id=user["id"], token_hash=self._hash_token(token), expires_at=datetime.now(timezone.utc) + timedelta(minutes=self.settings.reset_minutes), created_at=datetime.now(timezone.utc)))
        return token

    def reset_password(self, token: str, new_password: str) -> bool:
        now = datetime.now(timezone.utc)
        with self.engine.begin() as connection:
            reset = connection.execute(select(password_resets).where(password_resets.c.token_hash == self._hash_token(token), password_resets.c.used_at.is_(None))).mappings().first()
            if reset is None or self._expired(reset["expires_at"], now):
                return False
            connection.execute(update(users).where(users.c.id == reset["user_id"]).values(password_hash=hash_password(new_password)))
            connection.execute(update(password_resets).where(password_resets.c.id == reset["id"]).values(used_at=now))
            connection.execute(update(refresh_sessions).where(refresh_sessions.c.user_id == reset["user_id"], refresh_sessions.c.revoked_at.is_(None)).values(revoked_at=now))
        return True

    def _issue(self, identity: AuthIdentity) -> AuthTokens:
        now = datetime.now(timezone.utc)
        expires = now + timedelta(minutes=self.settings.access_minutes)
        access = jwt.encode({"sub": identity.user_id, "org": identity.organization_id, "roles": sorted(identity.roles), "permissions": sorted(identity.permissions), "email": identity.email, "name": identity.name, "type": "access", "iss": self.settings.issuer, "iat": now, "exp": expires}, self.settings.jwt_secret, algorithm="HS256")
        refresh = secrets.token_urlsafe(48)
        with self.engine.begin() as connection:
            connection.execute(refresh_sessions.insert().values(id=str(uuid4()), user_id=identity.user_id, organization_id=identity.organization_id, token_hash=self._hash_token(refresh), expires_at=now + timedelta(days=self.settings.refresh_days), created_at=now))
        return AuthTokens(access, refresh, self.settings.access_minutes * 60, identity)

    @staticmethod
    def _identity(user: Any, membership: Any) -> AuthIdentity:
        return AuthIdentity(str(user["id"]), str(membership["organization_id"]), frozenset(membership["roles"] or []), frozenset(membership["permissions"] or []), str(user["email"]), str(user["name"]))

    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def _expired(value: datetime, now: datetime) -> bool:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value <= now

    def _audit(self, event: str, identity: AuthIdentity | None, details: dict[str, Any]) -> None:
        if self.audit_hook:
            self.audit_hook(event, identity, details)
