from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Integer, JSON, MetaData, String, Table, Column, Text

metadata = MetaData()

organizations = Table(
    "gm_auth_organizations", metadata,
    Column("id", String(128), primary_key=True), Column("slug", String(128), unique=True, nullable=False),
    Column("name", String(255), nullable=False), Column("created_at", DateTime(timezone=True), nullable=False),
)
users = Table(
    "gm_auth_users", metadata,
    Column("id", String(36), primary_key=True), Column("email", String(320), unique=True, nullable=False),
    Column("name", String(255), nullable=False), Column("password_hash", String(255), nullable=False),
    Column("is_active", Boolean, nullable=False, default=True), Column("created_at", DateTime(timezone=True), nullable=False),
)
memberships = Table(
    "gm_auth_memberships", metadata,
    Column("user_id", String(36), primary_key=True), Column("organization_id", String(128), primary_key=True),
    Column("roles", JSON, nullable=False), Column("permissions", JSON, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)
refresh_sessions = Table(
    "gm_auth_refresh_sessions", metadata,
    Column("id", String(36), primary_key=True), Column("user_id", String(36), nullable=False),
    Column("organization_id", String(128), nullable=False), Column("token_hash", String(128), unique=True, nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False), Column("revoked_at", DateTime(timezone=True)),
    Column("created_at", DateTime(timezone=True), nullable=False),
)
password_resets = Table(
    "gm_auth_password_resets", metadata,
    Column("id", String(36), primary_key=True), Column("user_id", String(36), nullable=False),
    Column("token_hash", String(128), unique=True, nullable=False), Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("used_at", DateTime(timezone=True)), Column("created_at", DateTime(timezone=True), nullable=False),
)
audit_events = Table(
    "gm_auth_audit_events", metadata,
    Column("id", String(36), primary_key=True), Column("event", String(128), nullable=False),
    Column("user_id", String(36)), Column("organization_id", String(128)), Column("metadata", JSON, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)


@dataclass(frozen=True, slots=True)
class AuthIdentity:
    user_id: str
    organization_id: str
    roles: frozenset[str]
    permissions: frozenset[str]
    email: str | None = None
    name: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "user_id": self.user_id, "organization_id": self.organization_id,
            "roles": sorted(self.roles), "permissions": sorted(self.permissions),
            "email": self.email, "name": self.name,
        }


@dataclass(frozen=True, slots=True)
class AuthTokens:
    access_token: str
    refresh_token: str
    expires_in: int
    identity: AuthIdentity
