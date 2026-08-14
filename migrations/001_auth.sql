CREATE TABLE IF NOT EXISTS gm_auth_organizations (
  id VARCHAR(128) PRIMARY KEY, slug VARCHAR(128) NOT NULL UNIQUE,
  name VARCHAR(255) NOT NULL, created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS gm_auth_users (
  id VARCHAR(36) PRIMARY KEY, email VARCHAR(320) NOT NULL UNIQUE,
  name VARCHAR(255) NOT NULL, password_hash VARCHAR(255) NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS gm_auth_memberships (
  user_id VARCHAR(36) NOT NULL, organization_id VARCHAR(128) NOT NULL,
  roles JSONB NOT NULL DEFAULT '[]'::jsonb, permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (user_id, organization_id),
  FOREIGN KEY (user_id) REFERENCES gm_auth_users(id),
  FOREIGN KEY (organization_id) REFERENCES gm_auth_organizations(id)
);
CREATE TABLE IF NOT EXISTS gm_auth_refresh_sessions (
  id VARCHAR(36) PRIMARY KEY, user_id VARCHAR(36) NOT NULL, organization_id VARCHAR(128) NOT NULL,
  token_hash VARCHAR(128) NOT NULL UNIQUE, expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL,
  FOREIGN KEY (user_id) REFERENCES gm_auth_users(id)
);
CREATE TABLE IF NOT EXISTS gm_auth_password_resets (
  id VARCHAR(36) PRIMARY KEY, user_id VARCHAR(36) NOT NULL, token_hash VARCHAR(128) NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL,
  FOREIGN KEY (user_id) REFERENCES gm_auth_users(id)
);
CREATE TABLE IF NOT EXISTS gm_auth_audit_events (
  id VARCHAR(36) PRIMARY KEY, event VARCHAR(128) NOT NULL, user_id VARCHAR(36),
  organization_id VARCHAR(128), metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL
);
