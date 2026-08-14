# gm-auth

Reusable GoodMorning authentication for FastAPI and React products. The
module owns users, organizations, memberships, roles, permissions, sessions,
password reset tokens, and audit hooks while using the product's PostgreSQL
database.

Backend products install `gm-auth`, run the versioned migration, construct
`AuthService(engine, AuthSettings(...))`, and mount `create_auth_router`. The
identity contract is stable and includes `user_id`, `organization_id`,
`roles`, and `permissions`. `require_permissions` and `require_roles` are
FastAPI dependencies for product endpoints and MCP adapters.

The React package exports `AuthProvider`, `Login`, `ForgotPassword`,
`ResetPassword`, `UserMenu`, `AuthGuard`, `RoleGuard`, and `UsersAdmin`.
Products provide the API client/base URL and can wrap the components with
their own theme; no product UI implementation is required.

This release intentionally does not implement social OAuth, MFA, passkeys, or
SSO. Secret values are runtime configuration and are never part of this
package or the frontend bundle.
