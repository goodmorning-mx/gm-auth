import React, { createContext, useContext, useEffect, useMemo, useState } from 'react'

export type AuthIdentity = { user_id: string; organization_id: string; roles: string[]; permissions: string[]; email?: string | null; name?: string | null }
export type AuthTokens = { access_token: string; refresh_token: string; expires_in: number; identity: AuthIdentity }
export type AuthClient = { login(email: string, password: string): Promise<AuthTokens>; refresh(token: string): Promise<AuthTokens>; logout(token: string): Promise<void>; me(token: string): Promise<AuthIdentity>; requestPasswordReset(email: string): Promise<void>; resetPassword(token: string, password: string): Promise<void> }

export function createAuthClient(baseUrl: string): AuthClient {
  async function request(path: string, init: RequestInit = {}) {
    const response = await fetch(`${baseUrl}${path}`, { ...init, headers: { 'Content-Type': 'application/json', ...(init.headers || {}) } })
    if (!response.ok) throw new Error((await response.json().catch(() => null))?.detail || 'Authentication request failed.')
    return response.status === 204 ? null : response.json()
  }
  return {
    login: (email, password) => request('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
    refresh: (refresh_token) => request('/auth/refresh', { method: 'POST', body: JSON.stringify({ refresh_token }) }),
    logout: (refresh_token) => request('/auth/logout', { method: 'POST', body: JSON.stringify({ refresh_token }) }),
    me: (token) => request('/auth/me', { headers: { Authorization: `Bearer ${token}` } }),
    requestPasswordReset: async (email) => { await request('/auth/password-reset/request', { method: 'POST', body: JSON.stringify({ email }) }) },
    resetPassword: async (token, password) => { await request('/auth/password-reset/confirm', { method: 'POST', body: JSON.stringify({ token, password }) }) },
  }
}

type AuthContextValue = { identity: AuthIdentity | null; accessToken: string | null; loading: boolean; error: string | null; login(email: string, password: string): Promise<void>; logout(): Promise<void> }
const AuthContext = createContext<AuthContextValue | null>(null)
export function useAuth() { const value = useContext(AuthContext); if (!value) throw new Error('AuthProvider is required.'); return value }

export function AuthProvider({ client, children }: { client: AuthClient; children: React.ReactNode }) {
  const [tokens, setTokens] = useState<AuthTokens | null>(null); const [loading, setLoading] = useState(false); const [error, setError] = useState<string | null>(null)
  useEffect(() => { const saved = sessionStorage.getItem('gm-auth-tokens'); if (saved) setTokens(JSON.parse(saved)) }, [])
  useEffect(() => { if (tokens) sessionStorage.setItem('gm-auth-tokens', JSON.stringify(tokens)); else sessionStorage.removeItem('gm-auth-tokens') }, [tokens])
  const value = useMemo<AuthContextValue>(() => ({
    identity: tokens?.identity || null, accessToken: tokens?.access_token || null, loading, error,
    async login(email, password) { setLoading(true); setError(null); try { setTokens(await client.login(email, password)) } catch (e) { setError(e instanceof Error ? e.message : 'Unable to log in.'); throw e } finally { setLoading(false) } },
    async logout() { if (tokens) await client.logout(tokens.refresh_token); setTokens(null) },
  }), [client, error, loading, tokens])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function Login({ onSuccess }: { onSuccess?: () => void }) {
  const auth = useAuth(); const [email, setEmail] = useState(''); const [password, setPassword] = useState('')
  return <form onSubmit={async e => { e.preventDefault(); await auth.login(email, password); onSuccess?.() }} aria-label="Login">
    <label>Email<input type="email" value={email} onChange={e => setEmail(e.target.value)} required /></label>
    <label>Password<input type="password" value={password} onChange={e => setPassword(e.target.value)} required minLength={8} /></label>
    {auth.error && <p role="alert">{auth.error}</p>}<button type="submit" disabled={auth.loading}>{auth.loading ? 'Loading…' : 'Login'}</button>
  </form>
}

export function ForgotPassword({ client }: { client: AuthClient }) {
  const [email, setEmail] = useState(''); const [sent, setSent] = useState(false); const [error, setError] = useState<string | null>(null)
  return <form onSubmit={async e => { e.preventDefault(); try { await client.requestPasswordReset(email); setSent(true) } catch (x) { setError(x instanceof Error ? x.message : 'Request failed.') } }}>
    <label>Email<input type="email" value={email} onChange={e => setEmail(e.target.value)} required /></label>{error && <p role="alert">{error}</p>}{sent && <p>Check your email for reset instructions.</p>}<button type="submit">Send reset link</button>
  </form>
}

export function ResetPassword({ client, token }: { client: AuthClient; token: string }) {
  const [password, setPassword] = useState(''); const [done, setDone] = useState(false); const [error, setError] = useState<string | null>(null)
  return <form onSubmit={async e => { e.preventDefault(); try { await client.resetPassword(token, password); setDone(true) } catch (x) { setError(x instanceof Error ? x.message : 'Reset failed.') } }}>
    <label>New password<input type="password" minLength={8} value={password} onChange={e => setPassword(e.target.value)} required /></label>{error && <p role="alert">{error}</p>}{done && <p>Password updated.</p>}<button type="submit">Update password</button>
  </form>
}

export function UserMenu() { const auth = useAuth(); if (!auth.identity) return null; return <div role="menu"><span>{auth.identity.name || auth.identity.email}</span><button onClick={() => void auth.logout()}>Logout</button></div> }
export function AuthGuard({ children, fallback = <Login /> }: { children: React.ReactNode; fallback?: React.ReactNode }) { return useAuth().identity ? <>{children}</> : <>{fallback}</> }
export function RoleGuard({ role, children, fallback = null }: { role: string; children: React.ReactNode; fallback?: React.ReactNode }) { const identity = useAuth().identity; return identity?.roles.includes(role) ? <>{children}</> : <>{fallback}</> }
export function UsersAdmin({ users, onUpdate }: { users: Array<{ id: string; email: string; name: string; roles: string[] }>; onUpdate?: (id: string, roles: string[]) => Promise<void> }) { return <section aria-label="Users"><h2>Users</h2>{users.map(user => <div key={user.id}><span>{user.name} ({user.email})</span><span>{user.roles.join(', ')}</span>{onUpdate && <button onClick={() => void onUpdate(user.id, user.roles)}>Update</button>}</div>)}</section> }
