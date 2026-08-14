import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { createContext, useContext, useEffect, useMemo, useState } from 'react';
export function createAuthClient(baseUrl) {
    async function request(path, init = {}) {
        const response = await fetch(`${baseUrl}${path}`, { ...init, headers: { 'Content-Type': 'application/json', ...(init.headers || {}) } });
        if (!response.ok)
            throw new Error((await response.json().catch(() => null))?.detail || 'Authentication request failed.');
        return response.status === 204 ? null : response.json();
    }
    return {
        login: (email, password) => request('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
        refresh: (refresh_token) => request('/auth/refresh', { method: 'POST', body: JSON.stringify({ refresh_token }) }),
        logout: (refresh_token) => request('/auth/logout', { method: 'POST', body: JSON.stringify({ refresh_token }) }),
        me: (token) => request('/auth/me', { headers: { Authorization: `Bearer ${token}` } }),
        requestPasswordReset: async (email) => { await request('/auth/password-reset/request', { method: 'POST', body: JSON.stringify({ email }) }); },
        resetPassword: async (token, password) => { await request('/auth/password-reset/confirm', { method: 'POST', body: JSON.stringify({ token, password }) }); },
    };
}
const AuthContext = createContext(null);
export function useAuth() { const value = useContext(AuthContext); if (!value)
    throw new Error('AuthProvider is required.'); return value; }
export function AuthProvider({ client, children }) {
    const [tokens, setTokens] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    useEffect(() => { const saved = sessionStorage.getItem('gm-auth-tokens'); if (saved)
        setTokens(JSON.parse(saved)); }, []);
    useEffect(() => { if (tokens)
        sessionStorage.setItem('gm-auth-tokens', JSON.stringify(tokens));
    else
        sessionStorage.removeItem('gm-auth-tokens'); }, [tokens]);
    const value = useMemo(() => ({
        identity: tokens?.identity || null, accessToken: tokens?.access_token || null, loading, error,
        async login(email, password) { setLoading(true); setError(null); try {
            setTokens(await client.login(email, password));
        }
        catch (e) {
            setError(e instanceof Error ? e.message : 'Unable to log in.');
            throw e;
        }
        finally {
            setLoading(false);
        } },
        async logout() { if (tokens)
            await client.logout(tokens.refresh_token); setTokens(null); },
    }), [client, error, loading, tokens]);
    return _jsx(AuthContext.Provider, { value: value, children: children });
}
export function Login({ onSuccess }) {
    const auth = useAuth();
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    return _jsxs("form", { onSubmit: async (e) => { e.preventDefault(); await auth.login(email, password); onSuccess?.(); }, "aria-label": "Login", children: [_jsxs("label", { children: ["Email", _jsx("input", { type: "email", value: email, onChange: e => setEmail(e.target.value), required: true })] }), _jsxs("label", { children: ["Password", _jsx("input", { type: "password", value: password, onChange: e => setPassword(e.target.value), required: true, minLength: 8 })] }), auth.error && _jsx("p", { role: "alert", children: auth.error }), _jsx("button", { type: "submit", disabled: auth.loading, children: auth.loading ? 'Loading…' : 'Login' })] });
}
export function ForgotPassword({ client }) {
    const [email, setEmail] = useState('');
    const [sent, setSent] = useState(false);
    const [error, setError] = useState(null);
    return _jsxs("form", { onSubmit: async (e) => { e.preventDefault(); try {
            await client.requestPasswordReset(email);
            setSent(true);
        }
        catch (x) {
            setError(x instanceof Error ? x.message : 'Request failed.');
        } }, children: [_jsxs("label", { children: ["Email", _jsx("input", { type: "email", value: email, onChange: e => setEmail(e.target.value), required: true })] }), error && _jsx("p", { role: "alert", children: error }), sent && _jsx("p", { children: "Check your email for reset instructions." }), _jsx("button", { type: "submit", children: "Send reset link" })] });
}
export function ResetPassword({ client, token }) {
    const [password, setPassword] = useState('');
    const [done, setDone] = useState(false);
    const [error, setError] = useState(null);
    return _jsxs("form", { onSubmit: async (e) => { e.preventDefault(); try {
            await client.resetPassword(token, password);
            setDone(true);
        }
        catch (x) {
            setError(x instanceof Error ? x.message : 'Reset failed.');
        } }, children: [_jsxs("label", { children: ["New password", _jsx("input", { type: "password", minLength: 8, value: password, onChange: e => setPassword(e.target.value), required: true })] }), error && _jsx("p", { role: "alert", children: error }), done && _jsx("p", { children: "Password updated." }), _jsx("button", { type: "submit", children: "Update password" })] });
}
export function UserMenu() { const auth = useAuth(); if (!auth.identity)
    return null; return _jsxs("div", { role: "menu", children: [_jsx("span", { children: auth.identity.name || auth.identity.email }), _jsx("button", { onClick: () => void auth.logout(), children: "Logout" })] }); }
export function AuthGuard({ children, fallback = _jsx(Login, {}) }) { return useAuth().identity ? _jsx(_Fragment, { children: children }) : _jsx(_Fragment, { children: fallback }); }
export function RoleGuard({ role, children, fallback = null }) { const identity = useAuth().identity; return identity?.roles.includes(role) ? _jsx(_Fragment, { children: children }) : _jsx(_Fragment, { children: fallback }); }
export function UsersAdmin({ users, onUpdate }) { return _jsxs("section", { "aria-label": "Users", children: [_jsx("h2", { children: "Users" }), users.map(user => _jsxs("div", { children: [_jsxs("span", { children: [user.name, " (", user.email, ")"] }), _jsx("span", { children: user.roles.join(', ') }), onUpdate && _jsx("button", { onClick: () => void onUpdate(user.id, user.roles), children: "Update" })] }, user.id))] }); }
