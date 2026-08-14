import React from 'react';
export type AuthIdentity = {
    user_id: string;
    organization_id: string;
    roles: string[];
    permissions: string[];
    email?: string | null;
    name?: string | null;
};
export type AuthTokens = {
    access_token: string;
    refresh_token: string;
    expires_in: number;
    identity: AuthIdentity;
};
export type AuthClient = {
    login(email: string, password: string): Promise<AuthTokens>;
    refresh(token: string): Promise<AuthTokens>;
    logout(token: string): Promise<void>;
    me(token: string): Promise<AuthIdentity>;
    requestPasswordReset(email: string): Promise<void>;
    resetPassword(token: string, password: string): Promise<void>;
};
export declare function createAuthClient(baseUrl: string): AuthClient;
type AuthContextValue = {
    identity: AuthIdentity | null;
    accessToken: string | null;
    loading: boolean;
    error: string | null;
    login(email: string, password: string): Promise<void>;
    logout(): Promise<void>;
};
export declare function useAuth(): AuthContextValue;
export declare function AuthProvider({ client, children }: {
    client: AuthClient;
    children: React.ReactNode;
}): React.JSX.Element;
export declare function Login({ onSuccess }: {
    onSuccess?: () => void;
}): React.JSX.Element;
export declare function ForgotPassword({ client }: {
    client: AuthClient;
}): React.JSX.Element;
export declare function ResetPassword({ client, token }: {
    client: AuthClient;
    token: string;
}): React.JSX.Element;
export declare function UserMenu(): React.JSX.Element | null;
export declare function AuthGuard({ children, fallback }: {
    children: React.ReactNode;
    fallback?: React.ReactNode;
}): React.JSX.Element;
export declare function RoleGuard({ role, children, fallback }: {
    role: string;
    children: React.ReactNode;
    fallback?: React.ReactNode;
}): React.JSX.Element;
export declare function UsersAdmin({ users, onUpdate }: {
    users: Array<{
        id: string;
        email: string;
        name: string;
        roles: string[];
    }>;
    onUpdate?: (id: string, roles: string[]) => Promise<void>;
}): React.JSX.Element;
export {};
