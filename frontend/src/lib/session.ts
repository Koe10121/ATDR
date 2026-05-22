import type { Role, TokenResponse } from "../types/api";

const SESSION_KEY = "atdr.session.v1";

export interface Session {
  token: string;
  username: string;
  role: Role;
  expiresAt: number;
}

export function tokenToSession(token: TokenResponse): Session {
  return {
    token: token.access_token,
    username: token.username,
    role: token.role,
    expiresAt: Date.now() + token.expires_in_minutes * 60_000
  };
}

export function loadSession(): Session | null {
  const raw = localStorage.getItem(SESSION_KEY);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Session;
    if (!parsed.token || parsed.expiresAt <= Date.now()) {
      clearSession();
      return null;
    }
    return parsed;
  } catch {
    clearSession();
    return null;
  }
}

export function saveSession(session: Session): void {
  localStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

export function clearSession(): void {
  localStorage.removeItem(SESSION_KEY);
}
