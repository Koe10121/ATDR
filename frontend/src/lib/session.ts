import type { Role, TokenResponse, User } from "../types/api";

const SESSION_KEY = "atdr.session.v1";

export interface Session {
  /** A local login keeps its bearer token in browser storage. */
  token?: string;
  /** Template-shell handoff sessions use an HttpOnly API cookie instead. */
  authMode: "bearer" | "cookie";
  username: string;
  role: Role;
  expiresAt: number;
}

export function tokenToSession(token: TokenResponse): Session {
  return {
    token: token.access_token,
    authMode: "bearer",
    username: token.username,
    role: token.role,
    expiresAt: Date.now() + token.expires_in_minutes * 60_000
  };
}

export function userToCookieSession(user: User): Session {
  return {
    authMode: "cookie",
    username: user.username,
    role: user.role,
    // This is only a UI cache. The API remains the authority for the HttpOnly session.
    expiresAt: Date.now() + 12 * 60 * 60 * 1_000
  };
}

export function loadSession(): Session | null {
  const raw = localStorage.getItem(SESSION_KEY);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Session;
    const authMode = parsed.authMode ?? "bearer";
    if (
      !parsed.username ||
      !parsed.role ||
      parsed.expiresAt <= Date.now() ||
      (authMode === "bearer" && !parsed.token)
    ) {
      clearSession();
      return null;
    }
    return { ...parsed, authMode };
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
