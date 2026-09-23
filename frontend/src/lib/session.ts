import type { Role, TokenResponse, User } from "../types/api";

const SESSION_KEY = "atdr.session.v1";

export interface Session {
  /** Both real login paths (template-shell handoff and local recovery) now
   * set the same HttpOnly API cookie as the actual credential -- this field
   * exists only as a UI cache of who is logged in, never a bearer token. */
  authMode: "cookie";
  username: string;
  role: Role;
  expiresAt: number;
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

/**
 * The recovery login endpoint now sets the same HttpOnly cookie the
 * template-shell handoff uses, so its token must never be persisted to
 * browser storage either -- that was the XSS-exfiltration vector. Build a
 * cookie-mode session from the login response's own fields (a more accurate
 * expiresAt than userToCookieSession's fixed 12h) without touching
 * access_token at all.
 */
export function loginResponseToCookieSession(token: TokenResponse): Session {
  return {
    authMode: "cookie",
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
    if (!parsed.username || !parsed.role || parsed.expiresAt <= Date.now()) {
      clearSession();
      return null;
    }
    return { ...parsed, authMode: "cookie" };
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
