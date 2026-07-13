import { createContext, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { api } from "../lib/api";
import { clearSession, loadSession, saveSession, tokenToSession, userToCookieSession } from "../lib/session";
import type { Session } from "../lib/session";

interface AuthContextValue {
  session: Session | null;
  isAuthenticated: boolean;
  isAdmin: boolean;
  isReady: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);
const SESSION_PROBE_TIMEOUT_MS = 3_000;

function probeSession<T>(request: Promise<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const timeout = window.setTimeout(
      () => reject(new Error("Session probe timed out.")),
      SESSION_PROBE_TIMEOUT_MS
    );
    request.then(
      (value) => {
        window.clearTimeout(timeout);
        resolve(value);
      },
      (error: unknown) => {
        window.clearTimeout(timeout);
        reject(error);
      }
    );
  });
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(() => loadSession());
  const [isReady, setIsReady] = useState(false);

  useEffect(() => {
    const expire = () => setSession(null);
    window.addEventListener("atdr:session-expired", expire);
    return () => window.removeEventListener("atdr:session-expired", expire);
  }, []);

  useEffect(() => {
    let active = true;
    probeSession(api.me())
      .then((user) => {
        if (!active) return;
        const nextSession = userToCookieSession(user);
        saveSession(nextSession);
        setSession(nextSession);
      })
      .catch(() => {
        if (!active) return;
        clearSession();
        setSession(null);
      })
      .finally(() => {
        if (active) setIsReady(true);
      });
    return () => {
      active = false;
    };
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      session,
      isAuthenticated: Boolean(session),
      isAdmin: session?.role === "admin",
      isReady,
      login: async (username: string, password: string) => {
        const token = await api.login(username, password);
        const nextSession = tokenToSession(token);
        saveSession(nextSession);
        setSession(nextSession);
      },
      logout: () => {
        void api.logout().catch(() => undefined);
        clearSession();
        setSession(null);
      }
    }),
    [isReady, session]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return value;
}
