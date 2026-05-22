import { createContext, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { api } from "../lib/api";
import { clearSession, loadSession, saveSession, tokenToSession } from "../lib/session";
import type { Session } from "../lib/session";

interface AuthContextValue {
  session: Session | null;
  isAuthenticated: boolean;
  isAdmin: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(() => loadSession());

  useEffect(() => {
    const expire = () => setSession(null);
    window.addEventListener("atdr:session-expired", expire);
    return () => window.removeEventListener("atdr:session-expired", expire);
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      session,
      isAuthenticated: Boolean(session),
      isAdmin: session?.role === "admin",
      login: async (username: string, password: string) => {
        const token = await api.login(username, password);
        const nextSession = tokenToSession(token);
        saveSession(nextSession);
        setSession(nextSession);
      },
      logout: () => {
        clearSession();
        setSession(null);
      }
    }),
    [session]
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
