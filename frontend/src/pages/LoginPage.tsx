import { FormEvent, useEffect, useRef, useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { useAuth } from "../hooks/useAuth";
import { api } from "../lib/api";
import type { MfuIamPublicStatus } from "../types/api";

interface TemplateHandoff {
  token: string | null;
  tokenKind: "token" | "code" | null;
  source: string | null;
  target: string | null;
}

const HANDOFF_TOKEN_KEYS = ["mfu_token", "iam_token", "handoff_token", "atdr_handoff_token", "x_access_token", "access_token", "token"];
const HANDOFF_CODE_KEYS = ["handoff_code", "atdr_handoff_code", "code"];

function firstParam(params: URLSearchParams, keys: string[]): string | null {
  for (const key of keys) {
    const value = params.get(key);
    if (value?.trim()) {
      return value.trim();
    }
  }
  return null;
}

function parseHashParams(hash: string): URLSearchParams {
  const raw = hash.replace(/^#/, "");
  if (!raw) return new URLSearchParams();
  if (raw.startsWith("/")) {
    const queryStart = raw.indexOf("?");
    return queryStart >= 0 ? new URLSearchParams(raw.slice(queryStart + 1)) : new URLSearchParams();
  }
  return new URLSearchParams(raw);
}

function safeRedirectPath(value: string | null): string | null {
  if (!value || !value.startsWith("/") || value.startsWith("//")) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(value)) return null;
  return value;
}

function parseTemplateHandoff(search: string, hash: string): TemplateHandoff {
  const queryParams = new URLSearchParams(search);
  const hashParams = parseHashParams(hash);
  const token = firstParam(queryParams, HANDOFF_TOKEN_KEYS) ?? firstParam(hashParams, HANDOFF_TOKEN_KEYS);
  const code = firstParam(queryParams, HANDOFF_CODE_KEYS) ?? firstParam(hashParams, HANDOFF_CODE_KEYS);
  const target =
    safeRedirectPath(queryParams.get("next")) ??
    safeRedirectPath(queryParams.get("redirect")) ??
    safeRedirectPath(queryParams.get("return_to")) ??
    safeRedirectPath(queryParams.get("returnTo")) ??
    safeRedirectPath(hashParams.get("next")) ??
    safeRedirectPath(hashParams.get("redirect")) ??
    safeRedirectPath(hashParams.get("return_to")) ??
    safeRedirectPath(hashParams.get("returnTo"));
  const source = queryParams.get("source") ?? hashParams.get("source") ?? queryParams.get("provider") ?? hashParams.get("provider");
  if (token) return { token, tokenKind: "token", source, target };
  if (code) return { token: code, tokenKind: "code", source, target };
  return { token: null, tokenKind: null, source, target };
}

export function LoginPage() {
  const { isAuthenticated, login, loginWithMfuIamToken } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const handoffAttempted = useRef(false);
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin123");
  const [schoolToken, setSchoolToken] = useState("");
  const [mfuStatus, setMfuStatus] = useState<MfuIamPublicStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [handoffStatus, setHandoffStatus] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [schoolLoading, setSchoolLoading] = useState(false);
  const [pendingTemplateHandoff, setPendingTemplateHandoff] = useState<TemplateHandoff>(() =>
    parseTemplateHandoff(location.search, location.hash)
  );

  useEffect(() => {
    let active = true;
    api
      .mfuIamPublicStatus()
      .then((status) => {
        if (active) setMfuStatus(status);
      })
      .catch(() => {
        if (active) setMfuStatus(null);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    const parsed = parseTemplateHandoff(location.search, location.hash);
    if (parsed.token && !handoffAttempted.current) {
      setPendingTemplateHandoff(parsed);
    }
  }, [location.hash, location.search]);

  const from = (location.state as { from?: string } | null)?.from ?? pendingTemplateHandoff.target ?? "/overview";
  const schoolLoginReady = Boolean(mfuStatus?.enabled && mfuStatus.token_login_ready);
  const schoolDomains = mfuStatus?.allowed_domains.length
    ? mfuStatus.allowed_domains
    : mfuStatus?.domain_hints ?? [];

  useEffect(() => {
    if (!pendingTemplateHandoff.token || !mfuStatus || handoffAttempted.current) return;
    handoffAttempted.current = true;
    window.history.replaceState({}, document.title, window.location.pathname || "/login");
    if (!schoolLoginReady) {
      setError("Template handoff received, but school IAM is not configured. Local login remains available.");
      setHandoffStatus("Handoff blocked: school IAM is not ready.");
      return;
    }
    setError(null);
    setHandoffStatus(
      pendingTemplateHandoff.tokenKind === "code"
        ? "Template handoff code received. Validating with ATDR..."
        : "Template IAM handoff received. Validating with ATDR..."
    );
    setSchoolLoading(true);
    loginWithMfuIamToken(pendingTemplateHandoff.token)
      .then(() => {
        setHandoffStatus("Template handoff accepted. Opening ATDR...");
      })
      .catch((exc) => {
        setError(exc instanceof Error ? exc.message : "Template handoff failed. Local login remains available.");
        setHandoffStatus("Template handoff failed. Use local login or retry from the school shell.");
      })
      .finally(() => setSchoolLoading(false));
  }, [
    from,
    loginWithMfuIamToken,
    mfuStatus,
    navigate,
    pendingTemplateHandoff.token,
    pendingTemplateHandoff.tokenKind,
    schoolLoginReady
  ]);

  if (isAuthenticated) {
    return <Navigate to={from} replace />;
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setHandoffStatus(null);
    setLoading(true);
    try {
      await login(username, password);
      navigate(from, { replace: true });
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Login failed.");
    } finally {
      setLoading(false);
    }
  }

  async function onSchoolSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setHandoffStatus(null);
    setSchoolLoading(true);
    try {
      await loginWithMfuIamToken(schoolToken);
      navigate(from, { replace: true });
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "School email login failed.");
    } finally {
      setSchoolLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-shell p-6 text-text">
      <div className="grid w-full max-w-5xl gap-6 lg:grid-cols-[1.1fr_0.9fr]">
        <section className="rounded-lg border border-line bg-panel p-8 shadow-panel">
          <div className="mb-8 inline-flex rounded-full border border-cyan/30 bg-cyan/10 p-3 text-cyan">
            <ShieldCheck size={28} />
          </div>
          <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">MFU ATDR SOC Console</div>
          <h1 className="mt-3 text-4xl font-black leading-tight">AI-driven log-based threat detection and response.</h1>
          <p className="mt-4 max-w-xl text-muted">
            SOC lab console for firewall logs, explainable alerts, AI-assisted review, simulated response, and audit evidence.
          </p>
          <div className="mt-8 grid gap-3 sm:grid-cols-3">
            {["Rule-first", "ML assistive", "Response simulated"].map((item) => (
              <div key={item} className="rounded-lg border border-line bg-panel2 p-3 text-sm font-bold text-muted">
                {item}
              </div>
            ))}
          </div>
        </section>

        <form onSubmit={onSubmit} className="rounded-lg border border-line bg-panel p-8 shadow-panel">
          <div className="text-xl font-black">Sign in</div>
          <div className="mt-1 text-sm text-muted">Use your ATDR analyst or admin account.</div>
          <label className="mt-6 block text-sm font-bold text-muted">
            Username or email
            <input className="input mt-2" value={username} onChange={(event) => setUsername(event.target.value)} />
          </label>
          <label className="mt-4 block text-sm font-bold text-muted">
            Password
            <input className="input mt-2" type="password" value={password} onChange={(event) => setPassword(event.target.value)} />
          </label>
          {error ? <div className="mt-4 rounded-lg border border-danger/40 bg-danger/10 p-3 text-sm text-danger">{error}</div> : null}
          {handoffStatus ? (
            <div className="mt-4 rounded-lg border border-cyan/30 bg-cyan/10 p-3 text-sm font-bold text-cyan">{handoffStatus}</div>
          ) : null}
          <button className="btn-primary mt-6 w-full" disabled={loading}>
            {loading ? "Signing in..." : "Sign in"}
          </button>
          <div className="mt-6 rounded-lg border border-line bg-panel2 p-4">
            <div className="flex items-center justify-between gap-3">
              <div>
                <div className="text-sm font-black uppercase tracking-wide text-muted">School email login</div>
                <div className="mt-1 text-sm text-muted">
                  {schoolLoginReady
                    ? "Template-to-ATDR IAM handoff is configured."
                    : "Not configured. Local login remains available."}
                </div>
                {mfuStatus?.auth_require_2fa ? <div className="mt-1 text-xs text-muted">2FA/OTP is handled by the outer school shell.</div> : null}
              </div>
              <span className={`badge ${schoolLoginReady ? "badge-ok" : ""}`}>
                {schoolLoginReady ? "Ready" : "Disabled"}
              </span>
            </div>
            {schoolDomains.length ? (
              <div className="mt-3 text-xs font-bold text-muted">Allowed domain: {schoolDomains.join(", ")}</div>
            ) : null}
            {schoolLoginReady ? (
              <form onSubmit={onSchoolSubmit} className="mt-4">
                <label className="block text-sm font-bold text-muted">
                  External IAM token
                  <input
                    className="input mt-2"
                    value={schoolToken}
                    onChange={(event) => setSchoolToken(event.target.value)}
                    placeholder={mfuStatus?.mock_enabled ? "mock:user@lamduan.mfu.ac.th" : "Paste provider token if not launched from shell"}
                    autoComplete="off"
                  />
                </label>
                <button className="btn-secondary mt-3 w-full" disabled={schoolLoading || !schoolToken.trim()}>
                  {schoolLoading ? "Validating..." : "Continue with school IAM"}
                </button>
              </form>
            ) : null}
          </div>
          <p className="mt-4 text-xs text-muted">
            Demo credentials are for local presentation only. Replace secrets and passwords before lab-pilot deployment.
          </p>
        </form>
      </div>
    </div>
  );
}
