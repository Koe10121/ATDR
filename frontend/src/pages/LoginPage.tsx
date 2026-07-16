import { FormEvent, useEffect, useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { useAuth } from "../hooks/useAuth";
import { api } from "../lib/api";
import type { MfuIamPublicStatus } from "../types/api";

function safeRedirectPath(value: string | null): string | null {
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.includes(":")) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(value)) return null;
  return value;
}

const LEGACY_HANDOFF_KEYS = ["mfu_token", "iam_token", "handoff_token", "atdr_handoff_token", "x_access_token", "access_token", "token", "handoff_code", "atdr_handoff_code", "code"];

const HANDOFF_ERROR_MESSAGES: Record<string, string> = {
  legacy_handoff_blocked: "A legacy browser-token handoff was blocked. Start from the approved MFU application shell.",
  handoff_not_configured: "School sign in is not configured. Ask an administrator to run the authentication preflight.",
  handoff_origin_not_allowed: "The sign-in origin is not approved. Open the MFU shell at http://localhost:8080 and try again.",
  handoff_code_invalid: "The sign-in handoff was invalid. Return to the MFU shell and sign in again.",
  handoff_expired_or_used: "The one-time sign-in handoff expired or was already used. Sign in again from the MFU shell.",
  handoff_backend_unavailable: "The MFU sign-in service is temporarily unavailable. Check system health and try again.",
  handoff_invalid_response: "The MFU sign-in service returned an invalid identity response. Contact an administrator.",
  account_disabled: "This ATDR account is disabled. Contact an administrator.",
  identity_conflict: "This school identity conflicts with an existing ATDR account. An administrator must link it safely.",
  domain_not_allowed: "This email domain is not permitted for ATDR.",
  handoff_rejected: "School sign in could not be completed. Return to the MFU shell and try again."
};

export function LoginPage() {
  const { isAuthenticated, isReady, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [mfuStatus, setMfuStatus] = useState<MfuIamPublicStatus | null>(null);
  const [statusReady, setStatusReady] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let active = true;
    api
      .mfuIamPublicStatus()
      .then((status) => {
        if (active) {
          setMfuStatus(status);
          setStatusReady(true);
        }
      })
      .catch(() => {
        if (active) {
          setMfuStatus(null);
          setStatusReady(true);
        }
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const containsLegacyCredential = LEGACY_HANDOFF_KEYS.some((key) => Boolean(params.get(key)) || location.hash.includes(key));
    const handoffError = params.get("handoff_error");
    if (containsLegacyCredential) {
      setError("A legacy browser-token handoff was blocked. Start from the approved MFU application shell.");
      navigate("/login?handoff_error=legacy_handoff_blocked", { replace: true });
      return;
    }
    if (handoffError) {
      setError(HANDOFF_ERROR_MESSAGES[handoffError] ?? HANDOFF_ERROR_MESSAGES.handoff_rejected);
    }
  }, [location.hash, location.search, navigate]);

  const from = safeRedirectPath((location.state as { from?: string } | null)?.from ?? null) ?? "/overview";
  const schoolLoginReady = Boolean(mfuStatus?.enabled && mfuStatus.handoff_ready);
  const localRecovery = Boolean(mfuStatus?.local_login_enabled && mfuStatus.auth_mode === "local_recovery");
  const shellRequired = mfuStatus?.template_shell_required ?? true;
  const schoolDomains = mfuStatus?.allowed_domains.length
    ? mfuStatus.allowed_domains
    : mfuStatus?.domain_hints ?? [];

  if (isAuthenticated) {
    return <Navigate to={from} replace />;
  }

  if (!isReady || !statusReady) {
    return <div className="flex min-h-screen items-center justify-center bg-shell text-sm font-bold text-muted">Checking secure session...</div>;
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
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

        <section className="rounded-lg border border-line bg-panel p-8 shadow-panel">
          <div className="text-xl font-black">{localRecovery ? "Local recovery sign in" : "MFU secure sign in"}</div>
          <div className="mt-1 text-sm text-muted">
            {localRecovery
              ? "Recovery/development profile is explicitly enabled."
              : "Authentication is owned by the approved MFU application shell."}
          </div>
          {error ? <div className="mt-4 rounded-lg border border-danger/40 bg-danger/10 p-3 text-sm text-danger">{error}</div> : null}
          {!mfuStatus ? (
            <div className="mt-6 rounded-lg border border-danger/40 bg-danger/10 p-4 text-sm text-danger">
              Authentication status is unavailable. Check that the ATDR API is running.
            </div>
          ) : null}
          {shellRequired ? (
            <div className="mt-6 rounded-lg border border-line bg-panel2 p-4">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="text-sm font-black uppercase tracking-wide text-muted">School email authentication</div>
                  <div className="mt-1 text-sm text-muted">
                    {schoolLoginReady ? "Secure one-time handoff is ready." : "Secure handoff configuration is incomplete."}
                  </div>
                  {mfuStatus?.auth_require_2fa ? <div className="mt-1 text-xs text-muted">2FA/OTP is handled by the MFU shell.</div> : null}
                </div>
                <span className={`badge ${schoolLoginReady ? "badge-ok" : ""}`}>{schoolLoginReady ? "Ready" : "Unavailable"}</span>
              </div>
              {schoolDomains.length ? <div className="mt-3 text-xs font-bold text-muted">Allowed domain: {schoolDomains.join(", ")}</div> : null}
              {mfuStatus?.template_shell_launch_url ? (
                <a className="btn-primary mt-5 block w-full text-center" href={mfuStatus.template_shell_launch_url}>
                  Return to MFU Sign In
                </a>
              ) : (
                <div className="mt-4 text-xs font-semibold text-muted">Run the system preflight to configure the MFU shell launch URL.</div>
              )}
            </div>
          ) : null}
          {localRecovery ? (
            <form onSubmit={onSubmit} className="mt-6">
              <div className="rounded-lg border border-warning/40 bg-warning/10 p-3 text-sm font-semibold text-warning">
                Recovery mode is not the normal user entry path.
              </div>
              <label className="mt-5 block text-sm font-bold text-muted">
                Username or email
                <input className="input mt-2" value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" />
              </label>
              <label className="mt-4 block text-sm font-bold text-muted">
                Password
                <input className="input mt-2" type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" />
              </label>
              <button className="btn-primary mt-6 w-full" disabled={loading || !username || !password}>
                {loading ? "Signing in..." : "Sign in for recovery"}
              </button>
            </form>
          ) : null}
        </section>
      </div>
    </div>
  );
}
