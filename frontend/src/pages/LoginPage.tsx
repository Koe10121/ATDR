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

export function LoginPage() {
  const { isAuthenticated, isReady, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin123");
  const [mfuStatus, setMfuStatus] = useState<MfuIamPublicStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

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
    const params = new URLSearchParams(location.search);
    const containsLegacyCredential = LEGACY_HANDOFF_KEYS.some((key) => Boolean(params.get(key)) || location.hash.includes(key));
    const handoffError = params.get("handoff_error");
    if (containsLegacyCredential) {
      setError("A legacy browser-token handoff was blocked. Start from the approved MFU application shell.");
      navigate("/login?handoff_error=legacy_handoff_blocked", { replace: true });
      return;
    }
    if (handoffError) {
      setError(
        handoffError === "legacy_handoff_blocked"
          ? "A legacy browser-token handoff was blocked. Start from the approved MFU application shell."
          : handoffError === "handoff_not_configured"
          ? "School IAM handoff is not configured yet. Local ATDR login remains available."
          : "School IAM handoff could not be completed. Return to the MFU application shell and try again."
      );
    }
  }, [location.hash, location.search, navigate]);

  const from = safeRedirectPath((location.state as { from?: string } | null)?.from ?? null) ?? "/overview";
  const schoolLoginReady = Boolean(mfuStatus?.enabled && mfuStatus.handoff_ready);
  const schoolDomains = mfuStatus?.allowed_domains.length
    ? mfuStatus.allowed_domains
    : mfuStatus?.domain_hints ?? [];

  if (isAuthenticated) {
    return <Navigate to={from} replace />;
  }

  if (!isReady) {
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
            {schoolLoginReady && mfuStatus?.template_shell_launch_url ? (
              <a className="btn-secondary mt-4 block w-full text-center" href={mfuStatus.template_shell_launch_url}>
                Continue through MFU application shell
              </a>
            ) : schoolLoginReady ? (
              <div className="mt-4 text-xs font-semibold text-muted">Open ATDR from the registered MFU application shell after you sign in there.</div>
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
