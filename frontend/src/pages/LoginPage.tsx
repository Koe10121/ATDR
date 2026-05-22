import { FormEvent, useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { useAuth } from "../hooks/useAuth";

export function LoginPage() {
  const { isAuthenticated, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin123");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  if (isAuthenticated) {
    return <Navigate to="/overview" replace />;
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await login(username, password);
      const from = (location.state as { from?: string } | null)?.from ?? "/overview";
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
            Production migration dashboard for Palo Alto firewall monitoring, explainable detection, ML-assisted anomaly review,
            simulated response, and audit evidence.
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
            Username
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
          <p className="mt-4 text-xs text-muted">
            Demo credentials are for local presentation only. Replace secrets and passwords before lab-pilot deployment.
          </p>
        </form>
      </div>
    </div>
  );
}
