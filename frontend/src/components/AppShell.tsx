import { Activity, BarChart3, Brain, Gauge, LogOut, RadioTower, ShieldAlert } from "lucide-react";
import { NavLink, Outlet } from "react-router-dom";
import clsx from "clsx";
import { useAuth } from "../hooks/useAuth";
import { useHealth, useMe } from "../hooks/useApiQueries";
import { Badge } from "./Badge";

const navItems = [
  { to: "/overview", label: "Executive Overview", icon: Gauge },
  { to: "/alerts", label: "Alerts Triage", icon: ShieldAlert },
  { to: "/tuning", label: "Detection Tuning", icon: BarChart3 },
  { to: "/ml", label: "ML Governance", icon: Brain },
  { to: "/response", label: "Response Center", icon: RadioTower }
];

export function AppShell() {
  const { logout, session } = useAuth();
  const health = useHealth();
  const me = useMe(Boolean(session));
  const responseMode = health.data?.checks.response_mode?.status ?? "unknown";

  return (
    <div className="min-h-screen bg-shell text-text">
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-72 border-r border-line bg-[#0b1118] p-5 lg:block">
        <div className="border-b border-line pb-5">
          <div className="text-lg font-black">MFU ATDR</div>
          <div className="mt-1 text-sm text-muted">AI-driven threat detection console</div>
        </div>
        <nav className="mt-6 space-y-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  clsx(
                    "flex items-center gap-3 rounded-lg border px-3 py-2.5 text-sm font-bold transition",
                    isActive ? "border-cyan/50 bg-cyan/10 text-cyan" : "border-transparent text-muted hover:border-line hover:bg-panel"
                  )
                }
              >
                <Icon size={18} />
                {item.label}
              </NavLink>
            );
          })}
        </nav>
      </aside>

      <main className="lg:pl-72">
        <header className="sticky top-0 z-10 border-b border-line bg-shell/88 px-5 py-4 backdrop-blur">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">SOC Command Center</div>
              <div className="text-xl font-black">MFU AI-Driven Threat Detection and Response</div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Badge value={health.data?.status === "ok" ? "ready" : "review"} />
              <Badge value={responseMode === "simulation" ? "ready" : "blocked"} />
              <span className="rounded-full border border-line px-3 py-1 text-sm font-bold text-muted">
                {me.data?.username ?? session?.username} ({me.data?.role ?? session?.role})
              </span>
              <button className="btn-secondary flex items-center gap-2" onClick={logout}>
                <LogOut size={16} />
                Logout
              </button>
            </div>
          </div>
        </header>
        <div className="p-5">
          {health.isError ? (
            <div className="mb-4 flex items-center gap-3 rounded-lg border border-danger/40 bg-danger/10 p-3 text-sm text-danger">
              <Activity size={18} />
              API health check failed. Confirm FastAPI is running.
            </div>
          ) : null}
          <Outlet />
        </div>
      </main>
    </div>
  );
}
