import { Activity, BarChart3, Brain, ClipboardList, Database, Gauge, LogOut, RadioTower, Settings2, ShieldAlert, SlidersHorizontal, Users } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { NavLink, Outlet } from "react-router-dom";
import clsx from "clsx";
import { useAuth } from "../hooks/useAuth";
import { useHealth, useMe } from "../hooks/useApiQueries";
import { Badge } from "./Badge";
import { presentationMode } from "../lib/presentationMode";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  adminOnly?: boolean;
}

const fullNavGroups: Array<{ label: string; items: NavItem[] }> = [
  {
    label: "Operations",
    items: [
      { to: "/overview", label: "Overview", icon: Gauge },
      { to: "/alerts", label: "Alerts", icon: ShieldAlert },
      { to: "/logs", label: "Investigation", icon: Database }
    ]
  },
  {
    label: "AI Governance",
    items: [
      { to: "/ml", label: "AI Governance", icon: Brain },
      { to: "/tuning", label: "Detection Tuning", icon: BarChart3 }
    ]
  },
  {
    label: "Response & Audit",
    items: [
      { to: "/response", label: "Response & Audit", icon: RadioTower },
      { to: "/audit", label: "Audit Trail", icon: ClipboardList },
      { to: "/controls", label: "Threat Controls", icon: SlidersHorizontal }
    ]
  },
  {
    label: "Admin / Settings",
    items: [
      { to: "/users", label: "User Admin", icon: Users, adminOnly: true },
      { to: "/demo", label: "Demo Controls", icon: Settings2, adminOnly: true }
    ]
  }
];

const presentationNavGroups: Array<{ label: string; items: NavItem[] }> = [
  {
    label: "SOC Workflow",
    items: [
      { to: "/overview", label: "Overview", icon: Gauge },
      { to: "/alerts", label: "Alerts", icon: ShieldAlert },
      { to: "/logs", label: "Investigation", icon: Database },
      { to: "/ml", label: "AI Governance", icon: Brain },
      { to: "/response", label: "Response & Audit", icon: RadioTower }
    ]
  },
  {
    label: "Admin",
    items: [
      { to: "/users", label: "Admin", icon: Users, adminOnly: true },
      { to: "/demo", label: "Demo Controls", icon: Settings2, adminOnly: true }
    ]
  }
];

const navGroups = presentationMode ? presentationNavGroups : fullNavGroups;
const navItems = navGroups.flatMap((group) => group.items);

export function AppShell() {
  const { logout, session, isAdmin } = useAuth();
  const health = useHealth();
  const me = useMe(Boolean(session));
  const responseMode = health.data?.checks.response_mode?.status ?? "unknown";

  return (
    <div className={clsx("min-h-screen bg-shell text-text", presentationMode && "presentation-mode")}>
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-72 border-r border-line bg-white p-5 text-text shadow-panel lg:block">
        <div className="border-b border-line pb-5">
          <div className="text-[11px] font-black uppercase tracking-[0.2em] text-danger">Mae Fah Luang University</div>
          <div className="mt-2 text-xl font-black text-text">MFU ATDR</div>
          <div className="mt-1 text-sm font-semibold text-muted">AI-assisted SOC console</div>
        </div>
        <nav className="mt-6 space-y-5">
          {navGroups.map((group) => {
            const visibleItems = group.items.filter((item) => !item.adminOnly || isAdmin);
            if (!visibleItems.length) return null;
            return (
              <div key={group.label}>
                <div className="mb-2 text-[11px] font-black uppercase tracking-[0.18em] text-muted">{group.label}</div>
                <div className="space-y-1.5">
                  {visibleItems.map((item) => {
                    const Icon = item.icon;
                    return (
                      <NavLink
                        key={item.to}
                        to={item.to}
                        className={({ isActive }) =>
                          clsx(
                            "flex items-center gap-3 rounded-lg border px-3 py-2.5 text-sm font-bold transition",
                            isActive ? "border-danger/30 bg-danger/10 text-danger" : "border-transparent text-muted hover:border-line hover:bg-panel2 hover:text-text"
                          )
                        }
                      >
                        <Icon size={18} />
                        {item.label}
                      </NavLink>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </nav>
      </aside>

      <main className="lg:pl-72">
        <header className="sticky top-0 z-10 border-b border-line bg-white/90 px-5 py-4 shadow-sm backdrop-blur">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-sm font-extrabold uppercase tracking-wide text-danger">SOC Command Center</div>
              <div className="text-xl font-black">AI-Driven Log-Based Threat Detection and Response</div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Badge value={health.data?.status === "ok" ? "ready" : "review"} />
              <Badge value={responseMode === "simulation" ? "Simulation Mode" : "blocked"} />
              <Badge value="Decision Support Only" />
              <Badge value="Response Automation Disabled" />
              <span className="rounded-full border border-line px-3 py-1 text-sm font-bold text-muted">
                {me.data?.username ?? session?.username} ({me.data?.role ?? session?.role})
              </span>
              <button className="btn-secondary flex items-center gap-2" onClick={logout}>
                <LogOut size={16} />
                Logout
              </button>
            </div>
          </div>
          <nav className="mt-4 flex gap-2 overflow-x-auto lg:hidden">
            {navItems.filter((item) => !item.adminOnly || isAdmin).map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  clsx("whitespace-nowrap rounded-lg border px-3 py-2 text-xs font-bold", isActive ? "border-danger/40 bg-danger/10 text-danger" : "border-line bg-panel2 text-muted")
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
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
