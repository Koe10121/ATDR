import { Activity, BarChart3, Bot, Brain, ClipboardCheck, ClipboardList, Database, Gauge, LogOut, RadioTower, Settings2, ShieldAlert, SlidersHorizontal, Users } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
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
      { to: "/logs", label: "Investigation", icon: Database },
      { to: "/assistant", label: "SOC Assistant", icon: Bot }
    ]
  },
  {
    label: "AI Governance",
    items: [
      { to: "/ml", label: "AI Governance", icon: Brain },
      { to: "/tuning", label: "Detection Tuning", icon: BarChart3 },
      { to: "/evidence-review", label: "Evidence Review", icon: ClipboardCheck }
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
      { to: "/demo", label: "Validation Controls", icon: Settings2, adminOnly: true }
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
      { to: "/assistant", label: "SOC Assistant", icon: Bot },
      { to: "/ml", label: "AI Governance", icon: Brain },
      { to: "/evidence-review", label: "Evidence Review", icon: ClipboardCheck },
      { to: "/response", label: "Response & Audit", icon: RadioTower }
    ]
  },
  {
    label: "Admin",
    items: [
      { to: "/users", label: "Admin", icon: Users, adminOnly: true },
      { to: "/demo", label: "Validation Controls", icon: Settings2, adminOnly: true }
    ]
  }
];

const navGroups = presentationMode ? presentationNavGroups : fullNavGroups;
const navItems = navGroups.flatMap((group) => group.items);

export function AppShell() {
  const { logout, session, isAdmin } = useAuth();
  const location = useLocation();
  const mainRef = useRef<HTMLElement>(null);
  const routeMountedRef = useRef(false);
  const [routeAnnouncement, setRouteAnnouncement] = useState("");
  const health = useHealth();
  const me = useMe(Boolean(session));
  const responseMode = health.data?.checks.response_mode?.status ?? "unknown";
  const accountLabel = me.data?.email ?? me.data?.username ?? session?.username ?? "signed in";
  const emailBadge = me.data?.email
    ? me.data.email_verified
      ? "Email Verified"
      : "Email Unverified"
    : "No Email";

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      const heading = mainRef.current?.querySelector("h1")?.textContent?.trim() || "ATDR workspace";
      document.title = `${heading} | MFU ATDR`;
      setRouteAnnouncement(`${heading} page loaded`);
      if (routeMountedRef.current) mainRef.current?.focus({ preventScroll: true });
      routeMountedRef.current = true;
    });
    return () => window.cancelAnimationFrame(frame);
  }, [location.pathname]);

  return (
    <div className={clsx("min-h-screen bg-shell text-text", presentationMode && "presentation-mode")}>
      <a
        href="#main-content"
        onClick={(event) => {
          event.preventDefault();
          mainRef.current?.focus();
          mainRef.current?.scrollIntoView({ block: "start" });
        }}
        className="sr-only fixed left-4 top-4 z-50 rounded-md bg-white px-4 py-2 font-bold text-danger shadow-panel focus:not-sr-only"
      >
        Skip to main content
      </a>
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-72 border-r border-danger bg-[#681114] p-5 text-white shadow-panel lg:block">
        <div className="border-b border-white/15 pb-5">
          <div className="text-[11px] font-black uppercase tracking-[0.2em] text-[#f0bd67]">Mae Fah Luang University</div>
          <div className="mt-2 text-xl font-black text-white">MFU ATDR</div>
          <div className="mt-1 text-sm font-semibold text-white/70">Security operations console</div>
        </div>
        <nav className="mt-6 space-y-5" aria-label="Primary navigation">
          {navGroups.map((group) => {
            const visibleItems = group.items.filter((item) => !item.adminOnly || isAdmin);
            if (!visibleItems.length) return null;
            return (
              <div key={group.label}>
                <div className="mb-2 text-[11px] font-black uppercase tracking-[0.18em] text-white/70">{group.label}</div>
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
                            isActive
                              ? "border-[#d9a64e]/70 bg-white/15 text-white"
                              : "border-transparent text-white/75 hover:border-white/15 hover:bg-white/10 hover:text-white"
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

      <div className="lg:pl-72">
        <header className="sticky top-0 z-10 border-b border-line border-t-4 border-t-gold bg-white/95 px-5 py-3 shadow-sm backdrop-blur">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-xs font-extrabold uppercase tracking-wide text-danger">MFU Security Operations</div>
              <div className="text-lg font-black">AI-Driven Threat Detection and Response</div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Badge value={health.data?.status === "ok" ? "ready" : "review"} />
              <Badge value={responseMode === "simulation" ? "Simulation Mode" : "blocked"} />
              <Badge value="Decision Support Only" />
              <Badge value="Response Automation Disabled" />
              <span className="max-w-xs truncate rounded-full border border-line px-3 py-1 text-sm font-bold text-muted" title={accountLabel}>
                {me.data?.username ?? session?.username} ({me.data?.role ?? session?.role})
              </span>
              <Badge value={emailBadge} />
              <button type="button" className="btn-secondary flex items-center gap-2" onClick={logout}>
                <LogOut size={16} />
                Logout
              </button>
            </div>
          </div>
          <nav className="mt-4 flex gap-2 overflow-x-auto lg:hidden" aria-label="Mobile navigation">
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
            <div role="alert" className="mb-4 flex items-center gap-3 rounded-lg border border-danger/40 bg-danger/10 p-3 text-sm text-danger">
              <Activity size={18} />
              API health check failed. Confirm FastAPI is running.
            </div>
          ) : null}
          <main id="main-content" ref={mainRef} tabIndex={-1} className="focus:outline-none">
            <Outlet />
          </main>
        </div>
      </div>
      <div className="sr-only" aria-live="polite" aria-atomic="true">{routeAnnouncement}</div>
    </div>
  );
}
