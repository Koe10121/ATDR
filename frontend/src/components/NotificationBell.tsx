import { Bell } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import clsx from "clsx";
import { useMarkNotificationsSeen, useNotifications } from "../hooks/useApiQueries";
import type { NotificationItem } from "../types/api";

// What ATDR has told people: new Critical alerts, the daily summary, and problems of its own. The same words go
// out as a Windows notification, by email and to a chat group where those are set up; here they are kept.

const when = (value: string) =>
  new Date(value).toLocaleString("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });

const levels: Record<string, { dot: string; words: string }> = {
  critical: { dot: "bg-danger", words: "Critical" },
  warning: { dot: "bg-amber", words: "Needs attention" },
  info: { dot: "bg-cyan", words: "For information" }
};

function Entry({ item, fresh, onOpen }: { item: NotificationItem; fresh: boolean; onOpen: () => void }) {
  const level = levels[item.level] ?? levels.info;
  const content = (
    <>
      <div className="flex items-start gap-2">
        <span className={clsx("mt-1.5 h-2 w-2 shrink-0 rounded-full", level.dot)} aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <div className="text-sm font-bold text-text">
            <span className="sr-only">{level.words}: </span>
            {item.title}
            {fresh ? (
              <span className="ml-2 rounded bg-cyan/15 px-1.5 py-0.5 text-[10px] font-black uppercase tracking-wide text-cyan" data-testid="notification-new">
                New
              </span>
            ) : null}
          </div>
          {item.body ? <div className="mt-0.5 whitespace-pre-line break-words text-xs text-muted">{item.body}</div> : null}
          <div className="mt-1 text-[11px] text-muted">{when(item.created_at)}</div>
        </div>
      </div>
    </>
  );
  return (
    <li className={clsx("border-t border-line first:border-t-0", fresh && "bg-cyan/5")} data-testid="notification-item">
      {item.link ? (
        <Link to={item.link} onClick={onOpen} className="block px-4 py-3 hover:bg-panel2 focus:bg-panel2 focus:outline-none">
          {content}
        </Link>
      ) : (
        <div className="px-4 py-3">{content}</div>
      )}
    </li>
  );
}

export function NotificationBell() {
  const [open, setOpen] = useState(false);
  // What was unread when the bell was opened stays marked while it is open, although opening it reads them.
  const [fresh, setFresh] = useState<Set<number>>(new Set());
  const list = useNotifications();
  const seen = useMarkNotificationsSeen();
  const holder = useRef<HTMLDivElement>(null);
  const unread = list.data?.unread ?? 0;
  const items = list.data?.items ?? [];

  useEffect(() => {
    if (!open) return;
    const outside = (event: MouseEvent) => {
      if (holder.current && !holder.current.contains(event.target as Node)) setOpen(false);
    };
    const escape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", outside);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("mousedown", outside);
      document.removeEventListener("keydown", escape);
    };
  }, [open]);

  const toggle = () => {
    if (!open) {
      setFresh(new Set(items.filter((item) => item.unread).map((item) => item.id)));
      if (unread > 0 && list.data) seen.mutate(list.data.newest_id);
    }
    setOpen(!open);
  };

  return (
    <div className="relative" ref={holder}>
      <button
        type="button"
        className="btn-secondary relative flex items-center gap-2"
        aria-label={unread ? `Notifications, ${unread} unread` : "Notifications"}
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={toggle}
        data-testid="notification-bell"
      >
        <Bell size={16} />
        {unread ? (
          <span className="rounded-full bg-danger px-1.5 text-[11px] font-black leading-5 text-white" data-testid="notification-unread">
            {unread > 99 ? "99+" : unread}
          </span>
        ) : null}
      </button>
      {open ? (
        <div
          role="dialog"
          aria-label="Notifications"
          data-testid="notification-panel"
          className="absolute right-0 top-full z-30 mt-2 max-h-[70vh] w-[24rem] max-w-[calc(100vw-2.5rem)] overflow-auto rounded-lg border border-line bg-panel shadow-panel"
        >
          <div className="border-b border-line px-4 py-2 text-xs font-extrabold uppercase tracking-wide text-muted">Notifications</div>
          {list.error ? (
            <p className="px-4 py-4 text-sm text-amber">The notifications could not be loaded.</p>
          ) : items.length ? (
            <ul>
              {items.map((item) => (
                <Entry key={item.id} item={item} fresh={fresh.has(item.id)} onOpen={() => setOpen(false)} />
              ))}
            </ul>
          ) : (
            <p className="px-4 py-4 text-sm text-muted">Nothing to tell yet.</p>
          )}
        </div>
      ) : null}
    </div>
  );
}
