import { useState } from "react";
import { useSendTestNotification, useSystemStatus } from "../hooks/useApiQueries";
import type {
  NotificationChannel,
  SystemBackups,
  SystemKeepRunning,
  SystemNotifications,
  SystemPart,
  SystemStatus,
  SystemUnattended,
  SystemVersion
} from "../types/api";
import { ErrorBanner } from "./ErrorBanner";

// How ATDR looks after itself on this machine: whether a stopped part is started again, when the database was last
// backed up and where its copies are, whom it tells about alerts and problems, which checked version runs, and which
// build of the dashboard this is.

const day = (value: string | null | undefined) =>
  value
    ? new Date(value).toLocaleString("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" })
    : "";

function size(bytes: number): string {
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
  return `${Math.max(1, Math.round(bytes / 1024 ** 2))} MB`;
}

function ago(hours: number): string {
  if (hours < 1) return "less than an hour ago";
  if (hours < 48) return `${Math.round(hours)} ${Math.round(hours) === 1 ? "hour" : "hours"} ago`;
  return `${Math.round(hours / 24)} days ago`;
}

export function keepRunningText(keep: SystemKeepRunning): { state: string; detail: string; warn: boolean } {
  if (keep.meant_to_be === "stopped") {
    return {
      state: "ATDR was stopped on purpose.",
      detail: keep.held_until ? `It stays stopped until ${day(keep.held_until)} unless someone starts it.` : "It starts again at the next sign-in, or when someone starts it.",
      warn: false
    };
  }
  if (!keep.watching) {
    return {
      state: "Nothing is watching ATDR's parts.",
      detail: "A part that stops stays stopped until someone starts ATDR again. Run scripts\\autostart.cmd once on this machine to switch the watcher on.",
      warn: true
    };
  }
  const stopping = keep.parts.filter((part) => part.keeps_stopping).map((part) => part.label);
  if (stopping.length) {
    return {
      state: `${stopping.join(" and ")} ${stopping.length === 1 ? "keeps" : "keep"} stopping.`,
      detail: "ATDR started it three times in ten minutes and now tries once every five. Its log in .atdr_runtime\\logs says why it stops.",
      warn: true
    };
  }
  const every = keep.interval_seconds ?? 30;
  const last = keep.last_action;
  // The table below counts restarts too: with one there, "not yet" would contradict it, whatever is on record as the last action.
  const restarted = keep.parts.some((part) => part.restarts_24h > 0);
  const acted = last
    ? ` Last time it had to act (${day(last.at)}): it ${last.what}${last.ok ? "." : ", which did not work."}`
    : restarted ? "" : " It has not had to act yet.";
  return {
    state: "ATDR restarts a part that stops.",
    detail: `It looks at its parts every ${every} seconds.${acted}`,
    warn: Boolean(last && !last.ok)
  };
}

export function unattendedText(unattended: SystemUnattended | null | undefined): { state: string; detail: string; warn: boolean } | null {
  // Nothing installed that starts ATDR: the line above already says that nothing is watching.
  if (!unattended) return null;
  const minutes = unattended.sleeps_after_minutes_on_mains;
  const sleeps = minutes !== null && minutes > 0;
  const time = `${minutes} ${minutes === 1 ? "minute" : "minutes"}`;
  if (!unattended.before_sign_in) {
    return {
      state: "ATDR starts when someone signs in to Windows, and stops when they sign out.",
      detail: `scripts\\autostart.cmd -BeforeSignIn on the machine makes it start with the machine instead; Windows asks for an administrator once.${
        sleeps ? ` On mains power the machine goes to sleep after ${time} without use, and ATDR pauses with it.` : ""
      }`,
      warn: false
    };
  }
  if (sleeps) {
    return {
      state: "ATDR starts with the machine, but the machine goes to sleep by itself.",
      detail: `On mains power it sleeps after ${time} without use, and ATDR pauses with it. scripts\\autostart.cmd -StayAwakeOnMains on the machine changes that.`,
      warn: true
    };
  }
  return {
    state: "ATDR starts with the machine, before anyone signs in, and keeps running when they sign out.",
    detail: minutes === 0 ? "On mains power the machine does not go to sleep by itself; closing the lid still puts it to sleep." : "",
    warn: false
  };
}

function partState(part: SystemPart): { text: string; warn: boolean } {
  if (part.keeps_stopping) return { text: "Keeps stopping", warn: true };
  if (!part.running) return { text: "Stopped", warn: true };
  if (part.answering === false) return { text: "Running, not answering", warn: true };
  return { text: "Running", warn: false };
}

export function backupText(backups: SystemBackups): { state: string; detail: string; warn: boolean } {
  if (!backups.scheduled) {
    return {
      state: "Scheduled backups are off.",
      detail: "The database is backed up only when someone does it by hand. Set ATDR_BACKUP_SCHEDULE_HOURS in .env to switch them on.",
      warn: true
    };
  }
  const every = backups.every_hours === 24 ? "every day" : `every ${backups.every_hours} hours`;
  const kept = `${backups.kept} kept (${size(backups.kept_bytes)}) in ${backups.folder}.`;
  if (!backups.worker_running) {
    return {
      state: "Backups are due, but the background worker is not running.",
      detail: `The worker takes the backup ${every}. ${backups.last ? `Last backup: ${day(backups.last.created_at)}.` : "No backup has been taken yet."}`,
      warn: true
    };
  }
  if (backups.last_failure) {
    return {
      state: "The last backup failed.",
      detail: `${day(backups.last_failure.at)}: ${backups.last_failure.words}. ATDR tries again every hour. ${backups.last ? `Last good backup: ${day(backups.last.created_at)}.` : "There is no backup yet."}`,
      warn: true
    };
  }
  if (!backups.last) {
    return { state: `The database is backed up ${every}.`, detail: "The first backup is taken within five minutes.", warn: false };
  }
  return {
    state: backups.overdue ? "The backup is late." : `The database is backed up ${every}.`,
    detail: `Last backup: ${day(backups.last.created_at)} (${size(backups.last.size_bytes)}), ${ago(backups.last.age_hours)}. ${kept}`,
    warn: backups.overdue
  };
}

export function offsiteText(backups: SystemBackups): { state: string; detail: string; warn: boolean } | null {
  const offsite = backups.offsite;
  if (!offsite.wanted) return null;
  const how = `Connect a drive that has a folder named ${offsite.folder_name} at its top; ATDR copies the newest backup to it within five minutes.`;
  const connected = offsite.connected.map((drive) => `${drive.label || "A drive"} (${drive.drive})`).join(" and ");
  if (offsite.last_failure) {
    return {
      state: `Copying to ${offsite.last_failure.drive} failed.`,
      detail: `${day(offsite.last_failure.at)}: ${offsite.last_failure.words}.`,
      warn: true
    };
  }
  if (!offsite.last_copy) {
    return {
      state: "No copy on another disk yet.",
      detail: connected ? `${connected} is connected; the copy follows the next backup check.` : `Every backup is on this laptop's own disk. ${how}`,
      warn: true
    };
  }
  const where = `${offsite.last_copy.label || "a drive"} (${offsite.last_copy.drive})`;
  const days = Math.floor(offsite.last_copy.age_days);
  return {
    state: offsite.stale ? `The copy on another disk is ${days} days old.` : "A copy is on another disk.",
    detail: `Last copied to ${where} on ${day(offsite.last_copy.copied_at)}.${offsite.stale ? ` ${how}` : ""}`,
    warn: offsite.stale
  };
}

export function notificationText(notifications: SystemNotifications): { state: string; detail: string; warn: boolean } {
  if (!notifications.enabled) {
    return {
      state: "Notifications are switched off.",
      detail: "Nobody is told about a new Critical alert or about a problem of ATDR's own. Set ATDR_NOTIFY_ENABLED=true in .env to switch them on.",
      warn: true
    };
  }
  if (!notifications.worker_running) {
    return {
      state: "Notifications are waiting: the background worker is not running.",
      detail: "The worker reports new alerts and sends every message.",
      warn: true
    };
  }
  const severities = notifications.alert_severities.includes("High") ? "High and Critical" : "Critical";
  const pace =
    notifications.minutes_between > 0
      ? `A burst is one message, and while alerts keep coming the next follows after ${notifications.minutes_between} minutes.`
      : "A burst is one message.";
  const summary = notifications.summary_setting_wrong
    ? "No daily summary is sent: ATDR_NOTIFY_SUMMARY_AT in .env is not a time such as 08:00."
    : notifications.summary_at
      ? `Everything else is in a summary each day at ${notifications.summary_at}.`
      : "No daily summary is sent.";
  return {
    state: `ATDR tells people about new ${severities} alerts at once, and about problems of its own.`,
    detail: `${pace} ${summary}`,
    warn: notifications.summary_setting_wrong
  };
}

export function channelText(channel: NotificationChannel): { state: string; last: string; warn: boolean } {
  if (!channel.on) return { state: `Off: ${channel.why_off}`, last: "-", warn: false };
  const where =
    channel.to !== undefined
      ? ` (${channel.to} ${channel.to === 1 ? "address" : "addresses"}, through ${channel.server})`
      : channel.service
        ? ` (${channel.service})`
        : "";
  const failure = channel.last_failure;
  if (failure) {
    const last = failure.delivered
      ? `Sent ${day(failure.at)}, but ${failure.words}.`
      : `Failed ${day(failure.at)}: ${failure.words}. ${failure.gave_up ? "ATDR is not trying this message again." : "ATDR tries again."}`;
    return { state: `On${where}`, last, warn: true };
  }
  return { state: `On${where}`, last: channel.last_sent_at ? `Sent ${day(channel.last_sent_at)}` : "Nothing sent yet", warn: false };
}

export function versionText(version: SystemVersion | null | undefined): { state: string; detail: string; warn: boolean } {
  if (!version) {
    return {
      state: "ATDR runs from the folder it is developed in.",
      detail: "A change to a file there goes live when a part restarts. scripts\\release.cmd setup makes a live copy that only takes checked versions.",
      warn: false
    };
  }
  const since = version.released_at ? `, live since ${day(version.released_at)}` : "";
  if (version.unfinished) {
    return {
      state: "A release did not finish.",
      detail: `The folder ATDR runs from may hold half of one version and half of another. In the folder ATDR is developed in, run scripts\\release.cmd recover: it puts version ${version.commit} back.`,
      warn: true
    };
  }
  if (!version.as_released) {
    return {
      state: `The files are not version ${version.commit} any more.`,
      detail: "Someone moved the folder ATDR runs from to another commit by hand, past the check a release makes. scripts\\release.cmd in the folder ATDR is developed in shows what differs.",
      warn: true
    };
  }
  // A commit's subject without its kind ("fix: ", "feat(ui): "), and without a full stop of its own.
  const change = version.subject.replace(/^[a-z]+(\([^)]*\))?:\s*/, "").replace(/\.$/, "");
  const said = [
    change ? `Its last change: ${change}.` : "",
    version.check ? `Checked before it went live: ${version.check}.` : "",
    version.previous ? `The version before it was ${version.previous}.` : ""
  ];
  return { state: `Version ${version.commit}${since}.`, detail: said.filter(Boolean).join(" "), warn: false };
}

function Channels({ notifications }: { notifications: SystemNotifications }) {
  const test = useSendTestNotification();
  const [said, setSaid] = useState<{ ok: boolean; words: string } | null>(null);
  const send = (channel: string) => {
    setSaid(null);
    test.mutate(channel, {
      onSuccess: (result) => setSaid({ ok: result.ok, words: result.words }),
      onError: () => setSaid({ ok: false, words: "The test message could not be asked for. Is the API running?" })
    });
  };
  const rows = (["windows", "email", "chat"] as const).map((key) => ({ key, channel: notifications.channels[key] }));
  return (
    <div className="mt-3 overflow-auto">
      <table className="w-full text-sm" data-testid="system-channels">
        <thead>
          <tr className="text-left text-xs uppercase tracking-wide text-muted">
            <th className="py-1 pr-3">Told through</th>
            <th className="py-1 pr-3">State</th>
            <th className="py-1 pr-3">Last message</th>
            <th className="py-1" />
          </tr>
        </thead>
        <tbody>
          <tr className="border-t border-line">
            <td className="py-1 pr-3 font-bold text-text">Bell in the dashboard</td>
            <td className="py-1 pr-3">On</td>
            <td className="py-1 pr-3">-</td>
            <td className="py-1" />
          </tr>
          {rows.map(({ key, channel }) => {
            const text = channelText(channel);
            return (
              <tr key={key} className="border-t border-line" data-testid={`system-channel-${key}`}>
                <td className="py-1 pr-3 font-bold text-text">{channel.name}</td>
                <td className="py-1 pr-3">{text.state}</td>
                <td className={`py-1 pr-3 ${text.warn ? "font-bold text-amber" : ""}`}>{text.last}</td>
                <td className="py-1 text-right">
                  <button
                    type="button"
                    className="btn-secondary px-2 py-1 text-xs"
                    disabled={!channel.on || !notifications.enabled || test.isPending}
                    onClick={() => send(key)}
                  >
                    Send a test
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <p className={`mt-2 text-sm ${said && !said.ok ? "font-bold text-amber" : "text-muted"}`} role="status" data-testid="system-channel-test">
        {test.isPending ? "Sending the test message..." : said ? said.words : ""}
      </p>
    </div>
  );
}

function Line({ testId, text }: { testId: string; text: { state: string; detail: string; warn: boolean } }) {
  return (
    <p className="mt-2 text-sm text-muted" data-testid={testId}>
      <span className={`font-bold ${text.warn ? "text-amber" : "text-text"}`}>{text.state}</span> {text.detail}
    </p>
  );
}

function buildText(status: SystemStatus): string {
  const build = status.dashboard_build;
  if (!build.built_at) return "";
  // A release builds the dashboard only when its source changed, so the build can be of an earlier version than
  // the one that runs. Said as it is, or it reads as a dashboard that is out of date.
  const released = status.version?.commit;
  if (build.commit && released && build.commit !== released && !build.stale && !build.uncommitted) {
    return `This dashboard was built ${day(build.built_at)}, at version ${build.commit}. Its source has not changed since.`;
  }
  const version = build.commit ? ` (version ${build.commit}${build.uncommitted ? ", with changes not yet committed" : ""})` : "";
  return `This dashboard was built ${day(build.built_at)}${version}.${
    build.stale ? " Its source has changed since; ATDR builds it again at its next start." : ""
  }`;
}

export function SystemPanel() {
  const status = useSystemStatus();
  const data = status.data;
  const offsite = data ? offsiteText(data.backups) : null;
  const unattended = data ? unattendedText(data.unattended) : null;
  return (
    <section className="panel" data-testid="system-panel" aria-labelledby="system-panel-title">
      <h2 id="system-panel-title" className="text-sm font-extrabold uppercase tracking-wide text-muted">System</h2>
      {status.error ? <ErrorBanner error={status.error} /> : null}
      {data ? (
        <>
          <Line testId="system-keep-running" text={keepRunningText(data.keeping_running)} />
          {data.keeping_running.parts.length ? (
            <div className="mt-3 overflow-auto">
              <table className="w-full text-sm" data-testid="system-parts">
                <thead>
                  <tr className="text-left text-xs uppercase tracking-wide text-muted">
                    <th className="py-1 pr-3">Part</th>
                    <th className="py-1 pr-3">State</th>
                    <th className="py-1 pr-3">Running since</th>
                    <th className="py-1">Restarted in 24 hours</th>
                  </tr>
                </thead>
                <tbody>
                  {data.keeping_running.parts.map((part) => {
                    const state = partState(part);
                    return (
                      <tr key={part.name} className="border-t border-line">
                        <td className="py-1 pr-3 font-bold text-text">{part.label}</td>
                        <td className={`py-1 pr-3 ${state.warn ? "font-bold text-amber" : ""}`}>{state.text}</td>
                        <td className="py-1 pr-3">{part.running ? day(part.started_at) : "-"}</td>
                        <td className="py-1">{part.restarts_24h ? `${part.restarts_24h} (last ${day(part.last_restart_at)})` : "0"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : null}
          {unattended ? <Line testId="system-unattended" text={unattended} /> : null}
          <Line testId="system-backups" text={backupText(data.backups)} />
          {offsite ? <Line testId="system-offsite" text={offsite} /> : null}
          <Line testId="system-notifications" text={notificationText(data.notifications)} />
          <Channels notifications={data.notifications} />
          <Line testId="system-version" text={versionText(data.version)} />
          {buildText(data) ? (
            <p className="mt-2 text-sm text-muted" data-testid="system-build">
              {buildText(data)}
            </p>
          ) : null}
        </>
      ) : status.error ? null : (
        <p className="mt-2 text-sm text-muted">Loading...</p>
      )}
    </section>
  );
}
