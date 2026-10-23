import { useState } from "react";
import { Link } from "react-router-dom";
import { EmptyState } from "../components/EmptyState";
import { ErrorBanner } from "../components/ErrorBanner";
import { LoadingPanel } from "../components/LoadingPanel";
import { MetricCard } from "../components/MetricCard";
import { useAuth } from "../hooks/useAuth";
import { useInternetServiceReview, useInternetServices } from "../hooks/useApiQueries";
import type { InternetService, InternetServiceStatus } from "../types/api";

type Filter = "all" | "risky" | "unreviewed" | "expected" | "not_expected";

const FILTERS: Array<{ id: Filter; label: string }> = [
  { id: "all", label: "All" },
  { id: "risky", label: "Risky, not approved" },
  { id: "unreviewed", label: "Not reviewed" },
  { id: "expected", label: "Meant to be public" },
  { id: "not_expected", label: "Should not be public" }
];

const STATUS_WORDS: Record<InternetServiceStatus, string> = {
  unreviewed: "Not reviewed",
  expected: "Meant to be public",
  not_expected: "Should not be public"
};

function riskyOpen(service: InternetService): boolean {
  return service.risk !== null && service.status !== "expected";
}

function shown(services: InternetService[], filter: Filter): InternetService[] {
  if (filter === "all") return services;
  if (filter === "risky") return services.filter(riskyOpen);
  return services.filter((service) => service.status === filter);
}

function when(value: string | null): string {
  if (!value) return "-";
  const moment = new Date(value);
  return `${moment.getUTCDate()} ${moment.toLocaleString("en-GB", { month: "short", timeZone: "UTC" })}, ${moment
    .toISOString()
    .slice(11, 16)} UTC`;
}

function Review({ service, onDone }: { service: InternetService; onDone: () => void }) {
  const review = useInternetServiceReview();
  const [note, setNote] = useState(service.note ?? "");
  const mark = (status: InternetServiceStatus) =>
    review.mutate({ id: service.id, status, note: note.trim() || undefined }, { onSuccess: onDone });
  return (
    <div className="space-y-2" data-testid="exposure-review">
      <input
        className="input"
        placeholder="Why (optional): whose service it is, what it is for"
        value={note}
        onChange={(event) => setNote(event.target.value)}
        aria-label={`Note for ${service.address} port ${service.port}`}
      />
      <div className="flex flex-wrap gap-2">
        <button type="button" className="btn-secondary px-2 py-1 text-xs" disabled={review.isPending} onClick={() => mark("expected")}>
          Meant to be public
        </button>
        <button type="button" className="btn-secondary px-2 py-1 text-xs" disabled={review.isPending} onClick={() => mark("not_expected")}>
          Should not be public
        </button>
        {service.status !== "unreviewed" ? (
          <button type="button" className="btn-secondary px-2 py-1 text-xs" disabled={review.isPending} onClick={() => mark("unreviewed")}>
            Not reviewed
          </button>
        ) : null}
        <button type="button" className="btn-secondary px-2 py-1 text-xs" onClick={onDone}>
          Cancel
        </button>
      </div>
      {review.isError ? <ErrorBanner error={review.error} /> : null}
    </div>
  );
}

export function InternetExposure() {
  const { isAdmin } = useAuth();
  const services = useInternetServices();
  const [filter, setFilter] = useState<Filter>("all");
  const [reviewing, setReviewing] = useState<number | null>(null);
  const summary = services.data?.summary;
  const all = services.data?.services ?? [];
  const rows = shown(all, filter);

  return (
    <div className="space-y-5">
      <section className="hero-panel">
        <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">Internet Exposure</div>
        <h1 className="mt-2 text-3xl font-black">Which MFU services answer the internet, and which should not.</h1>
        <p className="mt-2 text-muted">
          ATDR lists every MFU address and port that answered a connection from the internet. Mark each one as meant to be public or not.
          A risky service nobody approved, one marked not public, and one that starts answering later each raise an alert; people using a
          service meant to be public are not taken for probes.
        </p>
      </section>

      <div className="grid gap-4 md:grid-cols-4">
        <MetricCard
          label="Services"
          value={summary?.services ?? "-"}
          detail={summary ? `On ${summary.addresses.toLocaleString("en-US")} MFU addresses` : "Answering the internet"}
          tone="cyan"
        />
        <MetricCard label="Risky, not approved" value={summary?.risky_not_approved ?? "-"} detail="Remote control, databases, file sharing, debugging" tone="danger" />
        <MetricCard label="Not reviewed" value={summary?.unreviewed ?? "-"} detail="Nobody has said whether they are meant to be public" tone="amber" />
        <MetricCard label="Should not be public" value={summary?.not_expected ?? "-"} detail="Reported whenever they answer" tone="danger" />
      </div>

      <div className="flex flex-wrap gap-2">
        {FILTERS.map((item) => (
          <button key={item.id} type="button" className={filter === item.id ? "btn-primary" : "btn-secondary"} onClick={() => setFilter(item.id)}>
            {item.label}
          </button>
        ))}
      </div>

      {services.isError ? <ErrorBanner error={services.error} /> : null}
      {services.isLoading ? <LoadingPanel label="Loading services" /> : null}
      {services.data && !all.length ? (
        <EmptyState title="No MFU service has answered the internet" body="Not in the logs ATDR has checked so far. Services are listed as detection checks new logs." />
      ) : null}

      {rows.length ? (
        <section className="panel overflow-auto">
          <table className="w-full text-sm" data-testid="exposure-services">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wide text-muted">
                <th className="py-1 pr-3">Address</th>
                <th className="py-1 pr-3">Port</th>
                <th className="py-1 pr-3">What it is</th>
                <th className="py-1 pr-3">Outside addresses</th>
                <th className="py-1 pr-3">Connections</th>
                <th className="py-1 pr-3">Last answered</th>
                <th className="py-1 pr-3">Status</th>
                <th className="py-1" />
              </tr>
            </thead>
            <tbody>
              {rows.map((service) => (
                <tr key={service.id} className="border-t border-line align-top" data-testid="exposure-service-row">
                  <td className="py-2 pr-3 font-bold text-text">{service.address}</td>
                  <td className="py-2 pr-3">
                    {service.port}/{service.protocol}
                  </td>
                  <td className="py-2 pr-3">
                    <div className={riskyOpen(service) ? `font-bold ${service.risk?.severity === "High" ? "text-danger" : "text-amber"}` : "text-text"}>
                      {service.what}
                      {riskyOpen(service) ? ` (${service.risk?.severity} risk)` : ""}
                    </div>
                    {riskyOpen(service) ? <div className="text-xs text-muted">{service.risk?.why}.</div> : null}
                    {service.apps.length ? (
                      <div className="text-xs text-muted">Firewall saw: {service.apps.map((item) => item.app).join(", ")}</div>
                    ) : null}
                  </td>
                  <td className="py-2 pr-3">{service.sources.toLocaleString("en-US")} or more</td>
                  <td className="py-2 pr-3">{service.connections.toLocaleString("en-US")}</td>
                  <td className="py-2 pr-3">{when(service.last_seen)}</td>
                  <td className="py-2 pr-3" data-testid="exposure-service-status">
                    <div className={service.status === "not_expected" ? "font-bold text-danger" : service.status === "expected" ? "text-text" : "text-muted"}>
                      {STATUS_WORDS[service.status]}
                    </div>
                    {service.note ? <div className="text-xs text-muted">{service.note}</div> : null}
                    {service.reviewed_by ? <div className="text-xs text-muted">by {service.reviewed_by}</div> : null}
                    {service.alert ? (
                      <Link className="text-xs font-bold text-cyan underline" to={`/alerts?alert=${service.alert.id}`}>
                        Alert #{service.alert.id} ({service.alert.severity})
                      </Link>
                    ) : null}
                  </td>
                  <td className="py-2 text-right">
                    {isAdmin && reviewing === service.id ? (
                      <Review service={service} onDone={() => setReviewing(null)} />
                    ) : isAdmin ? (
                      <button type="button" className="btn-secondary px-2 py-1 text-xs" onClick={() => setReviewing(service.id)}>
                        Review
                      </button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!isAdmin ? <p className="mt-3 text-xs text-muted">Admins mark services; analysts can read the list.</p> : null}
        </section>
      ) : services.data && all.length ? (
        <EmptyState title="None here" body="No service matches this filter." />
      ) : null}
    </div>
  );
}
