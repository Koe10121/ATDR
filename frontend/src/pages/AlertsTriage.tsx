import { FormEvent, useMemo, useState } from "react";
import { flexRender, getCoreRowModel, useReactTable } from "@tanstack/react-table";
import type { ColumnDef } from "@tanstack/react-table";
import { useSearchParams } from "react-router-dom";
import { Badge } from "../components/Badge";
import { DetailDrawer } from "../components/DetailDrawer";
import { EmptyState } from "../components/EmptyState";
import { ErrorBanner } from "../components/ErrorBanner";
import { LoadingPanel } from "../components/LoadingPanel";
import { MetaGrid } from "../components/MetaGrid";
import { MetricCard } from "../components/MetricCard";
import { PaginationControls } from "../components/PaginationControls";
import { TableToolbar, tableDensityClass } from "../components/TableToolbar";
import type { SavedView, TableDensity } from "../components/TableToolbar";
import { useAuth } from "../hooks/useAuth";
import {
  useAlertNotes,
  useAlertReport,
  useAlertStatusMutation,
  useAlertTimeline,
  useAlertWorkflowMutations,
  useAlert,
  useAlertsPage,
  useResponseMutations
} from "../hooks/useApiQueries";
import { api } from "../lib/api";
import { usePersistentState } from "../hooks/usePersistentState";
import type { Alert, AlertStatus } from "../types/api";

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export function AlertsTriage() {
  const { isAdmin, session } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const [filters, setFilters] = usePersistentState("atdr.alert.filters.v1", { search: "", severity: "", status: "open", src_ip: "", dst_ip: "", alert_type: "", sort_by: "score" });
  const [limit, setLimit] = usePersistentState("atdr.alert.limit.v1", 50);
  const [density, setDensity] = usePersistentState<TableDensity>("atdr.alert.density.v1", "comfortable");
  const [savedViews, setSavedViews] = usePersistentState<Array<SavedView<typeof filters>>>("atdr.alert.views.v1", []);
  const [offset, setOffset] = useState(0);
  const [note, setNote] = useState("");
  const [reportError, setReportError] = useState<string | null>(null);
  const selectedIdParam = Number(searchParams.get("alert"));
  const selectedId = Number.isFinite(selectedIdParam) && selectedIdParam > 0 ? selectedIdParam : null;
  const alerts = useAlertsPage({ ...filters, limit, offset });
  const alertRows = alerts.data?.items ?? [];
  const selectedDetail = useAlert(selectedId);
  const statusMutation = useAlertStatusMutation();
  const workflow = useAlertWorkflowMutations();
  const response = useResponseMutations();
  const selected = selectedDetail.data ?? alertRows.find((item) => item.id === selectedId) ?? null;
  const notes = useAlertNotes(selected?.id);
  const timeline = useAlertTimeline(selected?.id);
  const report = useAlertReport(selected?.id);

  const columns = useMemo<ColumnDef<Alert>[]>(
    () => [
      { accessorKey: "id", header: "ID" },
      { accessorKey: "severity", header: "Severity", cell: ({ row }) => <Badge value={row.original.severity} kind="severity" /> },
      { accessorKey: "status", header: "Status", cell: ({ row }) => <Badge value={row.original.status} /> },
      { accessorKey: "threat_score", header: "Score" },
      { accessorKey: "title", header: "Alert" },
      { accessorKey: "src_ip", header: "Source" },
      { accessorKey: "dst_ip", header: "Destination" },
      { accessorKey: "assigned_to", header: "Owner" },
      { accessorKey: "evidence_count", header: "Evidence" }
    ],
    []
  );
  const table = useReactTable({ data: alertRows, columns, getCoreRowModel: getCoreRowModel() });

  function updateFilter(key: keyof typeof filters, value: string) {
    setOffset(0);
    setFilters((current) => ({ ...current, [key]: value }));
  }

  function openAlert(id: number) {
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      next.set("alert", String(id));
      return next;
    });
  }

  function closeAlert() {
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      next.delete("alert");
      return next;
    });
  }

  function saveView(name: string) {
    setSavedViews((current) => [...current.filter((view) => view.name !== name), { name, value: filters }]);
  }

  function applyView(view: SavedView<typeof filters>) {
    setOffset(0);
    setFilters(view.value);
  }

  function setAlertStatus(nextStatus: AlertStatus) {
    if (!selected) return;
    if (nextStatus === "false_positive" && !window.confirm("Mark this alert as false positive?")) return;
    statusMutation.mutate({ id: selected.id, status: nextStatus });
  }

  function addNote(event: FormEvent) {
    event.preventDefault();
    if (selected && note.trim()) {
      workflow.addNote.mutate({ id: selected.id, note: note.trim() });
      setNote("");
    }
  }

  async function downloadReport(format: "csv" | "html" | "pdf") {
    if (!selected) return;
    setReportError(null);
    try {
      const file = await api.downloadAlertReport(selected.id, format);
      downloadBlob(file.blob, file.filename);
    } catch (error) {
      setReportError(error instanceof Error ? error.message : "Report download failed.");
    }
  }

  return (
    <div className="space-y-5">
      <section className="hero-panel">
        <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">Alert Workbench</div>
        <h1 className="mt-2 text-3xl font-black">Prioritize, investigate, contain, and document alerts.</h1>
        <p className="mt-2 text-muted">Rule evidence stays primary. ML signals are assistive and response actions remain simulated.</p>
      </section>

      <div className="grid gap-4 md:grid-cols-4">
        <MetricCard label="Filtered Alerts" value={alerts.data?.totalCount ?? "-"} detail="Matching alerts" tone="teal" />
        <MetricCard label="Selected Alert" value={selected?.id ?? "-"} detail={selected?.severity ?? "No alert selected"} tone="amber" />
        <MetricCard label="Session" value={session?.role ?? "-"} detail={session?.username ?? "No user"} tone="cyan" />
        <MetricCard label="Response" value={isAdmin ? "Admin" : "Read-only"} detail="Block/unblock requires admin" tone={isAdmin ? "danger" : "slate"} />
      </div>

      <section className="panel space-y-3">
        <input className="input" placeholder="Search title, source IP, destination IP, alert type, explanation" value={filters.search} onChange={(event) => updateFilter("search", event.target.value)} />
        <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
          <select className="input" value={filters.severity} onChange={(event) => updateFilter("severity", event.target.value)}>
            <option value="">All severities</option>
            <option>Critical</option>
            <option>High</option>
            <option>Medium</option>
            <option>Low</option>
          </select>
          <select className="input" value={filters.status} onChange={(event) => updateFilter("status", event.target.value)}>
            <option value="">All statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="contained">Contained</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
          </select>
          <input className="input" placeholder="Source IP" value={filters.src_ip} onChange={(event) => updateFilter("src_ip", event.target.value)} />
          <input className="input" placeholder="Destination IP" value={filters.dst_ip} onChange={(event) => updateFilter("dst_ip", event.target.value)} />
          <input className="input" placeholder="Alert type" value={filters.alert_type} onChange={(event) => updateFilter("alert_type", event.target.value)} />
          <select className="input" value={filters.sort_by} onChange={(event) => updateFilter("sort_by", event.target.value)}>
            <option value="score">Sort by score</option>
            <option value="created">Sort by created</option>
            <option value="updated">Sort by updated</option>
            <option value="severity">Sort by severity</option>
          </select>
        </div>
      </section>

      {alerts.isError ? <ErrorBanner error={alerts.error} /> : null}
      {alerts.isLoading ? <LoadingPanel label="Loading alerts" /> : null}

      <TableToolbar
        density={density}
        onDensityChange={setDensity}
        savedViews={savedViews}
        onSaveView={saveView}
        onApplyView={applyView}
        onDeleteView={(name) => setSavedViews((current) => current.filter((view) => view.name !== name))}
      />

      <section className="panel overflow-hidden">
        <div className="overflow-auto">
          <table className={tableDensityClass(density)}>
            <thead>
              {table.getHeaderGroups().map((headerGroup) => (
                <tr key={headerGroup.id}>
                  {headerGroup.headers.map((header) => (
                    <th key={header.id}>{flexRender(header.column.columnDef.header, header.getContext())}</th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody>
              {table.getRowModel().rows.map((row) => (
                <tr key={row.id} className="cursor-pointer" onClick={() => openAlert(row.original.id)}>
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!alerts.isLoading && !alertRows.length ? <EmptyState title="No alerts found" body="Adjust filters or run detection from Demo Controls." /> : null}
      </section>

      <PaginationControls limit={limit} offset={offset} resultCount={alertRows.length} totalCount={alerts.data?.totalCount} onLimitChange={setLimit} onOffsetChange={setOffset} />

      <DetailDrawer title={`Alert ${selected?.id ?? ""}`} open={Boolean(selectedId)} onClose={closeAlert}>
        {selected ? (
          <div className="space-y-5">
            <div className="flex flex-wrap gap-2">
              <Badge value={selected.severity} kind="severity" />
              <Badge value={selected.status} />
              <Badge value={selected.sla?.state ?? "review"} />
            </div>
            <div>
              <h2 className="text-2xl font-black">{selected.title}</h2>
              <p className="mt-2 text-sm text-muted">{selected.explanation}</p>
            </div>
            <MetaGrid
              rows={[
                { label: "Threat Score", value: selected.threat_score },
                { label: "Alert Type", value: selected.alert_type },
                { label: "Source", value: selected.src_ip },
                { label: "Destination", value: selected.dst_ip },
                { label: "Owner", value: selected.assigned_to },
                { label: "Evidence Logs", value: selected.evidence_log_ids.join(", ") || "-" },
                { label: "Recommended Response", value: selected.recommended_response },
                { label: "SLA", value: `${selected.sla?.label ?? "-"} / ${selected.sla?.state ?? "-"}` }
              ]}
            />

            <section className="rounded-lg border border-line bg-panel2 p-4">
              <div className="mb-3 text-sm font-extrabold uppercase tracking-wide text-muted">Analyst Actions</div>
              <div className="flex flex-wrap gap-2">
                <button className="btn-secondary" onClick={() => workflow.assignToMe.mutate(selected.id)}>Assign to me</button>
                <button className="btn-secondary" onClick={() => setAlertStatus("investigating")}>Investigating</button>
                <button className="btn-secondary" onClick={() => setAlertStatus("contained")}>Contained</button>
                <button className="btn-primary" onClick={() => setAlertStatus("resolved")}>Resolve</button>
                <button className="btn-secondary" onClick={() => setAlertStatus("false_positive")}>False positive</button>
                <button
                  className="btn-secondary"
                  disabled={!isAdmin || !selected.src_ip}
                  onClick={() =>
                    selected.src_ip &&
                    window.confirm(`Record simulated block for ${selected.src_ip}?`) &&
                    response.blockIp.mutate({ targetIp: selected.src_ip, reason: `Simulated containment for alert ${selected.id}.`, alertId: selected.id })
                  }
                >
                  Simulated block source
                </button>
                <button
                  className="btn-secondary"
                  disabled={!isAdmin || !selected.src_ip}
                  onClick={() =>
                    selected.src_ip &&
                    window.confirm(`Remove simulated block for ${selected.src_ip}?`) &&
                    response.unblockIp.mutate({ targetIp: selected.src_ip, reason: `Removed simulated containment from alert ${selected.id}.` })
                  }
                >
                  Simulated unblock
                </button>
              </div>
              {!isAdmin ? <div className="mt-3 text-xs text-muted">Block/unblock actions are admin-only and simulated.</div> : null}
            </section>

            <section className="rounded-lg border border-line bg-panel2 p-4">
              <div className="mb-3 text-sm font-extrabold uppercase tracking-wide text-muted">Matched Rules</div>
              <div className="space-y-2">
                {selected.matched_rules_json.map((rule, index) => (
                  <div key={index} className="rounded border border-line bg-shell p-3 text-sm text-muted">
                    <div className="font-bold text-text">{String(rule.title ?? rule.code ?? `Rule ${index + 1}`)}</div>
                    <div className="mt-1">{String(rule.explanation ?? "No explanation provided.")}</div>
                  </div>
                ))}
              </div>
            </section>

            <section className="rounded-lg border border-line bg-panel2 p-4">
              <div className="mb-3 text-sm font-extrabold uppercase tracking-wide text-muted">Evidence And ML Context</div>
              <div className="text-sm text-muted">Evidence log IDs: {selected.evidence_log_ids.join(", ") || "-"}</div>
              <div className="mt-2 text-sm text-muted">
                ML anomaly evidence: {(report.data?.evidence_logs ?? []).some((log) => log.is_anomaly) ? "Present in evidence logs" : "No anomaly flag in loaded report evidence"}
              </div>
              <details className="mt-3">
                <summary className="cursor-pointer text-sm font-bold text-text">Report evidence preview</summary>
                <pre className="mt-3 max-h-72 overflow-auto rounded-lg border border-line bg-shell p-3 text-xs text-muted">
                  {JSON.stringify(report.data?.evidence_logs ?? [], null, 2)}
                </pre>
              </details>
            </section>

            <section className="rounded-lg border border-line bg-panel2 p-4">
              <div className="mb-3 text-sm font-extrabold uppercase tracking-wide text-muted">Notes</div>
              <form className="flex gap-2" onSubmit={addNote}>
                <input className="input" placeholder="Add analyst note" value={note} onChange={(event) => setNote(event.target.value)} />
                <button className="btn-primary" disabled={workflow.addNote.isPending}>Add</button>
              </form>
              <div className="mt-3 space-y-2">
                {(notes.data ?? []).map((item) => (
                  <div key={item.id} className="rounded border border-line bg-shell p-3 text-sm text-muted">
                    <div className="font-bold text-text">{item.author} | {item.created_at}</div>
                    <div className="mt-1">{item.note}</div>
                  </div>
                ))}
              </div>
            </section>

            <section className="rounded-lg border border-line bg-panel2 p-4">
              <div className="mb-3 text-sm font-extrabold uppercase tracking-wide text-muted">Timeline</div>
              <div className="space-y-2">
                {(timeline.data ?? []).map((event, index) => (
                  <div key={`${event.event_time}-${index}`} className="rounded border border-line bg-shell p-3 text-sm text-muted">
                    <div className="font-bold text-text">{event.event_type} | {event.actor}</div>
                    <div>{event.event_time}</div>
                    <div className="mt-1">{event.summary}</div>
                  </div>
                ))}
              </div>
            </section>

            <section className="rounded-lg border border-line bg-panel2 p-4">
              <div className="mb-3 text-sm font-extrabold uppercase tracking-wide text-muted">Incident Report Export</div>
              <div className="flex flex-wrap gap-2">
                <button className="btn-secondary" onClick={() => downloadReport("csv")}>Download CSV</button>
                <button className="btn-secondary" onClick={() => downloadReport("html")}>Download HTML</button>
                <button className="btn-secondary" onClick={() => downloadReport("pdf")}>Download PDF</button>
              </div>
              {reportError ? <div className="mt-3 text-sm text-danger">{reportError}</div> : null}
            </section>
          </div>
        ) : null}
      </DetailDrawer>
    </div>
  );
}
