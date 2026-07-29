import { FormEvent, useMemo, useState } from "react";
import { flexRender, getCoreRowModel, useReactTable } from "@tanstack/react-table";
import type { ColumnDef } from "@tanstack/react-table";
import { Link, useSearchParams } from "react-router-dom";
import { Badge } from "../components/Badge";
import { DetailDrawer } from "../components/DetailDrawer";
import { EmptyState } from "../components/EmptyState";
import { ErrorBanner } from "../components/ErrorBanner";
import { LoadingPanel } from "../components/LoadingPanel";
import { MetaGrid } from "../components/MetaGrid";
import { MetricCard } from "../components/MetricCard";
import { PaginationControls } from "../components/PaginationControls";
import { SafeSelect } from "../components/SafeSelect";
import { SocPageHeader } from "../components/SocPageHeader";
import { TableToolbar, tableDensityClass } from "../components/TableToolbar";
import type { SavedView, TableDensity } from "../components/TableToolbar";
import { useAuth } from "../hooks/useAuth";
import {
  useAlertNotes,
  useAlertReport,
  useAlertCases,
  useAlertStatusMutation,
  useAlertTimeline,
  useAlertWorkflowMutations,
  useAlert,
  useAlertsPage,
  useSources,
  useResponseMutations
} from "../hooks/useApiQueries";
import { api } from "../lib/api";
import { attackMappingForType, inferAttackTypeFromAlertType } from "../lib/attackMapping";
import { normalizeSavedViews, normalizeStringState } from "../lib/safeTableState";
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

const ALERT_FILTER_DEFAULTS = {
  search: "",
  severity: "",
  status: "open",
  src_ip: "",
  dst_ip: "",
  alert_type: "",
  source_id: "",
  source_status: "",
  sort_by: "score"
};
const ALERT_SORT_VALUES = ["score", "created", "updated", "severity"] as const;
const ALERT_SEVERITY_VALUES = ["", "Critical", "High", "Medium", "Low"] as const;
const ALERT_STATUS_VALUES = ["", "open", "investigating", "contained", "resolved", "false_positive", "needs_more_context"] as const;
type AlertFilters = typeof ALERT_FILTER_DEFAULTS;

function normalizeAlertFilters(value: unknown): AlertFilters {
  return normalizeStringState(ALERT_FILTER_DEFAULTS, value, {
    sort_by: ALERT_SORT_VALUES,
    severity: ALERT_SEVERITY_VALUES,
    status: ALERT_STATUS_VALUES
  });
}

export function AlertsTriage() {
  const { isAdmin, session } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const [filters, setFilters] = usePersistentState<AlertFilters>("atdr.alert.filters.v1", ALERT_FILTER_DEFAULTS);
  const safeFilters = useMemo(() => normalizeAlertFilters(filters), [filters]);
  const [limit, setLimit] = usePersistentState("atdr.alert.limit.v1", 50);
  const [density, setDensity] = usePersistentState<TableDensity>("atdr.alert.density.v1", "comfortable");
  const [rawSavedViews, setSavedViews] = usePersistentState<Array<SavedView<unknown>>>("atdr.alert.views.v1", []);
  const savedViews = useMemo(() => normalizeSavedViews(rawSavedViews, normalizeAlertFilters), [rawSavedViews]);
  const [offset, setOffset] = useState(0);
  const [note, setNote] = useState("");
  const [reportError, setReportError] = useState<string | null>(null);
  const selectedIdParam = Number(searchParams.get("alert"));
  const selectedId = Number.isFinite(selectedIdParam) && selectedIdParam > 0 ? selectedIdParam : null;
  const alerts = useAlertsPage({ ...safeFilters, limit, offset });
  const cases = useAlertCases({ active_only: true, limit: 5, source_id: safeFilters.source_id, source_status: safeFilters.source_status });
  const sources = useSources({ limit: 100 });
  const sourceOptions = useMemo(
    () => [
      { value: "", label: "Any source" },
      ...(sources.data ?? []).map((source) => ({ value: String(source.source_id), label: source.name }))
    ],
    [sources.data]
  );
  const alertRows = alerts.data?.items ?? [];
  const selectedDetail = useAlert(selectedId);
  const statusMutation = useAlertStatusMutation();
  const workflow = useAlertWorkflowMutations();
  const response = useResponseMutations();
  const selected = selectedDetail.data ?? alertRows.find((item) => item.id === selectedId) ?? null;
  const notes = useAlertNotes(selected?.id);
  const timeline = useAlertTimeline(selected?.id);
  const report = useAlertReport(selected?.id);
  const detectionSummary = selected?.detection_summary ?? report.data?.detection_summary;
  const attackMapping = detectionSummary?.attack_mapping ?? attackMappingForType(inferAttackTypeFromAlertType(selected?.alert_type));
  const anomalySummary = detectionSummary?.anomaly;
  const supervisedSummary = detectionSummary?.supervised;
  const hybridSummary = detectionSummary?.hybrid_risk;
  const alertAuthority = detectionSummary?.alert_authority;
  const groupMetadata = selected?.matched_rules_json?.find((rule) => rule.code === "group_metadata") ?? null;
  const occurrenceCount = Number(groupMetadata?.occurrence_count ?? groupMetadata?.evidence_count ?? selected?.evidence_count ?? 0);
  const relatedLogCount = Number(groupMetadata?.related_log_count ?? groupMetadata?.evidence_count ?? selected?.evidence_count ?? 0);
  const assistantPrompt = selected ? `Explain alert ${selected.id} and what an analyst should check next.` : "";
  const assistantHref = selected ? `/assistant?alert=${selected.id}&prompt=${encodeURIComponent(assistantPrompt)}` : "/assistant";
  const assistantLogHref = (logId: number) =>
    selected
      ? `/assistant?alert=${selected.id}&log=${logId}&prompt=${encodeURIComponent(`Summarize related log ${logId} for alert ${selected.id}.`)}`
      : `/assistant?log=${logId}&prompt=${encodeURIComponent(`Why was log ${logId} flagged or not flagged?`)}`;
  const assistantCaseHref = (caseId: string) =>
    `/assistant?case=${encodeURIComponent(caseId)}&prompt=${encodeURIComponent(`Summarize case ${caseId} and related alert group.`)}`;

  const columns = useMemo<ColumnDef<Alert>[]>(
    () => [
      { accessorKey: "id", header: "ID" },
      { accessorKey: "severity", header: "Severity", cell: ({ row }) => <Badge value={row.original.severity} kind="severity" /> },
      { accessorKey: "threat_score", header: "Risk Score" },
      {
        id: "attack_type",
        header: "Attack Type",
        cell: ({ row }) => {
          const attackType = row.original.detection_summary?.attack_type ?? inferAttackTypeFromAlertType(row.original.alert_type);
          return <Badge value={attackType} />;
        }
      },
      { accessorKey: "src_ip", header: "Source" },
      { accessorKey: "dst_ip", header: "Destination" },
      { id: "log_source", header: "Log Source", cell: ({ row }) => row.original.source_names?.join(", ") || "-" },
      { accessorKey: "evidence_count", header: "Evidence" },
      { accessorKey: "status", header: "Status", cell: ({ row }) => <Badge value={row.original.status} /> },
      { accessorKey: "title", header: "Alert" }
    ],
    []
  );
  const table = useReactTable({ data: alertRows, columns, getCoreRowModel: getCoreRowModel() });

  function updateFilter(key: keyof AlertFilters, value: string) {
    setOffset(0);
    setFilters((current) => normalizeAlertFilters({ ...normalizeAlertFilters(current), [key]: value }));
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
    setSavedViews((current) => [...normalizeSavedViews(current, normalizeAlertFilters).filter((view) => view.name !== name), { name, value: safeFilters }]);
  }

  function applyView(view: SavedView<AlertFilters>) {
    setOffset(0);
    setFilters(normalizeAlertFilters(view.value));
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
      <SocPageHeader
        eyebrow="Alerts"
        title="Prioritize, investigate, contain, and document alerts."
        description="Rule evidence stays primary. ML signals are assistive and response actions remain simulated."
      />

      <div className="grid gap-4 md:grid-cols-4">
        <MetricCard label="Filtered Alerts" value={alerts.data?.totalCount ?? "-"} detail="Matching alerts" tone="teal" />
        <MetricCard label="Selected Alert" value={selected?.id ?? "-"} detail={selected?.severity ?? "No alert selected"} tone="amber" />
        <MetricCard label="Session" value={session?.role ?? "-"} detail={session?.username ?? "No user"} tone="cyan" />
        <MetricCard label="Active Cases" value={cases.data?.length ?? "-"} detail="Computed related alert groups" tone="cyan" />
      </div>

      <section className="panel space-y-3">
        <input className="input" placeholder="Search title, source IP, destination IP, alert type, explanation" value={safeFilters.search} onChange={(event) => updateFilter("search", event.target.value)} />
        <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
          <SafeSelect
            value={safeFilters.severity}
            options={[
              { value: "", label: "All severities" },
              { value: "Critical", label: "Critical" },
              { value: "High", label: "High" },
              { value: "Medium", label: "Medium" },
              { value: "Low", label: "Low" }
            ]}
            onChange={(next) => updateFilter("severity", next)}
            ariaLabel="Alert severity filter"
          />
          <SafeSelect
            value={safeFilters.status}
            options={[
              { value: "", label: "All statuses" },
              { value: "open", label: "New" },
              { value: "investigating", label: "Investigating" },
              { value: "contained", label: "Contained" },
              { value: "resolved", label: "Resolved" },
              { value: "false_positive", label: "False Positive" },
              { value: "needs_more_context", label: "Needs More Context" }
            ]}
            onChange={(next) => updateFilter("status", next)}
            ariaLabel="Alert status filter"
          />
          <input className="input" placeholder="Source IP" value={safeFilters.src_ip} onChange={(event) => updateFilter("src_ip", event.target.value)} />
          <input className="input" placeholder="Destination IP" value={safeFilters.dst_ip} onChange={(event) => updateFilter("dst_ip", event.target.value)} />
          <input className="input" placeholder="Alert type" value={safeFilters.alert_type} onChange={(event) => updateFilter("alert_type", event.target.value)} />
          <SafeSelect
            value={safeFilters.source_id}
            options={sourceOptions}
            onChange={(next) => updateFilter("source_id", next)}
            ariaLabel="Alert source filter"
          />
          <SafeSelect
            value={safeFilters.source_status}
            options={[
              { value: "", label: "Any source status" },
              { value: "healthy", label: "Healthy sources" },
              { value: "idle", label: "Idle sources" },
              { value: "warning", label: "Warning sources" },
              { value: "error", label: "Error sources" },
              { value: "disabled", label: "Disabled sources" }
            ]}
            onChange={(next) => updateFilter("source_status", next)}
            ariaLabel="Alert source status filter"
          />
          <SafeSelect
            value={safeFilters.sort_by}
            options={[
              { value: "score", label: "Sort by score" },
              { value: "created", label: "Sort by created" },
              { value: "updated", label: "Sort by updated" },
              { value: "severity", label: "Sort by severity" }
            ]}
            onChange={(next) => updateFilter("sort_by", next)}
            ariaLabel="Alert sort"
          />
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
        onDeleteView={(name) => setSavedViews((current) => normalizeSavedViews(current, normalizeAlertFilters).filter((view) => view.name !== name))}
      />

      {cases.data?.length ? (
        <section className="panel">
          <details>
            <summary className="cursor-pointer text-sm font-extrabold uppercase tracking-wide text-muted">Active Case Grouping</summary>
            <div className="mt-3 grid gap-3 lg:grid-cols-2">
              {cases.data.map((item) => (
                <div key={item.case_id} className="rounded-lg border border-line bg-panel2 p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="font-bold text-text">{item.title}</div>
                    <Badge value={item.severity} kind="severity" />
                  </div>
                  <div className="mt-2 text-sm text-muted">
                    {item.related_alert_count} related alert(s) | {item.total_related_logs ?? 0} related log(s) | {item.attack_types.join(", ") || "unknown"} | owner {item.assigned_analyst ?? "unassigned"}
                  </div>
                  <div className="mt-2 text-xs text-muted">
                    Sources {item.source_ips.join(", ") || "-"} | Destinations {item.destination_ips.join(", ") || "-"}
                  </div>
                  <div className="mt-2 text-xs text-muted">
                    Ports {(item.top_destination_ports ?? []).map((port) => `${port.name} (${port.count})`).join(", ") || "-"} | Actions{" "}
                    {(item.top_actions ?? []).map((action) => `${action.name} (${action.count})`).join(", ") || "-"}
                  </div>
                  {item.recommended_analyst_focus ? <div className="mt-2 text-xs text-cyan">{item.recommended_analyst_focus}</div> : null}
                  <div className="mt-3">
                    <Link className="btn-secondary text-xs" to={assistantCaseHref(item.case_id)}>Ask Assistant about case</Link>
                  </div>
                </div>
              ))}
            </div>
          </details>
        </section>
      ) : null}

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
                { label: "Attack Mapping", value: `${attackMapping.tactic} / ${attackMapping.technique} (${attackMapping.technique_id})` },
                { label: "Detection Source", value: detectionSummary?.detection_source?.join(", ") ?? "rule" },
                { label: "Source", value: selected.src_ip },
                { label: "Destination", value: selected.dst_ip },
                { label: "Log Sources", value: selected.source_names?.join(", ") || "-" },
                { label: "Owner", value: selected.assigned_to },
                { label: "Evidence Logs", value: selected.evidence_log_ids.join(", ") || "-" },
                { label: "Alert Occurrences", value: occurrenceCount || "-" },
                { label: "Related Log Count", value: relatedLogCount || "-" },
                { label: "Deduplicated", value: groupMetadata?.deduplicated ? "yes" : "no" },
                { label: "Recommended Response", value: selected.recommended_response },
                { label: "SLA", value: `${selected.sla?.label ?? "-"} / ${selected.sla?.state ?? "-"}` }
              ]}
            />

            <section className="rounded-lg border border-cyan/25 bg-cyan/5 p-4">
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                <div>
                  <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">Why flagged?</div>
                  <p className="mt-1 text-sm text-muted">{detectionSummary?.why_flagged ?? selected.explanation}</p>
                </div>
                <Badge value={detectionSummary?.attack_type ?? inferAttackTypeFromAlertType(selected.alert_type)} />
              </div>
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
                <div className="rounded border border-line bg-panel2 p-3">
                  <div className="text-xs font-bold uppercase tracking-wide text-muted">Rule Authority</div>
                  <div className="mt-1 font-bold text-text">{alertAuthority?.authoritative_rule_count ?? detectionSummary?.matched_rule_names?.length ?? 0} matched</div>
                  <div className="text-sm text-muted">Created the alert</div>
                </div>
                <div className="rounded border border-line bg-panel2 p-3">
                  <div className="text-xs font-bold uppercase tracking-wide text-muted">ATT&CK-style Mapping</div>
                  <div className="mt-1 font-bold text-text">{attackMapping.tactic}</div>
                  <div className="text-sm text-muted">{attackMapping.technique} / {attackMapping.technique_id}</div>
                </div>
                <div className="rounded border border-line bg-panel2 p-3">
                  <div className="text-xs font-bold uppercase tracking-wide text-muted">Anomaly Advisory</div>
                  <div className="mt-1 font-bold text-text">{anomalySummary?.present === true ? "Present" : "Not present"}</div>
                  <div className="text-sm text-muted">Score {String(anomalySummary?.min_score ?? "-")} | No alert authority</div>
                </div>
                <div className="rounded border border-line bg-panel2 p-3">
                  <div className="text-xs font-bold uppercase tracking-wide text-muted">Supervised Shadow</div>
                  <div className="mt-1 font-bold text-text">{String(supervisedSummary?.predicted_label ?? "not trained")}</div>
                  <div className="text-sm text-muted">Threat-positive score {String(supervisedSummary?.malicious_probability ?? 0)}</div>
                  <div className="mt-1 text-xs text-muted">Review priority only; not automatic truth.</div>
                </div>
                <div className="rounded border border-line bg-panel2 p-3">
                  <div className="text-xs font-bold uppercase tracking-wide text-muted">Hybrid Interpretation</div>
                  <div className="mt-1 font-bold text-text">{String(hybridSummary?.hybrid_risk_score ?? hybridSummary?.risk_score ?? "-")}</div>
                  <div className="text-sm text-muted">Diagnostic only</div>
                </div>
              </div>
              <div className="mt-3 rounded border border-amber/30 bg-amber/10 px-3 py-2 text-xs text-amber">
                ML output is decision support. Verify rule evidence, anomaly context, and related logs before any simulated response.
              </div>
              <div className="mt-3 grid gap-2 md:grid-cols-2">
                {(detectionSummary?.top_evidence_points ?? []).slice(0, 6).map((point) => (
                  <div key={point} className="rounded border border-line bg-shell p-3 text-sm text-muted">{point}</div>
                ))}
              </div>
              <details className="mt-3">
                <summary className="cursor-pointer text-sm font-bold text-text">Behavior-window evidence</summary>
                <pre className="mt-3 max-h-64 overflow-auto rounded-lg border border-line bg-shell p-3 text-xs text-muted">
                  {JSON.stringify(detectionSummary?.behavior_window ?? {}, null, 2)}
                </pre>
              </details>
            </section>

            <section className="rounded-lg border border-line bg-panel2 p-4">
              <div className="mb-3 text-sm font-extrabold uppercase tracking-wide text-muted">Analyst Actions</div>
              <div className="flex flex-wrap gap-2">
                <Link className="btn-primary" to={assistantHref}>Ask Assistant</Link>
                <button className="btn-secondary" onClick={() => workflow.assignToMe.mutate(selected.id)}>Assign to me</button>
                <button className="btn-secondary" onClick={() => setAlertStatus("investigating")}>Investigating</button>
                <button className="btn-secondary" onClick={() => setAlertStatus("needs_more_context")}>Needs context</button>
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
                {selected.matched_rules_json.filter((rule) => rule.code !== "group_metadata").map((rule, index) => (
                  <div key={index} className="rounded border border-line bg-shell p-3 text-sm text-muted">
                    <div className="font-bold text-text">{String(rule.title ?? rule.code ?? `Rule ${index + 1}`)}</div>
                    <div className="mt-1">{String(rule.explanation ?? "No explanation provided.")}</div>
                  </div>
                ))}
              </div>
              {groupMetadata ? (
                <details className="mt-3">
                  <summary className="cursor-pointer text-sm font-bold text-text">Grouped alert metadata</summary>
                  <pre className="mt-3 max-h-56 overflow-auto rounded-lg border border-line bg-shell p-3 text-xs text-muted">
                    {JSON.stringify(groupMetadata, null, 2)}
                  </pre>
                </details>
              ) : null}
            </section>

            <section className="rounded-lg border border-line bg-panel2 p-4">
              <div className="mb-3 text-sm font-extrabold uppercase tracking-wide text-muted">Evidence And ML Context</div>
              <div className="flex flex-wrap gap-2 text-sm text-muted">
                Evidence logs:
                {selected.evidence_log_ids.length
                  ? selected.evidence_log_ids.map((id) => (
                      <span key={id} className="inline-flex flex-wrap items-center gap-2 rounded border border-cyan/30 bg-cyan/10 px-2 py-1">
                        <Link className="text-cyan underline" to={`/logs?log=${id}`}>
                          Log {id}
                        </Link>
                        <Link className="text-xs font-bold text-cyan underline" to={assistantLogHref(id)}>
                          Ask Assistant
                        </Link>
                      </span>
                    ))
                  : "-"}
              </div>
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
