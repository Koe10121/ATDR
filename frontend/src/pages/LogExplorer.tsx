import { useEffect, useMemo, useState } from "react";
import { flexRender, getCoreRowModel, useReactTable } from "@tanstack/react-table";
import type { ColumnDef } from "@tanstack/react-table";
import { Link, useSearchParams } from "react-router-dom";
import { Badge } from "../components/Badge";
import { DetailDrawer } from "../components/DetailDrawer";
import { EmptyState } from "../components/EmptyState";
import { ErrorBanner } from "../components/ErrorBanner";
import { LoadingPanel } from "../components/LoadingPanel";
import { MetaGrid } from "../components/MetaGrid";
import { PaginationControls } from "../components/PaginationControls";
import { SafeSelect } from "../components/SafeSelect";
import { SocPageHeader } from "../components/SocPageHeader";
import { TableToolbar, tableDensityClass } from "../components/TableToolbar";
import type { SavedView, TableDensity } from "../components/TableToolbar";
import { useLog, useLogsPage, useMlLabelMutations, useMlLabels, useSources } from "../hooks/useApiQueries";
import { useDebouncedValue } from "../hooks/useDebouncedValue";
import { usePersistentState } from "../hooks/usePersistentState";
import { normalizeSavedViews, normalizeStringState } from "../lib/safeTableState";
import type { MLAttackType, MLLabelValue, NormalizedLog } from "../types/api";

const LABEL_OPTIONS: MLLabelValue[] = ["benign", "benign_unusual", "suspicious", "malicious", "needs_context"];
const ATTACK_TYPE_OPTIONS: MLAttackType[] = [
  "normal",
  "port_scan",
  "brute_force",
  "dos_ddos",
  "malware_c2",
  "policy_violation",
  "data_exfiltration_suspicion",
  "unknown_anomaly"
];
const LOG_FILTER_DEFAULTS = {
  src_ip: "",
  dst_ip: "",
  app: "",
  action: "",
  app_risk: "",
  protocol: "",
  src_zone: "",
  dst_zone: "",
  country: "",
  generated_from: "",
  generated_to: "",
  source_id: "",
  source_status: "",
  sort_by: "generated"
};
const LOG_SORT_VALUES = ["generated", "app_risk", "action", "src_ip", "dst_ip"] as const;
type LogFilters = typeof LOG_FILTER_DEFAULTS;
type LogSavedView = { search: string; filters: LogFilters };

function normalizeLogFilters(value: unknown): LogFilters {
  return normalizeStringState(LOG_FILTER_DEFAULTS, value, { sort_by: LOG_SORT_VALUES });
}

function normalizeLogSavedView(value: unknown): LogSavedView {
  const raw = typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
  const filters = "filters" in raw ? raw.filters : raw;
  return {
    search: typeof raw.search === "string" ? raw.search : "",
    filters: normalizeLogFilters(filters)
  };
}

export function LogExplorer() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [search, setSearch] = usePersistentState("atdr.log.search.v1", "");
  const [filters, setFilters] = usePersistentState<LogFilters>("atdr.log.filters.v1", LOG_FILTER_DEFAULTS);
  const safeFilters = useMemo(() => normalizeLogFilters(filters), [filters]);
  const [limit, setLimit] = usePersistentState("atdr.log.limit.v1", 50);
  const [density, setDensity] = usePersistentState<TableDensity>("atdr.log.density.v1", "comfortable");
  const [rawSavedViews, setSavedViews] = usePersistentState<Array<SavedView<unknown>>>("atdr.log.views.v1", []);
  const savedViews = useMemo(() => normalizeSavedViews(rawSavedViews, normalizeLogSavedView), [rawSavedViews]);
  const [offset, setOffset] = useState(0);
  const selectedIdParam = Number(searchParams.get("log"));
  const selectedId = Number.isFinite(selectedIdParam) && selectedIdParam > 0 ? selectedIdParam : null;
  const debouncedSearch = useDebouncedValue(search);
  const logs = useLogsPage({ search: debouncedSearch, ...safeFilters, limit, offset });
  const sources = useSources({ limit: 100 });
  const sourceOptions = useMemo(
    () => [
      { value: "", label: "Any source" },
      ...(sources.data ?? []).map((source) => ({ value: String(source.source_id), label: source.name }))
    ],
    [sources.data]
  );
  const logRows = logs.data?.items ?? [];
  const selectedDetail = useLog(selectedId);
  const selected = selectedDetail.data ?? logRows.find((item) => item.id === selectedId) ?? null;
  const assistantHref = selected
    ? `/assistant?log=${selected.id}&prompt=${encodeURIComponent(`Why was log ${selected.id} flagged or not flagged?`)}`
    : "/assistant";
  const selectedLabels = useMlLabels({ log_id: selectedId ?? undefined, limit: 1 }, Boolean(selectedId));
  const currentLabel = selectedLabels.data?.[0] ?? null;
  const labelMutations = useMlLabelMutations();
  const [labelForm, setLabelForm] = useState<{
    label: MLLabelValue;
    attack_type: MLAttackType;
    confidence: number;
    review_note: string;
  }>({ label: "suspicious", attack_type: "unknown_anomaly", confidence: 3, review_note: "" });

  useEffect(() => {
    if (currentLabel) {
      setLabelForm({
        label: currentLabel.label as MLLabelValue,
        attack_type: currentLabel.attack_type as MLAttackType,
        confidence: currentLabel.confidence,
        review_note: currentLabel.review_note ?? ""
      });
    } else {
      setLabelForm({ label: "suspicious", attack_type: "unknown_anomaly", confidence: 3, review_note: "" });
    }
  }, [currentLabel, selectedId]);

  const columns = useMemo<ColumnDef<NormalizedLog>[]>(
    () => [
      { accessorKey: "id", header: "ID" },
      { accessorKey: "source_name", header: "Source" },
      { accessorKey: "generated_time", header: "Generated" },
      { accessorKey: "src_ip", header: "Source" },
      { accessorKey: "dst_ip", header: "Destination" },
      { accessorKey: "app", header: "App" },
      { accessorKey: "action", header: "Action", cell: ({ row }) => <Badge value={row.original.action ?? "unknown"} /> },
      { accessorKey: "protocol", header: "Protocol" },
      { accessorKey: "app_risk", header: "Risk" },
      { accessorKey: "is_anomaly", header: "ML", cell: ({ row }) => (row.original.is_anomaly ? <Badge value="review" /> : "-") }
    ],
    []
  );
  const table = useReactTable({ data: logRows, columns, getCoreRowModel: getCoreRowModel() });

  function updateFilter(key: keyof LogFilters, value: string) {
    setOffset(0);
    setFilters((current) => normalizeLogFilters({ ...normalizeLogFilters(current), [key]: value }));
  }

  function openLog(id: number) {
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      next.set("log", String(id));
      return next;
    });
  }

  function closeLog() {
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      next.delete("log");
      return next;
    });
  }

  function saveView(name: string) {
    setSavedViews((current) => [
      ...normalizeSavedViews(current, normalizeLogSavedView).filter((view) => view.name !== name),
      { name, value: { search, filters: safeFilters } }
    ]);
  }

  function applyView(view: SavedView<LogSavedView>) {
    const safeView = normalizeLogSavedView(view.value);
    setOffset(0);
    setSearch(safeView.search);
    setFilters(safeView.filters);
  }

  function saveLabel() {
    if (!selected) {
      return;
    }
    const payload = { ...labelForm, log_id: selected.id, review_note: labelForm.review_note || null };
    if (currentLabel) {
      labelMutations.update.mutate({ id: currentLabel.id, payload });
    } else {
      labelMutations.create.mutate(payload);
    }
  }

  return (
    <div className="space-y-5">
      <SocPageHeader
        eyebrow="Investigation"
        title="Search raw evidence and normalized firewall events."
        description="Every row remains tied to its original Palo Alto syslog line for investigation evidence."
      />

      <section className="panel space-y-3">
        <input className="input" placeholder="Search IP, app, rule, action, protocol, or zone" value={search} onChange={(event) => setSearch(event.target.value)} />
        <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
          <input className="input" type="datetime-local" value={safeFilters.generated_from} onChange={(event) => updateFilter("generated_from", event.target.value)} />
          <input className="input" type="datetime-local" value={safeFilters.generated_to} onChange={(event) => updateFilter("generated_to", event.target.value)} />
          <input className="input" placeholder="Source IP" value={safeFilters.src_ip} onChange={(event) => updateFilter("src_ip", event.target.value)} />
          <input className="input" placeholder="Destination IP" value={safeFilters.dst_ip} onChange={(event) => updateFilter("dst_ip", event.target.value)} />
          <input className="input" placeholder="Action" value={safeFilters.action} onChange={(event) => updateFilter("action", event.target.value)} />
          <input className="input" placeholder="App/service" value={safeFilters.app} onChange={(event) => updateFilter("app", event.target.value)} />
          <SafeSelect
            value={safeFilters.app_risk}
            options={[
              { value: "", label: "Any risk" },
              { value: "1", label: "Risk 1" },
              { value: "2", label: "Risk 2" },
              { value: "3", label: "Risk 3" },
              { value: "4", label: "Risk 4" },
              { value: "5", label: "Risk 5" }
            ]}
            onChange={(next) => updateFilter("app_risk", next)}
            ariaLabel="App risk filter"
          />
        </div>
        <details className="rounded-lg border border-line bg-panel2 p-3">
          <summary className="cursor-pointer text-sm font-extrabold uppercase tracking-wide text-muted">Advanced filters and sorting</summary>
          <div className="mt-3 grid gap-3 md:grid-cols-3 xl:grid-cols-5">
            <input className="input" placeholder="Protocol" value={safeFilters.protocol} onChange={(event) => updateFilter("protocol", event.target.value)} />
            <input className="input" placeholder="Source zone" value={safeFilters.src_zone} onChange={(event) => updateFilter("src_zone", event.target.value)} />
            <input className="input" placeholder="Destination zone" value={safeFilters.dst_zone} onChange={(event) => updateFilter("dst_zone", event.target.value)} />
            <input className="input" placeholder="Country" value={safeFilters.country} onChange={(event) => updateFilter("country", event.target.value)} />
            <SafeSelect
              value={safeFilters.source_id}
              options={sourceOptions}
              onChange={(next) => updateFilter("source_id", next)}
              ariaLabel="Log source filter"
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
              ariaLabel="Log source status filter"
            />
            <SafeSelect
              value={safeFilters.sort_by}
              options={[
                { value: "generated", label: "Sort by generated time" },
                { value: "app_risk", label: "Sort by app risk" },
                { value: "action", label: "Sort by action" },
                { value: "src_ip", label: "Sort by source IP" },
                { value: "dst_ip", label: "Sort by destination IP" }
              ]}
              onChange={(next) => updateFilter("sort_by", next)}
              ariaLabel="Log sort"
            />
          </div>
        </details>
      </section>

      {logs.isError ? <ErrorBanner error={logs.error} /> : null}
      {logs.isLoading ? <LoadingPanel label="Loading logs" /> : null}

      <TableToolbar
        density={density}
        onDensityChange={setDensity}
        savedViews={savedViews}
        onSaveView={saveView}
        onApplyView={applyView}
        onDeleteView={(name) => setSavedViews((current) => normalizeSavedViews(current, normalizeLogSavedView).filter((view) => view.name !== name))}
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
                <tr key={row.id} className="cursor-pointer" onClick={() => openLog(row.original.id)}>
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!logs.isLoading && !logRows.length ? <EmptyState title="No logs match" body="Adjust filters or import controlled logs from Validation Controls." /> : null}
      </section>

      <PaginationControls limit={limit} offset={offset} resultCount={logRows.length} totalCount={logs.data?.totalCount} onLimitChange={setLimit} onOffsetChange={setOffset} />

      <DetailDrawer title={`Log ${selected?.id ?? ""}`} open={Boolean(selectedId)} onClose={closeLog}>
        {selected ? (
          <div className="space-y-5">
            <MetaGrid
              rows={[
                { label: "Generated", value: selected.generated_time },
                { label: "Log Source", value: selected.source_name ? `${selected.source_name} (${selected.source_type ?? "unknown"})` : "-" },
                { label: "Parser Profile", value: selected.parser_profile ?? "-" },
                { label: "Receive Time", value: selected.receive_time },
                { label: "Source", value: `${selected.src_ip ?? "-"}:${selected.src_port ?? "-"}` },
                { label: "Destination", value: `${selected.dst_ip ?? "-"}:${selected.dst_port ?? "-"}` },
                { label: "Zones", value: `${selected.src_zone ?? "-"} -> ${selected.dst_zone ?? "-"}` },
                { label: "App / Risk", value: `${selected.app ?? "-"} / ${selected.app_risk ?? "-"}` },
                { label: "Action / Protocol", value: `${selected.action ?? "-"} / ${selected.protocol ?? "-"}` },
                { label: "Bytes / Packets", value: `${selected.bytes ?? "-"} / ${selected.packets ?? "-"}` },
                { label: "ML Anomaly", value: selected.is_anomaly ? `Yes (${selected.anomaly_score ?? "no score"})` : "No" },
                { label: "Countries", value: `${selected.src_country ?? "-"} -> ${selected.dst_country ?? "-"}` }
              ]}
            />
            <div className="flex flex-wrap gap-2">
              <Link className="btn-secondary" to={assistantHref}>Ask Assistant about this log</Link>
            </div>
            {selected.alert_ids?.length ? (
              <div className="rounded-lg border border-amber/30 bg-amber/10 p-3 text-sm text-amber">
                Related alerts: {selected.alert_ids.map((id) => <Link key={id} className="ml-2 underline" to={`/alerts?alert=${id}`}>{id}</Link>)}
              </div>
            ) : null}
            {selected.triage_explanation ? (
              <section className="rounded-lg border border-cyan/25 bg-cyan/5 p-4">
                <div className="mb-3 flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">
                      {selected.triage_explanation.status === "flagged" ? "Why flagged?" : "Why not flagged?"}
                    </div>
                    <p className="mt-1 text-sm text-muted">{selected.triage_explanation.summary}</p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Badge value="Decision Support" />
                    <Badge value="Automation Disabled" />
                    <Link className="btn-secondary text-xs" to={assistantHref}>Ask Assistant</Link>
                  </div>
                </div>
                {selected.triage_explanation.normalized_signals.length ? (
                  <div className="mb-3 flex flex-wrap gap-2">
                    {selected.triage_explanation.normalized_signals.slice(0, 6).map((signal) => (
                      <span key={signal} className="rounded border border-line bg-panel2 px-2 py-1 text-xs font-bold text-muted">
                        {signal}
                      </span>
                    ))}
                  </div>
                ) : null}
                <div className="grid gap-2 md:grid-cols-2">
                  {selected.triage_explanation.reasons.slice(0, 4).map((reason) => (
                    <div key={reason} className="rounded border border-line bg-shell p-3 text-sm text-muted">{reason}</div>
                  ))}
                </div>
                <div className="mt-3 grid gap-2 md:grid-cols-2">
                  <div className="rounded border border-line bg-panel2 p-3">
                    <div className="text-xs font-bold uppercase tracking-wide text-muted">Evidence strength</div>
                    <div className="mt-1 text-sm font-bold text-text">{selected.triage_explanation.evidence_strength ?? "analyst review required"}</div>
                  </div>
                  <div className="rounded border border-line bg-panel2 p-3">
                    <div className="text-xs font-bold uppercase tracking-wide text-muted">Missing context</div>
                    <div className="mt-1 text-sm font-semibold text-text">
                      {selected.triage_explanation.missing_context?.length
                        ? selected.triage_explanation.missing_context.slice(0, 3).join("; ")
                        : "No explicit gap recorded; verify environment context."}
                    </div>
                  </div>
                </div>
                {selected.triage_explanation.parser_warnings.length ? (
                  <details className="mt-3">
                    <summary className="cursor-pointer text-sm font-bold text-text">Parser notes</summary>
                    <div className="mt-2 space-y-2">
                      {selected.triage_explanation.parser_warnings.map((warning) => (
                        <div key={warning} className="rounded border border-amber/30 bg-amber/10 p-2 text-sm text-amber">{warning}</div>
                      ))}
                    </div>
                  </details>
                ) : null}
              </section>
            ) : null}
            <section className="rounded-lg border border-cyan/25 bg-cyan/5 p-4">
              <div className="mb-3 flex items-center justify-between gap-2">
                <div>
                  <div className="text-xs font-extrabold uppercase tracking-wide text-cyan">Analyst ML Label</div>
                  <div className="text-sm text-muted">Labels become training data for the supervised model. They do not trigger automatic response.</div>
                </div>
                {currentLabel ? <Badge value={`labeled: ${currentLabel.label}`} /> : <Badge value="unlabeled" />}
              </div>
              <div className="grid gap-3 md:grid-cols-2">
                <label className="text-xs font-bold uppercase tracking-wide text-muted">
                  Label
                  <SafeSelect
                    className="mt-1"
                    value={labelForm.label}
                    options={LABEL_OPTIONS.map((item) => ({ value: item, label: item }))}
                    onChange={(next) => setLabelForm((current) => ({ ...current, label: next as MLLabelValue }))}
                    ariaLabel="ML label"
                  />
                </label>
                <label className="text-xs font-bold uppercase tracking-wide text-muted">
                  Attack Type
                  <SafeSelect
                    className="mt-1"
                    value={labelForm.attack_type}
                    options={ATTACK_TYPE_OPTIONS.map((item) => ({ value: item, label: item }))}
                    onChange={(next) => setLabelForm((current) => ({ ...current, attack_type: next as MLAttackType }))}
                    ariaLabel="Attack type"
                  />
                </label>
                <label className="text-xs font-bold uppercase tracking-wide text-muted">
                  Confidence: {labelForm.confidence}
                  <input
                    className="mt-3 w-full"
                    type="range"
                    min={1}
                    max={5}
                    value={labelForm.confidence}
                    onChange={(event) => setLabelForm((current) => ({ ...current, confidence: Number(event.target.value) }))}
                  />
                </label>
                <label className="text-xs font-bold uppercase tracking-wide text-muted md:col-span-2">
                  Review Note
                  <textarea
                    className="input mt-1 min-h-24"
                    value={labelForm.review_note}
                    onChange={(event) => setLabelForm((current) => ({ ...current, review_note: event.target.value }))}
                    placeholder="Explain why this row is benign, suspicious, malicious, or needs context."
                  />
                </label>
              </div>
              <div className="mt-3 flex flex-wrap items-center gap-3">
                <button
                  className="btn-primary"
                  type="button"
                  onClick={saveLabel}
                  disabled={labelMutations.create.isPending || labelMutations.update.isPending}
                >
                  {currentLabel ? "Update Label" : "Save Label"}
                </button>
                {currentLabel ? (
                  <span className="text-xs text-muted">
                    Last reviewed by {currentLabel.reviewer} at {currentLabel.created_at}
                  </span>
                ) : null}
              </div>
              {labelMutations.create.isError || labelMutations.update.isError ? (
                <div className="mt-3"><ErrorBanner error={labelMutations.create.error ?? labelMutations.update.error} /></div>
              ) : null}
            </section>
            <div>
              <div className="mb-2 text-sm font-extrabold uppercase tracking-wide text-muted">Raw Evidence</div>
              <pre className="max-h-56 overflow-auto rounded-lg border border-line bg-shell p-3 text-xs text-muted">{selected.raw_line ?? "Raw line unavailable."}</pre>
            </div>
            <details className="presentation-technical rounded-lg border border-line bg-panel2 p-3">
              <summary className="cursor-pointer text-sm font-bold">Parsed Payload</summary>
              <pre className="mt-3 max-h-72 overflow-auto text-xs text-muted">{JSON.stringify(selected.parsed_json, null, 2)}</pre>
            </details>
          </div>
        ) : null}
      </DetailDrawer>
    </div>
  );
}
