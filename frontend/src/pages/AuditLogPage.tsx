import { useMemo, useState } from "react";
import { flexRender, getCoreRowModel, useReactTable } from "@tanstack/react-table";
import type { ColumnDef } from "@tanstack/react-table";
import { useSearchParams } from "react-router-dom";
import { DetailDrawer } from "../components/DetailDrawer";
import { EmptyState } from "../components/EmptyState";
import { ErrorBanner } from "../components/ErrorBanner";
import { LoadingPanel } from "../components/LoadingPanel";
import { MetaGrid } from "../components/MetaGrid";
import { PaginationControls } from "../components/PaginationControls";
import { TableToolbar, tableDensityClass } from "../components/TableToolbar";
import type { SavedView, TableDensity } from "../components/TableToolbar";
import { useAuditPage } from "../hooks/useApiQueries";
import { usePersistentState } from "../hooks/usePersistentState";
import { normalizeSavedViews, normalizeStringState } from "../lib/safeTableState";
import type { AuditLog } from "../types/api";

const AUDIT_FILTER_DEFAULTS = { actor: "", action: "", target_type: "", target_value: "", created_from: "", created_to: "" };
type AuditFilters = typeof AUDIT_FILTER_DEFAULTS;

function normalizeAuditFilters(value: unknown): AuditFilters {
  return normalizeStringState(AUDIT_FILTER_DEFAULTS, value);
}

export function AuditLogPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [filters, setFilters] = usePersistentState<AuditFilters>("atdr.audit.filters.v1", AUDIT_FILTER_DEFAULTS);
  const safeFilters = useMemo(() => normalizeAuditFilters(filters), [filters]);
  const [limit, setLimit] = usePersistentState("atdr.audit.limit.v1", 100);
  const [density, setDensity] = usePersistentState<TableDensity>("atdr.audit.density.v1", "comfortable");
  const [rawSavedViews, setSavedViews] = usePersistentState<Array<SavedView<unknown>>>("atdr.audit.views.v1", []);
  const savedViews = useMemo(() => normalizeSavedViews(rawSavedViews, normalizeAuditFilters), [rawSavedViews]);
  const [offset, setOffset] = useState(0);
  const selectedIdParam = Number(searchParams.get("audit"));
  const selectedId = Number.isFinite(selectedIdParam) && selectedIdParam > 0 ? selectedIdParam : null;
  const audit = useAuditPage({ ...safeFilters, limit, offset });
  const auditRows = audit.data?.items ?? [];
  const selected = auditRows.find((row) => row.id === selectedId) ?? null;

  const columns = useMemo<ColumnDef<AuditLog>[]>(
    () => [
      { accessorKey: "created_at", header: "Time" },
      { accessorKey: "actor", header: "Actor" },
      { accessorKey: "action", header: "Action" },
      { accessorKey: "target_type", header: "Target Type" },
      { accessorKey: "target_value", header: "Target" }
    ],
    []
  );
  const table = useReactTable({ data: auditRows, columns, getCoreRowModel: getCoreRowModel() });

  function updateFilter(key: keyof AuditFilters, value: string) {
    setOffset(0);
    setFilters((current) => normalizeAuditFilters({ ...normalizeAuditFilters(current), [key]: value }));
  }

  function openAudit(id: number) {
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      next.set("audit", String(id));
      return next;
    });
  }

  function closeAudit() {
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      next.delete("audit");
      return next;
    });
  }

  function saveView(name: string) {
    setSavedViews((current) => [...normalizeSavedViews(current, normalizeAuditFilters).filter((view) => view.name !== name), { name, value: safeFilters }]);
  }

  function applyView(view: SavedView<AuditFilters>) {
    setOffset(0);
    setFilters(normalizeAuditFilters(view.value));
  }

  return (
    <div className="space-y-5">
      <section className="hero-panel">
        <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">Audit Log</div>
        <h1 className="mt-2 text-3xl font-black">Read-only evidence for analyst and admin actions.</h1>
        <p className="mt-2 text-muted">Audit entries cannot be edited or deleted from this console.</p>
      </section>

      <section className="panel grid gap-3 md:grid-cols-3 xl:grid-cols-6">
        <input className="input" placeholder="Actor" value={safeFilters.actor} onChange={(event) => updateFilter("actor", event.target.value)} />
        <input className="input" placeholder="Action" value={safeFilters.action} onChange={(event) => updateFilter("action", event.target.value)} />
        <input className="input" placeholder="Target type" value={safeFilters.target_type} onChange={(event) => updateFilter("target_type", event.target.value)} />
        <input className="input" placeholder="Target value" value={safeFilters.target_value} onChange={(event) => updateFilter("target_value", event.target.value)} />
        <input className="input" type="datetime-local" value={safeFilters.created_from} onChange={(event) => updateFilter("created_from", event.target.value)} />
        <input className="input" type="datetime-local" value={safeFilters.created_to} onChange={(event) => updateFilter("created_to", event.target.value)} />
      </section>

      {audit.isError ? <ErrorBanner error={audit.error} /> : null}
      {audit.isLoading ? <LoadingPanel label="Loading audit log" /> : null}

      <TableToolbar
        density={density}
        onDensityChange={setDensity}
        savedViews={savedViews}
        onSaveView={saveView}
        onApplyView={applyView}
        onDeleteView={(name) => setSavedViews((current) => normalizeSavedViews(current, normalizeAuditFilters).filter((view) => view.name !== name))}
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
                <tr key={row.id} className="cursor-pointer" onClick={() => openAudit(row.original.id)}>
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!audit.isLoading && !auditRows.length ? <EmptyState title="No audit rows" body="No audit evidence matches the current filters." /> : null}
      </section>

      <PaginationControls limit={limit} offset={offset} resultCount={auditRows.length} totalCount={audit.data?.totalCount} onLimitChange={setLimit} onOffsetChange={setOffset} />

      <DetailDrawer title={`Audit ${selected?.id ?? ""}`} open={Boolean(selectedId)} onClose={closeAudit}>
        {selected ? (
          <div className="space-y-5">
            <MetaGrid
              rows={[
                { label: "Actor", value: selected.actor },
                { label: "Action", value: selected.action },
                { label: "Target", value: `${selected.target_type}:${selected.target_value}` },
                { label: "Timestamp", value: selected.created_at }
              ]}
            />
            <div>
              <div className="mb-2 text-sm font-extrabold uppercase tracking-wide text-muted">Details</div>
              <pre className="max-h-96 overflow-auto rounded-lg border border-line bg-shell p-3 text-xs text-muted">{JSON.stringify(selected.details, null, 2)}</pre>
            </div>
          </div>
        ) : null}
      </DetailDrawer>
    </div>
  );
}
