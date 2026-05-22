import { useMemo, useState } from "react";
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
import { TableToolbar, tableDensityClass } from "../components/TableToolbar";
import type { SavedView, TableDensity } from "../components/TableToolbar";
import { useLog, useLogsPage } from "../hooks/useApiQueries";
import { useDebouncedValue } from "../hooks/useDebouncedValue";
import { usePersistentState } from "../hooks/usePersistentState";
import type { NormalizedLog } from "../types/api";

export function LogExplorer() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [search, setSearch] = usePersistentState("atdr.log.search.v1", "");
  const [filters, setFilters] = usePersistentState("atdr.log.filters.v1", {
    src_ip: "",
    dst_ip: "",
    app: "",
    action: "",
    protocol: "",
    src_zone: "",
    dst_zone: "",
    country: "",
    generated_from: "",
    generated_to: "",
    sort_by: "generated"
  });
  const [limit, setLimit] = usePersistentState("atdr.log.limit.v1", 50);
  const [density, setDensity] = usePersistentState<TableDensity>("atdr.log.density.v1", "comfortable");
  const [savedViews, setSavedViews] = usePersistentState<Array<SavedView<{ search: string; filters: typeof filters }>>>("atdr.log.views.v1", []);
  const [offset, setOffset] = useState(0);
  const selectedIdParam = Number(searchParams.get("log"));
  const selectedId = Number.isFinite(selectedIdParam) && selectedIdParam > 0 ? selectedIdParam : null;
  const debouncedSearch = useDebouncedValue(search);
  const logs = useLogsPage({ search: debouncedSearch, ...filters, limit, offset });
  const logRows = logs.data?.items ?? [];
  const selectedDetail = useLog(selectedId);
  const selected = selectedDetail.data ?? logRows.find((item) => item.id === selectedId) ?? null;

  const columns = useMemo<ColumnDef<NormalizedLog>[]>(
    () => [
      { accessorKey: "id", header: "ID" },
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

  function updateFilter(key: keyof typeof filters, value: string) {
    setOffset(0);
    setFilters((current) => ({ ...current, [key]: value }));
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
    setSavedViews((current) => [...current.filter((view) => view.name !== name), { name, value: { search, filters } }]);
  }

  function applyView(view: SavedView<{ search: string; filters: typeof filters }>) {
    setOffset(0);
    setSearch(view.value.search);
    setFilters(view.value.filters);
  }

  return (
    <div className="space-y-5">
      <section className="hero-panel">
        <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">Log Explorer</div>
        <h1 className="mt-2 text-3xl font-black">Search raw evidence and normalized firewall events.</h1>
        <p className="mt-2 text-muted">Every row remains tied to its original Palo Alto syslog line for investigation evidence.</p>
      </section>

      <section className="panel space-y-3">
        <input className="input" placeholder="Search IP, app, rule, action, protocol, or zone" value={search} onChange={(event) => setSearch(event.target.value)} />
        <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-5">
          <input className="input" placeholder="Source IP" value={filters.src_ip} onChange={(event) => updateFilter("src_ip", event.target.value)} />
          <input className="input" placeholder="Destination IP" value={filters.dst_ip} onChange={(event) => updateFilter("dst_ip", event.target.value)} />
          <input className="input" placeholder="App" value={filters.app} onChange={(event) => updateFilter("app", event.target.value)} />
          <input className="input" placeholder="Action" value={filters.action} onChange={(event) => updateFilter("action", event.target.value)} />
          <input className="input" placeholder="Protocol" value={filters.protocol} onChange={(event) => updateFilter("protocol", event.target.value)} />
          <input className="input" placeholder="Source zone" value={filters.src_zone} onChange={(event) => updateFilter("src_zone", event.target.value)} />
          <input className="input" placeholder="Destination zone" value={filters.dst_zone} onChange={(event) => updateFilter("dst_zone", event.target.value)} />
          <input className="input" placeholder="Country" value={filters.country} onChange={(event) => updateFilter("country", event.target.value)} />
          <input className="input" type="datetime-local" value={filters.generated_from} onChange={(event) => updateFilter("generated_from", event.target.value)} />
          <input className="input" type="datetime-local" value={filters.generated_to} onChange={(event) => updateFilter("generated_to", event.target.value)} />
        </div>
        <select className="input max-w-xs" value={filters.sort_by} onChange={(event) => updateFilter("sort_by", event.target.value)}>
          <option value="generated">Sort by generated time</option>
          <option value="app_risk">Sort by app risk</option>
          <option value="action">Sort by action</option>
          <option value="src_ip">Sort by source IP</option>
          <option value="dst_ip">Sort by destination IP</option>
        </select>
      </section>

      {logs.isError ? <ErrorBanner error={logs.error} /> : null}
      {logs.isLoading ? <LoadingPanel label="Loading logs" /> : null}

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
                <tr key={row.id} className="cursor-pointer" onClick={() => openLog(row.original.id)}>
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!logs.isLoading && !logRows.length ? <EmptyState title="No logs match" body="Adjust filters or import sample logs from Demo Controls." /> : null}
      </section>

      <PaginationControls limit={limit} offset={offset} resultCount={logRows.length} totalCount={logs.data?.totalCount} onLimitChange={setLimit} onOffsetChange={setOffset} />

      <DetailDrawer title={`Log ${selected?.id ?? ""}`} open={Boolean(selectedId)} onClose={closeLog}>
        {selected ? (
          <div className="space-y-5">
            <MetaGrid
              rows={[
                { label: "Generated", value: selected.generated_time },
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
            {selected.alert_ids?.length ? (
              <div className="rounded-lg border border-amber/30 bg-amber/10 p-3 text-sm text-amber">
                Related alerts: {selected.alert_ids.map((id) => <Link key={id} className="ml-2 underline" to={`/alerts?alert=${id}`}>{id}</Link>)}
              </div>
            ) : null}
            <div>
              <div className="mb-2 text-sm font-extrabold uppercase tracking-wide text-muted">Raw Evidence</div>
              <pre className="max-h-56 overflow-auto rounded-lg border border-line bg-shell p-3 text-xs text-muted">{selected.raw_line ?? "Raw line unavailable."}</pre>
            </div>
            <details className="rounded-lg border border-line bg-panel2 p-3">
              <summary className="cursor-pointer text-sm font-bold">Parsed Payload</summary>
              <pre className="mt-3 max-h-72 overflow-auto text-xs text-muted">{JSON.stringify(selected.parsed_json, null, 2)}</pre>
            </details>
          </div>
        ) : null}
      </DetailDrawer>
    </div>
  );
}
