import { useMemo, useState } from "react";
import { flexRender, getCoreRowModel, useReactTable } from "@tanstack/react-table";
import type { ColumnDef } from "@tanstack/react-table";
import { Badge } from "../components/Badge";
import { EmptyState } from "../components/EmptyState";
import { MetricCard } from "../components/MetricCard";
import { useAlertStatusMutation, useAlerts } from "../hooks/useApiQueries";
import type { Alert, AlertStatus } from "../types/api";

export function AlertsTriage() {
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("open");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const alerts = useAlerts({ severity, status, limit: 100, sort_by: "score" });
  const statusMutation = useAlertStatusMutation();
  const selected = useMemo(() => (alerts.data ?? []).find((item) => item.id === selectedId) ?? alerts.data?.[0], [alerts.data, selectedId]);

  const columns = useMemo<ColumnDef<Alert>[]>(
    () => [
      { accessorKey: "id", header: "ID" },
      { accessorKey: "severity", header: "Severity", cell: ({ row }) => <Badge value={row.original.severity} kind="severity" /> },
      { accessorKey: "status", header: "Status", cell: ({ row }) => <Badge value={row.original.status} /> },
      { accessorKey: "threat_score", header: "Score" },
      { accessorKey: "title", header: "Alert" },
      { accessorKey: "src_ip", header: "Source" },
      { accessorKey: "evidence_count", header: "Evidence" }
    ],
    []
  );
  const table = useReactTable({ data: alerts.data ?? [], columns, getCoreRowModel: getCoreRowModel() });

  function setAlertStatus(nextStatus: AlertStatus) {
    if (selected) {
      statusMutation.mutate({ id: selected.id, status: nextStatus });
    }
  }

  return (
    <div className="space-y-5">
      <section className="hero-panel">
        <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">Alerts Triage</div>
        <h1 className="mt-2 text-3xl font-black">Prioritize, investigate, and close alert workflow.</h1>
      </section>

      <div className="grid gap-3 md:grid-cols-4">
        <select className="input" value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="">All severities</option>
          <option>Critical</option>
          <option>High</option>
          <option>Medium</option>
          <option>Low</option>
        </select>
        <select className="input" value={status} onChange={(event) => setStatus(event.target.value)}>
          <option value="">All statuses</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="contained">Contained</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False Positive</option>
        </select>
        <MetricCard label="Filtered Alerts" value={alerts.data?.length ?? "-"} detail="Current table result" tone="teal" />
        <MetricCard label="Selected" value={selected?.id ?? "-"} detail={selected?.severity ?? "No selection"} tone="amber" />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.3fr_0.7fr]">
        <section className="panel overflow-hidden">
          <div className="overflow-auto">
            <table className="soc-table">
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
                  <tr key={row.id} className="cursor-pointer" onClick={() => setSelectedId(row.original.id)}>
                    {row.getVisibleCells().map((cell) => (
                      <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!alerts.isLoading && !(alerts.data ?? []).length ? <EmptyState title="No alerts found" body="Adjust filters or run detection." /> : null}
        </section>

        <aside className="panel">
          {selected ? (
            <div>
              <Badge value={selected.severity} kind="severity" />
              <h2 className="mt-3 text-xl font-black">{selected.title}</h2>
              <p className="mt-3 text-sm text-muted">{selected.explanation}</p>
              <div className="mt-4 grid gap-2 text-sm text-muted">
                <div>Score: {selected.threat_score}</div>
                <div>Status: {selected.status}</div>
                <div>Source: {selected.src_ip ?? "-"}</div>
                <div>Destination: {selected.dst_ip ?? "-"}</div>
                <div>Evidence logs: {selected.evidence_count}</div>
                <div>Recommended: {selected.recommended_response}</div>
              </div>
              <div className="mt-5 grid gap-2">
                <button className="btn-secondary" onClick={() => setAlertStatus("investigating")}>Mark investigating</button>
                <button className="btn-secondary" onClick={() => setAlertStatus("contained")}>Mark contained</button>
                <button className="btn-primary" onClick={() => setAlertStatus("resolved")}>Resolve</button>
                <button className="btn-secondary" onClick={() => setAlertStatus("false_positive")}>False positive</button>
              </div>
            </div>
          ) : (
            <EmptyState title="Select an alert" body="Choose an alert from the table to inspect evidence and workflow." />
          )}
        </aside>
      </div>
    </div>
  );
}
