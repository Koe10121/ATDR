import { useState } from "react";

export type TableDensity = "comfortable" | "compact";

export interface SavedView<T> {
  name: string;
  value: T;
}

export function tableDensityClass(density: TableDensity): string {
  return density === "compact" ? "soc-table soc-table-compact" : "soc-table";
}

export function TableToolbar<T>({
  density,
  onDensityChange,
  savedViews,
  onSaveView,
  onApplyView,
  onDeleteView
}: {
  density: TableDensity;
  onDensityChange: (density: TableDensity) => void;
  savedViews: Array<SavedView<T>>;
  onSaveView: (name: string) => void;
  onApplyView: (view: SavedView<T>) => void;
  onDeleteView: (name: string) => void;
}) {
  const [name, setName] = useState("");
  const safeSavedViews = Array.isArray(savedViews) ? savedViews : [];
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line bg-panel2 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <select className="input w-36" value={density} onChange={(event) => onDensityChange(event.target.value as TableDensity)}>
          <option value="comfortable">Comfortable</option>
          <option value="compact">Compact</option>
        </select>
        <select
          className="input w-48"
          value=""
          onChange={(event) => {
            const view = safeSavedViews.find((item) => item.name === event.target.value);
            if (view) onApplyView(view);
          }}
        >
          <option value="">Apply saved view</option>
          {safeSavedViews.map((view) => (
            <option key={view.name} value={view.name}>{view.name}</option>
          ))}
        </select>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <input className="input w-48" placeholder="View name" value={name} onChange={(event) => setName(event.target.value)} />
        <button
          className="btn-secondary"
          onClick={() => {
            if (name.trim()) {
              onSaveView(name.trim());
              setName("");
            }
          }}
        >
          Save view
        </button>
        {safeSavedViews.length ? (
          <button className="btn-secondary" onClick={() => onDeleteView(safeSavedViews[safeSavedViews.length - 1].name)}>
            Delete last
          </button>
        ) : null}
      </div>
    </div>
  );
}
