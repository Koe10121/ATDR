import { useState } from "react";
import { SafeSelect } from "./SafeSelect";

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
  const savedViewOptions = [{ value: "", label: "Apply saved view" }, ...safeSavedViews.map((view) => ({ value: view.name, label: view.name }))];
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line bg-panel2 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <SafeSelect
          className="w-36"
          value={density}
          options={[
            { value: "comfortable", label: "Comfortable" },
            { value: "compact", label: "Compact" }
          ]}
          onChange={(next) => onDensityChange(next as TableDensity)}
          ariaLabel="Table density"
        />
        <SafeSelect
          className="w-48"
          value=""
          options={savedViewOptions}
          onChange={(next) => {
            const view = safeSavedViews.find((item) => item.name === next);
            if (view) onApplyView(view);
          }}
          ariaLabel="Apply saved view"
        />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <input aria-label="Saved view name" className="input w-48" placeholder="View name" value={name} onChange={(event) => setName(event.target.value)} />
        <button
          type="button"
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
          <button type="button" className="btn-secondary" onClick={() => onDeleteView(safeSavedViews[safeSavedViews.length - 1].name)}>
            Delete last
          </button>
        ) : null}
      </div>
    </div>
  );
}
