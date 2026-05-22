export function PaginationControls({
  limit,
  offset,
  resultCount,
  totalCount,
  onLimitChange,
  onOffsetChange
}: {
  limit: number;
  offset: number;
  resultCount: number;
  totalCount?: number;
  onLimitChange: (limit: number) => void;
  onOffsetChange: (offset: number) => void;
}) {
  const page = Math.floor(offset / limit) + 1;
  const knownTotal = totalCount ?? resultCount;
  const totalPages = Math.max(1, Math.ceil(knownTotal / limit));
  const hasNext = offset + resultCount < knownTotal;
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line bg-panel2 p-3 text-sm text-muted">
      <div>
        Page <span className="font-bold text-text">{page}</span> of <span className="font-bold text-text">{totalPages}</span> | Showing{" "}
        <span className="font-bold text-text">{resultCount}</span> of <span className="font-bold text-text">{knownTotal}</span> rows
      </div>
      <div className="flex items-center gap-2">
        <select className="input w-28" value={limit} onChange={(event) => onLimitChange(Number(event.target.value))}>
          <option value={25}>25</option>
          <option value={50}>50</option>
          <option value={100}>100</option>
          <option value={250}>250</option>
        </select>
        <button className="btn-secondary" disabled={offset === 0} onClick={() => onOffsetChange(Math.max(0, offset - limit))}>
          Previous
        </button>
        <button className="btn-secondary" disabled={!hasNext} onClick={() => onOffsetChange(offset + limit)}>
          Next
        </button>
      </div>
    </div>
  );
}
