export function EmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div className="rounded-lg border border-line bg-panel2/70 p-6">
      <div className="text-sm font-bold text-text">{title}</div>
      <div className="mt-2 text-sm text-muted">{body}</div>
    </div>
  );
}
