import type { ReactNode } from "react";

export function ChartCard({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="panel">
      <div className="mb-4 text-sm font-extrabold uppercase tracking-wide text-muted">{title}</div>
      {children}
    </section>
  );
}
