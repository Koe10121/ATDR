import { ShieldX } from "lucide-react";

export function AccessDenied() {
  return (
    <section className="panel flex items-start gap-4">
      <div className="rounded-lg border border-danger/40 bg-danger/10 p-3 text-danger">
        <ShieldX size={24} />
      </div>
      <div>
        <h1 className="text-2xl font-black">Access denied</h1>
        <p className="mt-2 text-muted">This page is restricted to admin users. Your session remains active, but the requested control is role-protected.</p>
      </div>
    </section>
  );
}
