import { X } from "lucide-react";
import type { ReactNode } from "react";

export function DetailDrawer({
  title,
  open,
  onClose,
  children
}: {
  title: string;
  open: boolean;
  onClose: () => void;
  children: ReactNode;
}) {
  if (!open) {
    return null;
  }
  return (
    <div className="fixed inset-0 z-40 bg-black/50">
      <aside className="absolute right-0 top-0 h-full w-full max-w-2xl overflow-y-auto border-l border-line bg-panel p-5 shadow-panel">
        <div className="flex items-center justify-between gap-4 border-b border-line pb-4">
          <h2 className="text-xl font-black">{title}</h2>
          <button className="btn-secondary px-3" onClick={onClose} aria-label="Close details">
            <X size={16} />
          </button>
        </div>
        <div className="mt-5">{children}</div>
      </aside>
    </div>
  );
}
