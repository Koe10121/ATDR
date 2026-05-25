import { useEffect, useId, useMemo, useRef, useState } from "react";
import clsx from "clsx";

export interface SafeSelectOption {
  value: string;
  label: string;
}

export function SafeSelect({
  value,
  options,
  onChange,
  className,
  disabled = false,
  ariaLabel
}: {
  value: string | number;
  options: SafeSelectOption[];
  onChange: (value: string) => void;
  className?: string;
  disabled?: boolean;
  ariaLabel?: string;
}) {
  const id = useId();
  const rootRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const stringValue = String(value ?? "");
  const selected = useMemo(() => options.find((option) => option.value === stringValue) ?? options[0], [options, stringValue]);

  useEffect(() => {
    if (!open) {
      return undefined;
    }
    function onDocumentClick(event: MouseEvent) {
      if (!rootRef.current?.contains(event.target as Node)) {
        setOpen(false);
      }
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setOpen(false);
      }
    }
    document.addEventListener("click", onDocumentClick);
    document.addEventListener("keydown", onKeyDown, true);
    return () => {
      document.removeEventListener("click", onDocumentClick);
      document.removeEventListener("keydown", onKeyDown, true);
    };
  }, [open]);

  function selectOption(nextValue: string) {
    window.setTimeout(() => {
      if (nextValue !== stringValue) {
        onChange(nextValue);
      }
      setOpen(false);
    }, 0);
  }

  return (
    <div ref={rootRef} className={clsx("relative", className)} data-atdr-dropdown-open={open ? "true" : "false"}>
      <button
        type="button"
        aria-label={ariaLabel}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={`${id}-listbox`}
        disabled={disabled}
        className="input flex w-full items-center justify-between gap-3 text-left disabled:cursor-not-allowed disabled:opacity-50"
        onClick={() => setOpen((current) => !current)}
      >
        <span className="truncate">{selected?.label ?? "Select"}</span>
        <span className="text-xs text-muted" aria-hidden="true">v</span>
      </button>
      {open ? (
        <div
          id={`${id}-listbox`}
          role="listbox"
          className="absolute left-0 right-0 top-full z-50 mt-1 max-h-72 overflow-auto rounded-lg border border-line bg-panel shadow-panel"
        >
          {options.map((option) => (
            <div
              key={option.value}
              role="option"
              tabIndex={0}
              aria-selected={option.value === stringValue}
              className={clsx(
                "block w-full cursor-pointer px-3 py-2 text-left text-sm transition hover:bg-cyan/10",
                option.value === stringValue ? "bg-cyan/10 font-extrabold text-cyan" : "text-text"
              )}
              onClick={() => selectOption(option.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  selectOption(option.value);
                }
              }}
            >
              {option.label}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}
