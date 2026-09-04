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
  const buttonRef = useRef<HTMLButtonElement>(null);
  const optionRefs = useRef<Array<HTMLDivElement | null>>([]);
  const [open, setOpen] = useState(false);
  const [focusIndex, setFocusIndex] = useState(0);
  const stringValue = String(value ?? "");
  const selected = useMemo(() => options.find((option) => option.value === stringValue) ?? options[0], [options, stringValue]);
  const selectedIndex = Math.max(0, options.findIndex((option) => option.value === selected?.value));

  useEffect(() => {
    if (!open) return;
    const frame = window.requestAnimationFrame(() => optionRefs.current[focusIndex]?.focus());
    return () => window.cancelAnimationFrame(frame);
  }, [focusIndex, open]);

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
        buttonRef.current?.focus();
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
      buttonRef.current?.focus();
    }, 0);
  }

  function moveFocus(nextIndex: number) {
    const bounded = Math.max(0, Math.min(options.length - 1, nextIndex));
    setFocusIndex(bounded);
    optionRefs.current[bounded]?.focus();
  }

  function openAt(index: number) {
    setFocusIndex(Math.max(0, Math.min(options.length - 1, index)));
    setOpen(true);
  }

  return (
    <div ref={rootRef} className={clsx("relative", className)} data-atdr-dropdown-open={open ? "true" : "false"}>
      <button
        ref={buttonRef}
        type="button"
        aria-label={ariaLabel}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={`${id}-listbox`}
        disabled={disabled}
        className="input flex w-full items-center justify-between gap-3 text-left disabled:cursor-not-allowed disabled:opacity-50"
        onClick={() => {
          if (!open) setFocusIndex(selectedIndex);
          setOpen((current) => !current);
        }}
        onKeyDown={(event) => {
          if (event.key === "ArrowDown") {
            event.preventDefault();
            openAt(open ? focusIndex + 1 : selectedIndex);
          } else if (event.key === "ArrowUp") {
            event.preventDefault();
            openAt(open ? focusIndex - 1 : selectedIndex);
          } else if (event.key === "Home") {
            event.preventDefault();
            openAt(0);
          } else if (event.key === "End") {
            event.preventDefault();
            openAt(options.length - 1);
          }
        }}
      >
        <span className="truncate">{selected?.label ?? "Select"}</span>
        <span className="text-xs text-muted" aria-hidden="true">v</span>
      </button>
      {open ? (
        <div
          id={`${id}-listbox`}
          role="listbox"
          aria-label={ariaLabel}
          className="absolute left-0 right-0 top-full z-50 mt-1 max-h-72 overflow-auto rounded-lg border border-line bg-panel shadow-panel"
        >
          {options.map((option, index) => (
            <div
              key={option.value}
              ref={(node) => { optionRefs.current[index] = node; }}
              role="option"
              tabIndex={index === focusIndex ? 0 : -1}
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
                } else if (event.key === "ArrowDown") {
                  event.preventDefault();
                  moveFocus(index + 1);
                } else if (event.key === "ArrowUp") {
                  event.preventDefault();
                  moveFocus(index - 1);
                } else if (event.key === "Home") {
                  event.preventDefault();
                  moveFocus(0);
                } else if (event.key === "End") {
                  event.preventDefault();
                  moveFocus(options.length - 1);
                } else if (event.key === "Tab") {
                  setOpen(false);
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
