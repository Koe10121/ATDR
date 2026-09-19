import { FormEvent, useEffect, useRef, useState } from "react";
import { Save } from "lucide-react";
import type { DetectionReviewDecision, ManualAnchorReviewInput } from "../types/api";
import { Badge } from "./Badge";
import { ErrorBanner } from "./ErrorBanner";
import { SafeSelect } from "./SafeSelect";

// Shared by every "independent human decision" review workspace (supervised
// qualification's 300 rows, its 700-row supplemental expansion, and any
// future batch). Reviewing hundreds of rows by mouse alone is the actual
// bottleneck to closing these campaigns, so this form adds keyboard
// shortcuts for the mechanical parts only -- it never shortcuts the
// judgment itself. The per-row confirmation checkbox still requires its own
// explicit keystroke/click; a shortcut never auto-confirms it, since its
// entire purpose is to force a distinct affirmative action that isn't the
// same keystroke as "submit".
export const DECISION_OPTIONS: { value: DetectionReviewDecision | ""; label: string }[] = [
  { value: "", label: "Select final decision" },
  { value: "benign", label: "Benign" },
  { value: "benign_unusual", label: "Benign unusual" },
  { value: "needs_context", label: "Needs context" },
  { value: "suspicious", label: "Suspicious" },
  { value: "malicious", label: "Malicious" }
];

const DECISION_SHORTCUT_KEYS = ["1", "2", "3", "4", "5"] as const;

export interface IndependentDecisionFormItem {
  row_index: number;
  revision: number;
  closed: boolean;
  reviewed: boolean;
  existing_review?: ManualAnchorReviewInput | null;
}

export interface IndependentDecisionSavePayload {
  expected_revision: number;
  decision: DetectionReviewDecision;
  attack_type: string;
  confidence: number;
  rationale: string;
  human_confirmed: true;
}

export function IndependentDecisionForm<TItem extends IndependentDecisionFormItem, TOperation>({
  item,
  onSubmit,
  onSaved,
  isPending,
  isError,
  error,
  errorFallback,
  decisionAriaLabel,
  testId
}: {
  item: TItem;
  onSubmit: (payload: IndependentDecisionSavePayload) => Promise<TOperation>;
  onSaved: (result: TOperation) => void;
  isPending: boolean;
  isError: boolean;
  error: unknown;
  errorFallback: string;
  decisionAriaLabel: string;
  testId: string;
}) {
  const [decision, setDecision] = useState<DetectionReviewDecision | "">("");
  const [attackType, setAttackType] = useState("");
  const [confidence, setConfidence] = useState("");
  const [rationale, setRationale] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const formRef = useRef<HTMLFormElement>(null);

  useEffect(() => {
    setDecision(item.existing_review?.decision ?? "");
    setAttackType(item.existing_review?.attack_type ?? "");
    setConfidence(item.existing_review ? String(item.existing_review.confidence) : "");
    setRationale(item.existing_review?.rationale ?? "");
    setConfirmed(false);
    // Reviewing many rows in sequence is the normal case here; land focus
    // back on the form immediately so "1"-"5" work without an extra click.
    formRef.current?.focus();
  }, [item]);

  const confidenceNumber = Number(confidence);
  const requiresAttackType = decision === "suspicious" || decision === "malicious";
  const valid = Boolean(
    decision &&
      confidenceNumber >= 1 &&
      confidenceNumber <= 100 &&
      rationale.trim().length >= 8 &&
      (!requiresAttackType || attackType.trim()) &&
      confirmed &&
      !item.closed
  );

  async function submit(event?: FormEvent) {
    event?.preventDefault();
    if (!valid || !decision) return;
    const result = await onSubmit({
      expected_revision: item.revision,
      decision,
      attack_type: attackType,
      confidence: confidenceNumber,
      rationale,
      human_confirmed: true
    });
    onSaved(result);
  }

  function onFormKeyDown(event: React.KeyboardEvent<HTMLFormElement>) {
    if (item.closed) return;
    const target = event.target as HTMLElement;
    const inTextEntry = target.tagName === "TEXTAREA" || (target.tagName === "INPUT" && (target as HTMLInputElement).type !== "checkbox");

    if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
      event.preventDefault();
      void submit();
      return;
    }
    if (inTextEntry) return;

    const shortcutIndex = DECISION_SHORTCUT_KEYS.indexOf(event.key as (typeof DECISION_SHORTCUT_KEYS)[number]);
    if (shortcutIndex !== -1) {
      event.preventDefault();
      setDecision(DECISION_OPTIONS[shortcutIndex + 1].value as DetectionReviewDecision);
      return;
    }
    if (event.key.toLowerCase() === "c") {
      event.preventDefault();
      setConfirmed((current) => !current);
    }
  }

  return (
    <section className="panel min-w-0" data-testid={testId}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="text-sm font-black uppercase tracking-wide text-muted">Independent decision</div>
        <Badge value={item.closed ? "Closed" : item.reviewed ? "Saved" : "Pending"} />
      </div>
      {!item.closed ? (
        <div className="mt-2 text-xs text-muted">
          Shortcuts: <span className="font-mono font-bold">1-5</span> decision ·{" "}
          <span className="font-mono font-bold">C</span> confirm ·{" "}
          <span className="font-mono font-bold">Ctrl+Enter</span> save &amp; next
        </div>
      ) : null}
      <form ref={formRef} tabIndex={-1} className="mt-4 space-y-4 outline-none" onSubmit={submit} onKeyDown={onFormKeyDown}>
        <label className="block text-sm font-bold">
          Final decision
          <SafeSelect
            ariaLabel={decisionAriaLabel}
            className="mt-2"
            disabled={item.closed}
            value={decision}
            options={DECISION_OPTIONS}
            onChange={(value) => setDecision(value as DetectionReviewDecision | "")}
          />
        </label>
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="text-sm font-bold">
            Attack type {requiresAttackType ? <span className="text-danger">required</span> : <span className="text-muted">optional</span>}
            <input
              className="input mt-2 w-full"
              disabled={item.closed}
              maxLength={120}
              value={attackType}
              onChange={(event) => setAttackType(event.target.value)}
              placeholder="e.g. network_probe"
            />
          </label>
          <label className="text-sm font-bold">
            Confidence (1-100)
            <input
              className="input mt-2 w-full"
              disabled={item.closed}
              type="number"
              min={1}
              max={100}
              value={confidence}
              onChange={(event) => setConfidence(event.target.value)}
            />
          </label>
        </div>
        <label className="block text-sm font-bold">
          Rationale
          <textarea
            className="input mt-2 min-h-28 w-full resize-y"
            disabled={item.closed}
            maxLength={2000}
            value={rationale}
            onChange={(event) => setRationale(event.target.value)}
            placeholder="Record the evidence supporting this independent decision."
          />
        </label>
        {!item.closed ? (
          <label className="flex items-start gap-3 rounded-lg border border-line bg-panel2 p-3 text-sm font-semibold">
            <input
              className="mt-1"
              type="checkbox"
              checked={confirmed}
              onChange={(event) => setConfirmed(event.target.checked)}
            />
            I confirm this is my independent human decision based only on the approved evidence shown.
          </label>
        ) : null}
        {isError ? <ErrorBanner error={error} fallback={errorFallback} /> : null}
        {!item.closed ? (
          <button className="btn-primary inline-flex items-center gap-2" type="submit" disabled={!valid || isPending}>
            <Save size={16} /> {isPending ? "Saving" : item.reviewed ? "Update and next" : "Save and next"}
          </button>
        ) : null}
      </form>
    </section>
  );
}
