import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { ArrowLeft, ArrowRight, CheckCircle2, ClipboardCheck, LockKeyhole, Save } from "lucide-react";
import { Badge } from "../components/Badge";
import { EmptyState } from "../components/EmptyState";
import { ErrorBanner } from "../components/ErrorBanner";
import { LoadingPanel } from "../components/LoadingPanel";
import { MetricCard } from "../components/MetricCard";
import { SafeSelect } from "../components/SafeSelect";
import { SocPageHeader } from "../components/SocPageHeader";
import {
  useAssistantReviewItem,
  useCloseManualAnchorReviewMutation,
  useCloseSupplementalThreatAnchorReviewMutation,
  useCompleteEvidenceReviewMutation,
  useDetectionReviewItem,
  useEvidenceReviewStatus,
  useFrozenEvaluationStatus,
  useManualAnchorFixedRevalidationStatus,
  useManualAnchorReviewItem,
  useManualAnchorReviewItems,
  useManualAnchorReviewStatus,
  useSaveAssistantReviewMutation,
  useSaveDetectionReviewMutation,
  useSaveManualAnchorReviewMutation,
  useSaveSupplementalThreatAnchorReviewMutation,
  useStartSupplementalThreatAnchorReviewMutation,
  useSupplementalThreatAnchorReviewItem,
  useSupplementalThreatAnchorReviewItems,
  useSupplementalThreatAnchorReviewStatus,
  useSupplementalThreatAnchorStatus,
  useStartEvidenceReviewMutation,
  useStartManualAnchorReviewMutation
} from "../hooks/useApiQueries";
import type {
  AssistantReviewItem,
  AssistantReviewScores,
  DetectionReviewDecision,
  DetectionReviewDecisionGroup,
  DetectionReviewItem,
  EvidenceReviewOperation,
  EvidenceReviewProgress,
  EvidenceReviewWorkspace,
  FrozenEvaluationStatus,
  ManualAnchorReviewItem,
  ManualAnchorReviewOperation,
  ManualAnchorReviewProgress,
  SupplementalThreatAnchorReviewItem,
  SupplementalThreatAnchorReviewOperation,
  SupplementalThreatAnchorReviewProgress
} from "../types/api";

const decisionGroups = [
  { value: "", label: "Select review category" },
  { value: "benign_like", label: "Benign-like" },
  { value: "needs_context", label: "Needs context" },
  { value: "threat_positive", label: "Threat-positive" }
];

const decisionsByGroup: Record<DetectionReviewDecisionGroup, Array<{ value: string; label: string }>> = {
  benign_like: [
    { value: "benign", label: "Benign" },
    { value: "benign_unusual", label: "Benign unusual" }
  ],
  needs_context: [{ value: "needs_context", label: "Needs context" }],
  threat_positive: [
    { value: "suspicious", label: "Suspicious" },
    { value: "malicious", label: "Malicious" }
  ]
};

const assistantScoreFields: Array<{ key: keyof AssistantReviewScores; label: string }> = [
  { key: "factual_correctness", label: "Correctness" },
  { key: "evidence_grounding", label: "Evidence grounding" },
  { key: "citation_correctness", label: "Citation accuracy" },
  { key: "relevance", label: "Relevance" },
  { key: "concision", label: "Concision" },
  { key: "actionable_usefulness", label: "Usefulness" },
  { key: "privacy", label: "Privacy" },
  { key: "unsafe_action_refusal", label: "Safety" }
];

const blankAssistantScores: Record<keyof AssistantReviewScores, string> = {
  factual_correctness: "",
  evidence_grounding: "",
  citation_correctness: "",
  relevance: "",
  concision: "",
  actionable_usefulness: "",
  privacy: "",
  unsafe_action_refusal: ""
};

const scoreOptions = [
  { value: "", label: "Select score" },
  ...[1, 2, 3, 4, 5].map((score) => ({ value: String(score), label: `${score} / 5` }))
];

function formatFieldName(value: string): string {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function ProgressPanel({ progress }: { progress: EvidenceReviewProgress | ManualAnchorReviewProgress | SupplementalThreatAnchorReviewProgress }) {
  return (
    <>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4" data-testid={`${progress.workspace}-review-metrics`}>
        <MetricCard label="Reviewed" value={`${progress.reviewed}/${progress.total}`} detail="Confirmed decisions" tone="teal" />
        <MetricCard label="Remaining" value={progress.remaining} detail="Pending review" tone="amber" />
        <MetricCard label="Integrity" value={formatFieldName(progress.integrity_status)} detail="Protected contract" tone={progress.integrity_status === "valid" ? "success" : "amber"} />
        <MetricCard label="Invalid" value={progress.invalid} detail="Must remain zero" tone={progress.invalid ? "danger" : "slate"} />
      </div>
      <section className="panel" data-testid={`${progress.workspace}-review-progress`}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="text-sm font-black">Review progress</div>
            <div className="mt-1 text-sm text-muted">{progress.message}</div>
          </div>
          <Badge value={`${progress.progress_percent}%`} />
        </div>
        <div
          className="mt-4 h-2 overflow-hidden rounded-full bg-line"
          role="progressbar"
          aria-label="Review progress"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={progress.progress_percent}
        >
          <div className="h-full bg-teal transition-all" style={{ width: `${Math.min(100, progress.progress_percent)}%` }} />
        </div>
      </section>
    </>
  );
}

function FrozenEvaluationPanel({ evaluation }: { evaluation: FrozenEvaluationStatus }) {
  const statusLabel = formatFieldName(evaluation.status);
  return (
    <section className="panel" data-testid="frozen-evaluation-status">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-sm font-black uppercase tracking-wide text-muted">Frozen evaluation</div>
          <div className="mt-1 text-sm text-muted">{evaluation.message}</div>
        </div>
        <Badge value={statusLabel} />
      </div>
      <div className="mt-4 grid gap-3 sm:grid-cols-3">
        <div className="rounded-lg border border-line bg-panel2 p-3">
          <div className="text-xs font-black uppercase tracking-wide text-muted">Detection review</div>
          <div className="mt-1 text-lg font-black">{evaluation.detection.reviewed}/{evaluation.detection.total}</div>
          <div className="mt-1 text-xs text-muted">{evaluation.detection.closed ? "Closed" : "Human review open"}</div>
        </div>
        <div className="rounded-lg border border-line bg-panel2 p-3">
          <div className="text-xs font-black uppercase tracking-wide text-muted">Assistant review</div>
          <div className="mt-1 text-lg font-black">{evaluation.assistant.reviewed}/{evaluation.assistant.total}</div>
          <div className="mt-1 text-xs text-muted">{evaluation.assistant.closed ? "Closed" : "Human review open"}</div>
        </div>
        <div className="rounded-lg border border-line bg-panel2 p-3">
          <div className="text-xs font-black uppercase tracking-wide text-muted">Lifecycle</div>
          <div className="mt-1 text-sm font-black">{formatFieldName(evaluation.activation_decision.lifecycle)}</div>
          <div className="mt-1 text-xs text-muted">No automatic activation</div>
        </div>
      </div>
    </section>
  );
}

function ItemNavigation({
  rowIndex,
  total,
  nextPendingIndex,
  onNavigate
}: {
  rowIndex: number;
  total: number;
  nextPendingIndex?: number | null;
  onNavigate: (rowIndex: number) => void;
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div className="text-sm font-bold text-muted">Item {rowIndex + 1} of {total}</div>
      <div className="flex flex-wrap gap-2">
        <button className="btn-secondary inline-flex items-center gap-2" type="button" disabled={rowIndex <= 0} onClick={() => onNavigate(rowIndex - 1)}>
          <ArrowLeft size={16} /> Previous
        </button>
        {nextPendingIndex !== null && nextPendingIndex !== undefined && nextPendingIndex !== rowIndex ? (
          <button className="btn-secondary" type="button" onClick={() => onNavigate(nextPendingIndex)}>Next pending</button>
        ) : null}
        <button className="btn-secondary inline-flex items-center gap-2" type="button" disabled={rowIndex >= total - 1} onClick={() => onNavigate(rowIndex + 1)}>
          Next <ArrowRight size={16} />
        </button>
      </div>
    </div>
  );
}

function DetectionReviewForm({
  item,
  onSaved
}: {
  item: DetectionReviewItem;
  onSaved: (result: EvidenceReviewOperation) => void;
}) {
  const save = useSaveDetectionReviewMutation();
  const [decisionGroup, setDecisionGroup] = useState<DetectionReviewDecisionGroup | "">("");
  const [decision, setDecision] = useState<DetectionReviewDecision | "">("");
  const [attackType, setAttackType] = useState("");
  const [confidence, setConfidence] = useState("");
  const [rationale, setRationale] = useState("");
  const [confirmed, setConfirmed] = useState(false);

  useEffect(() => {
    const existing = item.existing_review;
    setDecisionGroup(existing?.decision_group ?? "");
    setDecision(existing?.decision ?? "");
    setAttackType(existing?.attack_type ?? "");
    setConfidence(existing ? String(existing.confidence) : "");
    setRationale(existing?.rationale ?? "");
    setConfirmed(false);
  }, [item]);

  const decisionOptions = useMemo(
    () => [{ value: "", label: "Select final decision" }, ...(decisionGroup ? decisionsByGroup[decisionGroup] : [])],
    [decisionGroup]
  );
  const confidenceNumber = Number(confidence);
  const requiresAttackType = decision === "suspicious" || decision === "malicious";
  const valid = Boolean(
    decisionGroup &&
    decision &&
    confidenceNumber >= 1 &&
    confidenceNumber <= 100 &&
    rationale.trim().length >= 8 &&
    (!requiresAttackType || attackType.trim()) &&
    confirmed
  );

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!valid || !decisionGroup || !decision) return;
    const result = await save.mutateAsync({
      rowIndex: item.row_index,
      payload: {
        expected_revision: item.revision,
        decision_group: decisionGroup,
        decision,
        attack_type: attackType,
        confidence: confidenceNumber,
        rationale,
        human_confirmed: true
      }
    });
    onSaved(result);
  }

  return (
    <section className="panel min-w-0" data-testid="detection-review-form">
      <div className="flex items-center justify-between gap-3">
        <div className="text-sm font-black uppercase tracking-wide text-muted">Human decision</div>
        <Badge value={item.reviewed ? "Saved" : "Pending"} />
      </div>
      {item.reviewed ? <div className="mt-4 rounded-lg border border-success/30 bg-success/10 p-3 text-sm font-semibold text-success">This decision is complete and immutable.</div> : null}
      <form className="mt-4 space-y-4" onSubmit={submit}>
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="text-sm font-bold">
            Review category
            <SafeSelect
              ariaLabel="Detection review category"
              className="mt-2"
              disabled={item.reviewed}
              value={decisionGroup}
              options={decisionGroups}
              onChange={(value) => {
                setDecisionGroup(value as DetectionReviewDecisionGroup | "");
                setDecision("");
              }}
            />
          </label>
          <label className="text-sm font-bold">
            Final decision
            <SafeSelect
              ariaLabel="Detection final decision"
              className="mt-2"
              disabled={item.reviewed || !decisionGroup}
              value={decision}
              options={decisionOptions}
              onChange={(value) => setDecision(value as DetectionReviewDecision | "")}
            />
          </label>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="text-sm font-bold">
            Attack type {requiresAttackType ? <span className="text-danger">required</span> : <span className="text-muted">optional</span>}
            <input className="input mt-2 w-full" disabled={item.reviewed} maxLength={120} value={attackType} onChange={(event) => setAttackType(event.target.value)} placeholder="e.g. port_scan" />
          </label>
          <label className="text-sm font-bold">
            Confidence (1-100)
            <input className="input mt-2 w-full" disabled={item.reviewed} type="number" min={1} max={100} value={confidence} onChange={(event) => setConfidence(event.target.value)} />
          </label>
        </div>
        <label className="block text-sm font-bold">
          Rationale
          <textarea className="input mt-2 min-h-28 w-full resize-y" disabled={item.reviewed} maxLength={2000} value={rationale} onChange={(event) => setRationale(event.target.value)} placeholder="Record the evidence behind your independent decision." />
        </label>
        {!item.reviewed ? (
          <label className="flex items-start gap-3 rounded-lg border border-line bg-panel2 p-3 text-sm font-semibold">
            <input className="mt-1" type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />
            I confirm this is my independent human decision based only on the evidence shown.
          </label>
        ) : null}
        {save.isError ? <ErrorBanner error={save.error} fallback="Unable to save this decision." /> : null}
        {!item.reviewed ? (
          <button className="btn-primary inline-flex items-center gap-2" type="submit" disabled={!valid || save.isPending}>
            <Save size={16} /> {save.isPending ? "Saving" : "Save decision"}
          </button>
        ) : null}
      </form>
    </section>
  );
}

function DetectionWorkspace({
  item,
  onNavigate,
  onSaved
}: {
  item: DetectionReviewItem;
  onNavigate: (rowIndex: number) => void;
  onSaved: (result: EvidenceReviewOperation) => void;
}) {
  return (
    <div className="space-y-4" data-testid="detection-review-workspace">
      <ItemNavigation rowIndex={item.row_index} total={item.total} nextPendingIndex={item.next_pending_index} onNavigate={onNavigate} />
      <div className="grid min-w-0 gap-4 xl:grid-cols-[1.05fr_0.95fr]">
        <section className="panel min-w-0" data-testid="detection-approved-evidence">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="text-sm font-black uppercase tracking-wide text-muted">Approved evidence</div>
            <Badge value="Predictions Withheld" />
          </div>
          <dl className="mt-4 grid gap-x-6 gap-y-3 sm:grid-cols-2" data-testid="detection-evidence-fields">
            {Object.entries(item.evidence).map(([key, value]) => (
              <div key={key} className="min-w-0 border-b border-line pb-2">
                <dt className="text-xs font-black uppercase tracking-wide text-muted">{formatFieldName(key)}</dt>
                <dd className="mt-1 break-words text-sm font-semibold text-text">{value}</dd>
              </div>
            ))}
          </dl>
        </section>
        <DetectionReviewForm item={item} onSaved={onSaved} />
      </div>
    </div>
  );
}

function AssistantReviewForm({
  item,
  onSaved
}: {
  item: AssistantReviewItem;
  onSaved: (result: EvidenceReviewOperation) => void;
}) {
  const save = useSaveAssistantReviewMutation();
  const [scores, setScores] = useState<Record<keyof AssistantReviewScores, string>>(blankAssistantScores);
  const [decision, setDecision] = useState<"accept" | "revise" | "reject" | "">("");
  const [notes, setNotes] = useState("");
  const [confirmed, setConfirmed] = useState(false);

  useEffect(() => {
    const existing = item.existing_review;
    setScores(
      existing
        ? Object.fromEntries(Object.entries(existing.scores).map(([key, value]) => [key, String(value)])) as Record<keyof AssistantReviewScores, string>
        : blankAssistantScores
    );
    setDecision(existing?.overall_decision ?? "");
    setNotes(existing?.notes ?? "");
    setConfirmed(false);
  }, [item]);

  const allScoresValid = assistantScoreFields.every(({ key }) => {
    const score = Number(scores[key]);
    return score >= 1 && score <= 5;
  });
  const notesRequired = decision === "revise" || decision === "reject";
  const valid = Boolean(allScoresValid && decision && (!notesRequired || notes.trim().length >= 8) && confirmed);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!valid || !decision) return;
    const numericScores = Object.fromEntries(
      assistantScoreFields.map(({ key }) => [key, Number(scores[key])])
    ) as unknown as AssistantReviewScores;
    const result = await save.mutateAsync({
      rowIndex: item.row_index,
      payload: {
        expected_revision: item.revision,
        scores: numericScores,
        overall_decision: decision,
        notes,
        human_confirmed: true
      }
    });
    onSaved(result);
  }

  return (
    <section className="panel min-w-0" data-testid="assistant-acceptance-form">
      <div className="flex items-center justify-between gap-3">
        <div className="text-sm font-black uppercase tracking-wide text-muted">Acceptance decision</div>
        <Badge value={item.reviewed ? "Saved" : "Pending"} />
      </div>
      {item.reviewed ? <div className="mt-4 rounded-lg border border-success/30 bg-success/10 p-3 text-sm font-semibold text-success">This acceptance decision is complete and immutable.</div> : null}
      <form className="mt-4 space-y-4" onSubmit={submit}>
        <div className="grid gap-3 sm:grid-cols-2">
          {assistantScoreFields.map(({ key, label }) => (
            <label key={key} className="text-sm font-bold">
              {label}
              <SafeSelect ariaLabel={`${label} score`} className="mt-2" disabled={item.reviewed} value={scores[key]} options={scoreOptions} onChange={(value) => setScores((current) => ({ ...current, [key]: value }))} />
            </label>
          ))}
        </div>
        <label className="block text-sm font-bold">
          Overall decision
          <SafeSelect
            ariaLabel="Assistant overall decision"
            className="mt-2"
            disabled={item.reviewed}
            value={decision}
            options={[
              { value: "", label: "Select decision" },
              { value: "accept", label: "Accept" },
              { value: "revise", label: "Revise" },
              { value: "reject", label: "Reject" }
            ]}
            onChange={(value) => setDecision(value as "accept" | "revise" | "reject" | "")}
          />
        </label>
        <label className="block text-sm font-bold">
          Review note {notesRequired ? <span className="text-danger">required</span> : <span className="text-muted">optional</span>}
          <textarea className="input mt-2 min-h-24 w-full resize-y" disabled={item.reviewed} maxLength={2000} value={notes} onChange={(event) => setNotes(event.target.value)} />
        </label>
        {!item.reviewed ? (
          <label className="flex items-start gap-3 rounded-lg border border-line bg-panel2 p-3 text-sm font-semibold">
            <input className="mt-1" type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />
            I confirm these scores and this decision are my independent human assessment.
          </label>
        ) : null}
        {save.isError ? <ErrorBanner error={save.error} fallback="Unable to save this acceptance decision." /> : null}
        {!item.reviewed ? (
          <button className="btn-primary inline-flex items-center gap-2" type="submit" disabled={!valid || save.isPending}>
            <Save size={16} /> {save.isPending ? "Saving" : "Save assessment"}
          </button>
        ) : null}
      </form>
    </section>
  );
}

function AssistantWorkspace({
  item,
  onNavigate,
  onSaved
}: {
  item: AssistantReviewItem;
  onNavigate: (rowIndex: number) => void;
  onSaved: (result: EvidenceReviewOperation) => void;
}) {
  return (
    <div className="space-y-4" data-testid="assistant-acceptance-workspace">
      <ItemNavigation rowIndex={item.row_index} total={item.total} nextPendingIndex={item.next_pending_index} onNavigate={onNavigate} />
      <div className="grid min-w-0 gap-4 xl:grid-cols-[1.05fr_0.95fr]">
        <section className="panel min-w-0" data-testid="assistant-protected-answer">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="text-sm font-black uppercase tracking-wide text-muted">Protected answer</div>
            <Badge value={formatFieldName(item.context_type)} />
          </div>
          <div className="mt-4 border-b border-line pb-4">
            <div className="text-xs font-black uppercase tracking-wide text-muted">Question</div>
            <div className="mt-2 break-words text-base font-bold">{item.question}</div>
          </div>
          <div className="border-b border-line py-4">
            <div className="text-xs font-black uppercase tracking-wide text-muted">Answer</div>
            <div className="mt-2 whitespace-pre-wrap break-words text-sm leading-6">{item.answer}</div>
          </div>
          <div className="pt-4">
            <div className="text-xs font-black uppercase tracking-wide text-muted">Citations</div>
            <div className="mt-2 whitespace-pre-wrap break-all text-sm text-muted">{item.citations || "No citation supplied"}</div>
          </div>
        </section>
        <AssistantReviewForm item={item} onSaved={onSaved} />
      </div>
    </div>
  );
}

const manualDecisionOptions = [
  { value: "", label: "Select final decision" },
  { value: "benign", label: "Benign" },
  { value: "benign_unusual", label: "Benign unusual" },
  { value: "needs_context", label: "Needs context" },
  { value: "suspicious", label: "Suspicious" },
  { value: "malicious", label: "Malicious" }
];

function ManualAnchorReviewForm({
  item,
  onSaved
}: {
  item: ManualAnchorReviewItem;
  onSaved: (result: ManualAnchorReviewOperation) => void;
}) {
  const save = useSaveManualAnchorReviewMutation();
  const [decision, setDecision] = useState<DetectionReviewDecision | "">("");
  const [attackType, setAttackType] = useState("");
  const [confidence, setConfidence] = useState("");
  const [rationale, setRationale] = useState("");
  const [confirmed, setConfirmed] = useState(false);

  useEffect(() => {
    setDecision(item.existing_review?.decision ?? "");
    setAttackType(item.existing_review?.attack_type ?? "");
    setConfidence(item.existing_review ? String(item.existing_review.confidence) : "");
    setRationale(item.existing_review?.rationale ?? "");
    setConfirmed(false);
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

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!valid || !decision) return;
    const result = await save.mutateAsync({
      rowIndex: item.row_index,
      payload: {
        expected_revision: item.revision,
        decision,
        attack_type: attackType,
        confidence: confidenceNumber,
        rationale,
        human_confirmed: true
      }
    });
    onSaved(result);
  }

  return (
    <section className="panel min-w-0" data-testid="manual-anchor-review-form">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="text-sm font-black uppercase tracking-wide text-muted">Independent decision</div>
        <Badge value={item.closed ? "Closed" : item.reviewed ? "Saved" : "Pending"} />
      </div>
      <form className="mt-4 space-y-4" onSubmit={submit}>
        <label className="block text-sm font-bold">
          Final decision
          <SafeSelect
            ariaLabel="Manual anchor final decision"
            className="mt-2"
            disabled={item.closed}
            value={decision}
            options={manualDecisionOptions}
            onChange={(value) => setDecision(value as DetectionReviewDecision | "")}
          />
        </label>
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="text-sm font-bold">
            Attack type {requiresAttackType ? <span className="text-danger">required</span> : <span className="text-muted">optional</span>}
            <input className="input mt-2 w-full" disabled={item.closed} maxLength={120} value={attackType} onChange={(event) => setAttackType(event.target.value)} placeholder="e.g. port_scan" />
          </label>
          <label className="text-sm font-bold">
            Confidence (1-100)
            <input className="input mt-2 w-full" disabled={item.closed} type="number" min={1} max={100} value={confidence} onChange={(event) => setConfidence(event.target.value)} />
          </label>
        </div>
        <label className="block text-sm font-bold">
          Rationale
          <textarea className="input mt-2 min-h-28 w-full resize-y" disabled={item.closed} maxLength={2000} value={rationale} onChange={(event) => setRationale(event.target.value)} placeholder="Record the evidence supporting this independent decision." />
        </label>
        {!item.closed ? (
          <label className="flex items-start gap-3 rounded-lg border border-line bg-panel2 p-3 text-sm font-semibold">
            <input className="mt-1" type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />
            I confirm this is my independent human decision based only on the approved evidence shown.
          </label>
        ) : null}
        {save.isError ? <ErrorBanner error={save.error} fallback="Unable to save this manual-anchor decision." /> : null}
        {!item.closed ? (
          <button className="btn-primary inline-flex items-center gap-2" type="submit" disabled={!valid || save.isPending}>
            <Save size={16} /> {save.isPending ? "Saving" : item.reviewed ? "Update and next" : "Save and next"}
          </button>
        ) : null}
      </form>
    </section>
  );
}

function ManualAnchorWorkspace({
  item,
  onNavigate,
  onSaved
}: {
  item: ManualAnchorReviewItem;
  onNavigate: (rowIndex: number) => void;
  onSaved: (result: ManualAnchorReviewOperation) => void;
}) {
  return (
    <div className="space-y-4" data-testid="manual-anchor-review-workspace">
      <ItemNavigation rowIndex={item.row_index} total={item.total} nextPendingIndex={item.next_pending_index} onNavigate={onNavigate} />
      <div className="grid min-w-0 gap-4 xl:grid-cols-[1.05fr_0.95fr]">
        <section className="panel min-w-0" data-testid="manual-anchor-approved-evidence">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="text-sm font-black uppercase tracking-wide text-muted">Approved evidence</div>
            <div className="flex flex-wrap gap-2">
              <Badge value={formatFieldName(item.coverage_stratum)} />
              <Badge value="Predictions Withheld" />
            </div>
          </div>
          <dl className="mt-4 grid gap-x-6 gap-y-3 sm:grid-cols-2" data-testid="manual-anchor-evidence-fields">
            {Object.entries(item.evidence).map(([key, value]) => (
              <div key={key} className="min-w-0 border-b border-line pb-2">
                <dt className="text-xs font-black uppercase tracking-wide text-muted">{formatFieldName(key)}</dt>
                <dd className="mt-1 break-words text-sm font-semibold text-text">{value}</dd>
              </div>
            ))}
          </dl>
        </section>
        <ManualAnchorReviewForm item={item} onSaved={onSaved} />
      </div>
    </div>
  );
}

function ManualAnchorReviewPanel() {
  const [rowIndex, setRowIndex] = useState<number | null>(null);
  const [coverageStratum, setCoverageStratum] = useState("");
  const [reviewState, setReviewState] = useState("all");
  const [offset, setOffset] = useState(0);
  const status = useManualAnchorReviewStatus();
  const revalidation = useManualAnchorFixedRevalidationStatus();
  const start = useStartManualAnchorReviewMutation();
  const close = useCloseManualAnchorReviewMutation();
  const progress = status.data;
  const item = useManualAnchorReviewItem(
    rowIndex,
    Boolean(progress?.owned_by_current_user && progress.prepared)
  );
  const pageParams = useMemo(
    () => ({
      offset,
      limit: 20,
      review_state: reviewState,
      ...(coverageStratum ? { coverage_stratum: coverageStratum } : {})
    }),
    [coverageStratum, offset, reviewState]
  );
  const items = useManualAnchorReviewItems(
    pageParams,
    Boolean(progress?.owned_by_current_user && progress.prepared)
  );

  useEffect(() => {
    if (!progress?.owned_by_current_user || !progress.prepared || !progress.total) return;
    setRowIndex((current) => current ?? progress.next_pending_index ?? 0);
  }, [progress]);

  useEffect(() => {
    setOffset(0);
  }, [coverageStratum, reviewState]);

  async function startWorkspace() {
    const result = await start.mutateAsync();
    setRowIndex(result.next_item?.row_index ?? result.progress.next_pending_index ?? 0);
  }

  function handleSaved(result: ManualAnchorReviewOperation) {
    setRowIndex(result.next_item?.row_index ?? result.progress.next_pending_index ?? rowIndex);
  }

  async function closeWorkspace() {
    if (!progress || !window.confirm("Close this completed manual-anchor review? Saved decisions will become immutable.")) return;
    await close.mutateAsync(progress.revision);
  }

  if (status.isLoading) return <LoadingPanel label="Loading manual-anchor review status" />;
  if (status.isError) return <ErrorBanner error={status.error} fallback="Unable to load manual-anchor review status." />;
  if (!progress) return null;

  return (
    <div className="space-y-4" data-testid="manual-anchor-review-panel">
      {revalidation.isError ? <ErrorBanner error={revalidation.error} fallback="Unable to validate the fixed protocol." /> : null}
      <section className="panel" data-testid="manual-anchor-protocol-status">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="text-sm font-black uppercase tracking-wide text-muted">Fixed revalidation protocol</div>
            <div className="mt-1 text-sm text-muted">Development-only evaluation remains blocked until genuine review is closed.</div>
          </div>
          <Badge value={revalidation.data?.protocol.locked ? "Protocol Locked" : "Locks Before Review"} />
        </div>
        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          <div><div className="text-xs font-black uppercase text-muted">Strategies</div><div className="mt-1 text-lg font-black">{revalidation.data?.protocol.strategy_count ?? 0}</div></div>
          <div><div className="text-xs font-black uppercase text-muted">Evaluation</div><div className="mt-1 text-sm font-black">{revalidation.data?.evaluation_attempted ? "Completed" : "Not Run"}</div></div>
          <div><div className="text-xs font-black uppercase text-muted">Lifecycle</div><div className="mt-1 text-sm font-black">Shadow Observation</div></div>
        </div>
      </section>

      <ProgressPanel progress={progress} />

      <section className="panel" data-testid="manual-anchor-class-support">
        <div className="text-sm font-black uppercase tracking-wide text-muted">Class support</div>
        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          {Object.entries(progress.minimum_class_support).map(([label, target]) => (
            <div key={label} className="min-w-0 border-b border-line pb-3">
              <div className="text-xs font-black uppercase text-muted">{formatFieldName(label)}</div>
              <div className="mt-1 text-lg font-black">{progress.class_support[label] ?? 0}/{target}</div>
            </div>
          ))}
        </div>
      </section>

      {!progress.prepared || !progress.owned_by_current_user ? (
        <section className="panel" data-testid="manual-anchor-review-empty-state">
          <div className="flex items-start gap-3">
            <LockKeyhole className="mt-0.5 shrink-0 text-danger" size={20} />
            <div className="min-w-0 flex-1">
              <EmptyState
                title={progress.owner_assigned && !progress.owned_by_current_user ? "Review assigned" : progress.available ? "Workspace ready" : "Private pack unavailable"}
                body={progress.owner_assigned && !progress.owned_by_current_user ? "Aggregate progress is visible; evidence is restricted to the assigned reviewer." : progress.message}
              />
              {progress.can_review && progress.available ? (
                <button className="btn-primary mt-4 inline-flex items-center gap-2" type="button" onClick={startWorkspace} disabled={start.isPending}>
                  <ClipboardCheck size={16} /> {start.isPending ? "Opening" : "Start protected review"}
                </button>
              ) : null}
            </div>
          </div>
          {start.isError ? <div className="mt-4"><ErrorBanner error={start.error} fallback="Unable to start the manual-anchor review." /></div> : null}
        </section>
      ) : null}

      {progress.prepared && progress.owned_by_current_user ? (
        <>
          <section className="panel" data-testid="manual-anchor-review-filters">
            <div className="grid gap-4 sm:grid-cols-2">
              <label className="text-sm font-bold">
                Coverage stratum
                <SafeSelect
                  ariaLabel="Manual anchor coverage stratum"
                  className="mt-2"
                  value={coverageStratum}
                  options={[{ value: "", label: "All strata" }, ...progress.coverage_strata.map((value) => ({ value, label: formatFieldName(value) }))]}
                  onChange={setCoverageStratum}
                />
              </label>
              <label className="text-sm font-bold">
                Review state
                <SafeSelect
                  ariaLabel="Manual anchor review state"
                  className="mt-2"
                  value={reviewState}
                  options={[{ value: "all", label: "All rows" }, { value: "pending", label: "Pending" }, { value: "reviewed", label: "Reviewed" }]}
                  onChange={setReviewState}
                />
              </label>
            </div>
            {items.isError ? <div className="mt-4"><ErrorBanner error={items.error} fallback="Unable to filter manual-anchor items." /></div> : null}
            {items.data ? (
              <div className="mt-4">
                <div className="flex flex-wrap gap-2" data-testid="manual-anchor-item-list">
                  {items.data.items.map((entry) => (
                    <button key={entry.row_index} type="button" className={entry.row_index === rowIndex ? "btn-primary" : "btn-secondary"} onClick={() => setRowIndex(entry.row_index)}>
                      {entry.display_position} {entry.reviewed ? "Reviewed" : "Pending"}
                    </button>
                  ))}
                </div>
                <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-sm text-muted">
                  <span>{items.data.filtered_total} matching rows</span>
                  <div className="flex gap-2">
                    <button className="btn-secondary" type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 20))}>Previous page</button>
                    <button className="btn-secondary" type="button" disabled={offset + 20 >= items.data.filtered_total} onClick={() => setOffset(offset + 20)}>Next page</button>
                  </div>
                </div>
              </div>
            ) : null}
          </section>

          {progress.completed && !progress.closed ? (
            <section className="panel flex flex-wrap items-center justify-between gap-4" data-testid="manual-anchor-review-complete">
              <div className="flex items-start gap-3">
                <CheckCircle2 className="mt-0.5 text-success" size={20} />
                <div><div className="font-black">All decisions are valid</div><div className="mt-1 text-sm text-muted">Close to make decisions immutable. No import or evaluation runs automatically.</div></div>
              </div>
              <button className="btn-secondary" type="button" disabled={close.isPending} onClick={closeWorkspace}>{close.isPending ? "Closing" : "Close review"}</button>
              {close.isError ? <ErrorBanner error={close.error} fallback="Unable to close this review." /> : null}
            </section>
          ) : null}

          {item.isLoading ? <LoadingPanel label="Loading approved manual-anchor evidence" /> : null}
          {item.isError ? <ErrorBanner error={item.error} fallback="Unable to open this manual-anchor item." /> : null}
          {item.data ? <ManualAnchorWorkspace item={item.data} onNavigate={setRowIndex} onSaved={handleSaved} /> : null}
        </>
      ) : null}
    </div>
  );
}

function SupplementalThreatAnchorReviewForm({
  item,
  onSaved
}: {
  item: SupplementalThreatAnchorReviewItem;
  onSaved: (result: SupplementalThreatAnchorReviewOperation) => void;
}) {
  const save = useSaveSupplementalThreatAnchorReviewMutation();
  const [decision, setDecision] = useState<DetectionReviewDecision | "">("");
  const [attackType, setAttackType] = useState("");
  const [confidence, setConfidence] = useState("");
  const [rationale, setRationale] = useState("");
  const [confirmed, setConfirmed] = useState(false);

  useEffect(() => {
    setDecision(item.existing_review?.decision ?? "");
    setAttackType(item.existing_review?.attack_type ?? "");
    setConfidence(item.existing_review ? String(item.existing_review.confidence) : "");
    setRationale(item.existing_review?.rationale ?? "");
    setConfirmed(false);
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

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!valid || !decision) return;
    const result = await save.mutateAsync({
      rowIndex: item.row_index,
      payload: {
        expected_revision: item.revision,
        decision,
        attack_type: attackType,
        confidence: confidenceNumber,
        rationale,
        human_confirmed: true
      }
    });
    onSaved(result);
  }

  return (
    <section className="panel min-w-0" data-testid="supplemental-anchor-review-form">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="text-sm font-black uppercase tracking-wide text-muted">Independent decision</div>
        <Badge value={item.closed ? "Closed" : item.reviewed ? "Saved" : "Pending"} />
      </div>
      <form className="mt-4 space-y-4" onSubmit={submit}>
        <label className="block text-sm font-bold">
          Final decision
          <SafeSelect
            ariaLabel="Supplemental threat anchor final decision"
            className="mt-2"
            disabled={item.closed}
            value={decision}
            options={manualDecisionOptions}
            onChange={(value) => setDecision(value as DetectionReviewDecision | "")}
          />
        </label>
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="text-sm font-bold">
            Attack type {requiresAttackType ? <span className="text-danger">required</span> : <span className="text-muted">optional</span>}
            <input className="input mt-2 w-full" disabled={item.closed} maxLength={120} value={attackType} onChange={(event) => setAttackType(event.target.value)} placeholder="e.g. port_scan" />
          </label>
          <label className="text-sm font-bold">
            Confidence (1-100)
            <input className="input mt-2 w-full" disabled={item.closed} type="number" min={1} max={100} value={confidence} onChange={(event) => setConfidence(event.target.value)} />
          </label>
        </div>
        <label className="block text-sm font-bold">
          Rationale
          <textarea className="input mt-2 min-h-28 w-full resize-y" disabled={item.closed} maxLength={2000} value={rationale} onChange={(event) => setRationale(event.target.value)} placeholder="Record the evidence supporting this independent decision." />
        </label>
        {!item.closed ? (
          <label className="flex items-start gap-3 rounded-lg border border-line bg-panel2 p-3 text-sm font-semibold">
            <input className="mt-1" type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />
            I confirm this is my independent human decision based only on the approved evidence shown.
          </label>
        ) : null}
        {save.isError ? <ErrorBanner error={save.error} fallback="Unable to save this supplemental decision." /> : null}
        {!item.closed ? (
          <button className="btn-primary inline-flex items-center gap-2" type="submit" disabled={!valid || save.isPending}>
            <Save size={16} /> {save.isPending ? "Saving" : item.reviewed ? "Update and next" : "Save and next"}
          </button>
        ) : null}
      </form>
    </section>
  );
}

function SupplementalThreatAnchorWorkspace({
  item,
  onNavigate,
  onSaved
}: {
  item: SupplementalThreatAnchorReviewItem;
  onNavigate: (rowIndex: number) => void;
  onSaved: (result: SupplementalThreatAnchorReviewOperation) => void;
}) {
  return (
    <div className="space-y-4" data-testid="supplemental-anchor-review-workspace">
      <ItemNavigation rowIndex={item.row_index} total={item.total} nextPendingIndex={item.next_pending_index} onNavigate={onNavigate} />
      <div className="grid min-w-0 gap-4 xl:grid-cols-[1.05fr_0.95fr]">
        <section className="panel min-w-0" data-testid="supplemental-anchor-approved-evidence">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="text-sm font-black uppercase tracking-wide text-muted">Approved evidence</div>
            <div className="flex flex-wrap gap-2">
              <Badge value={formatFieldName(item.coverage_stratum)} />
              <Badge value="Predictions Withheld" />
              <Badge value="Deterministic Evidence" />
            </div>
          </div>
          <dl className="mt-4 grid gap-x-6 gap-y-3 sm:grid-cols-2" data-testid="supplemental-anchor-evidence-fields">
            {Object.entries(item.evidence).map(([key, value]) => (
              <div key={key} className="min-w-0 border-b border-line pb-2">
                <dt className="text-xs font-black uppercase tracking-wide text-muted">{formatFieldName(key)}</dt>
                <dd className="mt-1 break-words text-sm font-semibold text-text">{value}</dd>
              </div>
            ))}
          </dl>
        </section>
        <SupplementalThreatAnchorReviewForm item={item} onSaved={onSaved} />
      </div>
    </div>
  );
}

function SupplementalThreatAnchorReviewPanel() {
  const [rowIndex, setRowIndex] = useState<number | null>(null);
  const [coverageStratum, setCoverageStratum] = useState("");
  const [reviewState, setReviewState] = useState("all");
  const [offset, setOffset] = useState(0);
  const acquisition = useSupplementalThreatAnchorStatus();
  const status = useSupplementalThreatAnchorReviewStatus();
  const start = useStartSupplementalThreatAnchorReviewMutation();
  const close = useCloseSupplementalThreatAnchorReviewMutation();
  const progress = status.data;
  const item = useSupplementalThreatAnchorReviewItem(
    rowIndex,
    Boolean(progress?.owned_by_current_user && progress.prepared)
  );
  const pageParams = useMemo(
    () => ({
      offset,
      limit: 20,
      review_state: reviewState,
      ...(coverageStratum ? { coverage_stratum: coverageStratum } : {})
    }),
    [coverageStratum, offset, reviewState]
  );
  const items = useSupplementalThreatAnchorReviewItems(
    pageParams,
    Boolean(progress?.owned_by_current_user && progress.prepared)
  );

  useEffect(() => {
    if (!progress?.owned_by_current_user || !progress.prepared || !progress.total) return;
    setRowIndex((current) => current ?? progress.next_pending_index ?? 0);
  }, [progress]);

  useEffect(() => {
    setOffset(0);
  }, [coverageStratum, reviewState]);

  async function startWorkspace() {
    const result = await start.mutateAsync();
    setRowIndex(result.next_item?.row_index ?? result.progress.next_pending_index ?? 0);
  }

  function handleSaved(result: SupplementalThreatAnchorReviewOperation) {
    setRowIndex(result.next_item?.row_index ?? result.progress.next_pending_index ?? rowIndex);
  }

  async function closeWorkspace() {
    if (!progress || !window.confirm("Close this completed supplemental review? Saved decisions will become immutable.")) return;
    await close.mutateAsync(progress.revision);
  }

  if (status.isLoading || acquisition.isLoading) return <LoadingPanel label="Loading supplemental threat-anchor status" />;
  if (status.isError) return <ErrorBanner error={status.error} fallback="Unable to load the supplemental review." />;
  if (acquisition.isError) return <ErrorBanner error={acquisition.error} fallback="Unable to validate supplemental acquisition custody." />;
  if (!progress || !acquisition.data) return null;

  return (
    <div className="space-y-4" data-testid="supplemental-anchor-review-panel">
      <section className="panel" data-testid="supplemental-anchor-custody-status">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="text-sm font-black uppercase tracking-wide text-muted">Supplemental evidence custody</div>
            <div className="mt-1 text-sm text-muted">The closed 120-row review remains immutable. This workspace does not execute model evaluation.</div>
          </div>
          <Badge value={acquisition.data.coverage_gate_passed ? "Prediction-Blind Pack Ready" : "Preparation Required"} />
        </div>
        <div className="mt-4 grid gap-3 sm:grid-cols-4">
          <div><div className="text-xs font-black uppercase text-muted">Original review</div><div className="mt-1 text-sm font-black">{acquisition.data.original_review.reviewed}/{acquisition.data.original_review.total} Closed</div></div>
          <div><div className="text-xs font-black uppercase text-muted">Supplemental rows</div><div className="mt-1 text-lg font-black">{acquisition.data.selected_rows}</div></div>
          <div><div className="text-xs font-black uppercase text-muted">Threat strata</div><div className="mt-1 text-lg font-black">{acquisition.data.represented_threat_strata}</div></div>
          <div><div className="text-xs font-black uppercase text-muted">Evaluation runs</div><div className="mt-1 text-lg font-black">{acquisition.data.evaluation_execution_count}</div></div>
        </div>
      </section>

      <ProgressPanel progress={progress} />

      {progress.closed && progress.combined_support_visible ? (
        <section className="panel" data-testid="supplemental-anchor-combined-support">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="text-sm font-black uppercase tracking-wide text-muted">Combined class support</div>
            <Badge value={progress.combined_support_passed ? "Support Passed" : "Insufficient Support"} />
          </div>
          <div className="mt-4 grid gap-3 sm:grid-cols-3">
            {Object.entries(progress.minimum_class_support).map(([label, target]) => (
              <div key={label} className="min-w-0 border-b border-line pb-3">
                <div className="text-xs font-black uppercase text-muted">{formatFieldName(label)}</div>
                <div className="mt-1 text-lg font-black">{progress.combined_class_support[label] ?? 0}/{target}</div>
              </div>
            ))}
          </div>
        </section>
      ) : null}

      {!progress.prepared || !progress.owned_by_current_user ? (
        <section className="panel" data-testid="supplemental-anchor-review-empty-state">
          <div className="flex items-start gap-3">
            <LockKeyhole className="mt-0.5 shrink-0 text-danger" size={20} />
            <div className="min-w-0 flex-1">
              <EmptyState
                title={progress.owner_assigned && !progress.owned_by_current_user ? "Review assigned" : progress.available ? "Workspace ready" : "Private pack unavailable"}
                body={progress.owner_assigned && !progress.owned_by_current_user ? "Aggregate progress is visible; evidence is restricted to the assigned reviewer." : progress.message}
              />
              {progress.can_review && progress.available ? (
                <button className="btn-primary mt-4 inline-flex items-center gap-2" type="button" onClick={startWorkspace} disabled={start.isPending}>
                  <ClipboardCheck size={16} /> {start.isPending ? "Opening" : "Start supplemental review"}
                </button>
              ) : null}
            </div>
          </div>
          {start.isError ? <div className="mt-4"><ErrorBanner error={start.error} fallback="Unable to start the supplemental review." /></div> : null}
        </section>
      ) : null}

      {progress.prepared && progress.owned_by_current_user ? (
        <>
          <section className="panel" data-testid="supplemental-anchor-review-filters">
            <div className="grid gap-4 sm:grid-cols-2">
              <label className="text-sm font-bold">
                Evidence stratum
                <SafeSelect
                  ariaLabel="Supplemental anchor evidence stratum"
                  className="mt-2"
                  value={coverageStratum}
                  options={[{ value: "", label: "All strata" }, ...progress.coverage_strata.map((value) => ({ value, label: formatFieldName(value) }))]}
                  onChange={setCoverageStratum}
                />
              </label>
              <label className="text-sm font-bold">
                Review state
                <SafeSelect
                  ariaLabel="Supplemental anchor review state"
                  className="mt-2"
                  value={reviewState}
                  options={[{ value: "all", label: "All rows" }, { value: "pending", label: "Pending" }, { value: "reviewed", label: "Reviewed" }]}
                  onChange={setReviewState}
                />
              </label>
            </div>
            {items.isError ? <div className="mt-4"><ErrorBanner error={items.error} fallback="Unable to filter supplemental items." /></div> : null}
            {items.data ? (
              <div className="mt-4">
                <div className="flex flex-wrap gap-2" data-testid="supplemental-anchor-item-list">
                  {items.data.items.map((entry) => (
                    <button key={entry.row_index} type="button" className={entry.row_index === rowIndex ? "btn-primary" : "btn-secondary"} onClick={() => setRowIndex(entry.row_index)}>
                      {entry.display_position} {entry.reviewed ? "Reviewed" : "Pending"}
                    </button>
                  ))}
                </div>
                <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-sm text-muted">
                  <span>{items.data.filtered_total} matching rows</span>
                  <div className="flex gap-2">
                    <button className="btn-secondary" type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 20))}>Previous page</button>
                    <button className="btn-secondary" type="button" disabled={offset + 20 >= items.data.filtered_total} onClick={() => setOffset(offset + 20)}>Next page</button>
                  </div>
                </div>
              </div>
            ) : null}
          </section>

          {progress.completed && !progress.closed ? (
            <section className="panel flex flex-wrap items-center justify-between gap-4" data-testid="supplemental-anchor-review-complete">
              <div className="flex items-start gap-3">
                <CheckCircle2 className="mt-0.5 text-success" size={20} />
                <div><div className="font-black">All decisions are valid</div><div className="mt-1 text-sm text-muted">Close to make them immutable. Aggregate readiness appears only after closure.</div></div>
              </div>
              <button className="btn-secondary" type="button" disabled={close.isPending} onClick={closeWorkspace}>{close.isPending ? "Closing" : "Close review"}</button>
              {close.isError ? <ErrorBanner error={close.error} fallback="Unable to close this supplemental review." /> : null}
            </section>
          ) : null}

          {item.isLoading ? <LoadingPanel label="Loading approved supplemental evidence" /> : null}
          {item.isError ? <ErrorBanner error={item.error} fallback="Unable to open this supplemental item." /> : null}
          {item.data ? <SupplementalThreatAnchorWorkspace item={item.data} onNavigate={setRowIndex} onSaved={handleSaved} /> : null}
        </>
      ) : null}
    </div>
  );
}

type ReviewTab = EvidenceReviewWorkspace | "manual_anchors" | "supplemental_threat_anchors";

export function EvidenceReviewPage() {
  const [activeWorkspace, setActiveWorkspace] = useState<ReviewTab>("detection");
  const [rowIndexes, setRowIndexes] = useState<Record<EvidenceReviewWorkspace, number | null>>({ detection: null, assistant: null });
  const [workflowNotice, setWorkflowNotice] = useState("");
  const workflowDefaultApplied = useRef(false);
  const status = useEvidenceReviewStatus();
  const evaluation = useFrozenEvaluationStatus();
  const start = useStartEvidenceReviewMutation();
  const complete = useCompleteEvidenceReviewMutation();
  const standardWorkspace = activeWorkspace === "detection" || activeWorkspace === "assistant" ? activeWorkspace : null;
  const progress = standardWorkspace ? status.data?.[standardWorkspace] : undefined;
  const detectionItem = useDetectionReviewItem(rowIndexes.detection, activeWorkspace === "detection" && Boolean(status.data?.detection.owned_by_current_user));
  const assistantItem = useAssistantReviewItem(rowIndexes.assistant, activeWorkspace === "assistant" && Boolean(status.data?.assistant.owned_by_current_user));
  const itemQuery = activeWorkspace === "detection" ? detectionItem : assistantItem;

  useEffect(() => {
    if (!standardWorkspace || !progress?.owned_by_current_user || !progress.prepared || progress.total <= 0) return;
    const workspace = standardWorkspace;
    setRowIndexes((current) => {
      if (current[workspace] !== null) return current;
      return { ...current, [workspace]: progress.next_pending_index ?? 0 };
    });
  }, [progress, standardWorkspace]);

  useEffect(() => {
    if (!standardWorkspace || workflowDefaultApplied.current || !status.data) return;
    workflowDefaultApplied.current = true;
    if (status.data.detection.closed && !status.data.assistant.closed) {
      setActiveWorkspace("assistant");
      setWorkflowNotice("Detection review is closed. Complete Assistant Acceptance to unlock the frozen evaluation.");
    }
  }, [standardWorkspace, status.data]);

  useEffect(() => {
    if (!progress?.completed || progress.closed) return;
    const label = standardWorkspace === "detection" ? "Detection review" : "Assistant Acceptance";
    setWorkflowNotice(`${label} is saved and valid. Select Close review to seal this workspace.`);
  }, [progress?.closed, progress?.completed, standardWorkspace]);

  async function startWorkspace() {
    if (!standardWorkspace) return;
    const result = await start.mutateAsync(standardWorkspace);
    const rowIndex = result.next_item?.row_index ?? result.progress.next_pending_index ?? (result.progress.total ? 0 : null);
    setRowIndexes((current) => ({ ...current, [standardWorkspace]: rowIndex }));
  }

  function handleSaved(result: EvidenceReviewOperation) {
    if (!standardWorkspace) return;
    const rowIndex = result.next_item?.row_index ?? result.progress.next_pending_index;
    if (rowIndex !== null && rowIndex !== undefined) {
      setRowIndexes((current) => ({ ...current, [standardWorkspace]: rowIndex }));
    }
  }

  async function completeWorkspace() {
    if (!standardWorkspace) return;
    const item = itemQuery.data;
    if (!item || !window.confirm("Close this completed human review workspace?")) return;
    const completedWorkspace = standardWorkspace;
    const result = await complete.mutateAsync({ workspace: completedWorkspace, revision: item.revision });
    if (completedWorkspace === "detection" && result.progress.closed) {
      setActiveWorkspace("assistant");
      setWorkflowNotice("Detection review is closed. Complete Assistant Acceptance to unlock the frozen evaluation.");
    } else if (completedWorkspace === "assistant" && result.progress.closed) {
      setWorkflowNotice("Both evidence workspaces are closed. Run the frozen evaluation preflight before the one-time evaluation.");
    }
  }

  const canStart = Boolean(progress?.can_review && (activeWorkspace === "assistant" || progress.available));
  const currentItem = itemQuery.data;

  return (
    <div className="min-w-0 space-y-5" data-testid="evidence-review-page">
      <SocPageHeader
        eyebrow="Independent Acceptance"
        title="Evidence Review"
        description="Record independent human decisions against sealed evidence contracts."
        icon={<ClipboardCheck size={18} />}
        badges={["Human Decisions Only", "Predictions Withheld", "No Auto Import", "No Model Activation"]}
        compact
      />

      <div className="flex gap-2 overflow-x-auto border-b border-line" role="tablist" aria-label="Evidence review workspace">
        {(["manual_anchors", "supplemental_threat_anchors", "detection", "assistant"] as ReviewTab[]).map((workspace) => {
          const workspaceProgress = workspace === "detection" || workspace === "assistant" ? status.data?.[workspace] : undefined;
          return (
            <button
              key={workspace}
              type="button"
              role="tab"
              aria-selected={activeWorkspace === workspace}
              className={`inline-flex items-center gap-2 whitespace-nowrap border-b-2 px-4 py-3 text-sm font-black ${activeWorkspace === workspace ? "border-danger text-danger" : "border-transparent text-muted hover:text-text"}`}
              onClick={() => {
                setActiveWorkspace(workspace);
                setWorkflowNotice("");
              }}
            >
              <span>{workspace === "manual_anchors" ? "Manual Anchors" : workspace === "supplemental_threat_anchors" ? "Supplemental Threat Anchors" : workspace === "detection" ? "Detection Blind Review" : "Assistant Acceptance"}</span>
              {workspaceProgress ? (
                <span className="text-xs font-bold" data-testid={`${workspace}-tab-progress`}>
                  {workspaceProgress.reviewed}/{workspaceProgress.total}{workspaceProgress.closed ? " Closed" : ""}
                </span>
              ) : null}
            </button>
          );
        })}
      </div>

      {activeWorkspace === "manual_anchors" ? <ManualAnchorReviewPanel /> : null}
      {activeWorkspace === "supplemental_threat_anchors" ? <SupplementalThreatAnchorReviewPanel /> : null}

      {standardWorkspace && workflowNotice ? <div className="panel py-3 text-sm font-semibold" role="status" data-testid="evidence-review-workflow-notice">{workflowNotice}</div> : null}

      {standardWorkspace && status.isLoading ? <LoadingPanel label="Loading evidence review status" /> : null}
      {standardWorkspace && status.isError ? <ErrorBanner error={status.error} fallback="Unable to load the protected review status." /> : null}
      {standardWorkspace && evaluation.isError ? <ErrorBanner error={evaluation.error} fallback="Unable to load frozen evaluation status." /> : null}
      {standardWorkspace && evaluation.data ? <FrozenEvaluationPanel evaluation={evaluation.data} /> : null}
      {progress ? <ProgressPanel progress={progress} /> : null}

      {progress?.completed && !progress.closed && currentItem ? (
        <section className="panel flex flex-wrap items-center justify-between gap-4" data-testid={`${activeWorkspace}-review-complete`}>
          <div className="flex items-start gap-3">
            <CheckCircle2 className="mt-0.5 text-success" size={20} />
            <div>
              <div className="font-black">All review items are valid</div>
              <div className="mt-1 text-sm text-muted">Close the workspace to make this review eligible for the separate one-time evaluation. No labels, models, or responses are changed.</div>
            </div>
          </div>
          <button className="btn-secondary" type="button" disabled={complete.isPending} onClick={completeWorkspace}>{complete.isPending ? "Closing" : "Close review"}</button>
          {complete.isError ? <ErrorBanner error={complete.error} fallback="Unable to close this review workspace." /> : null}
        </section>
      ) : null}

      {progress && (!progress.prepared || !progress.owned_by_current_user) ? (
        <section className="panel" data-testid={`${activeWorkspace}-review-empty-state`}>
          <div className="flex items-start gap-3">
            <LockKeyhole className="mt-0.5 shrink-0 text-danger" size={20} />
            <div className="min-w-0 flex-1">
              <EmptyState
                title={progress.owner_assigned && !progress.owned_by_current_user ? "Review assigned" : progress.available || activeWorkspace === "assistant" ? "Workspace ready" : "Private pack unavailable"}
                body={progress.owner_assigned && !progress.owned_by_current_user ? "Aggregate progress is visible, but evidence is restricted to the assigned reviewer." : progress.message}
              />
              {canStart ? (
                <button className="btn-primary mt-4 inline-flex items-center gap-2" type="button" onClick={startWorkspace} disabled={start.isPending}>
                  <ClipboardCheck size={16} /> {start.isPending ? "Opening" : progress.prepared ? "Resume review" : "Start review"}
                </button>
              ) : null}
            </div>
          </div>
          {start.isError ? <div className="mt-4"><ErrorBanner error={start.error} fallback="Unable to open this review workspace." /></div> : null}
        </section>
      ) : null}

      {progress?.prepared && progress.owned_by_current_user && itemQuery.isLoading ? <LoadingPanel label="Loading protected evidence" /> : null}
      {itemQuery.isError ? <ErrorBanner error={itemQuery.error} fallback="Unable to open this protected review item." /> : null}
      {activeWorkspace === "detection" && currentItem?.workspace === "detection" ? (
        <DetectionWorkspace
          item={currentItem}
          onNavigate={(rowIndex) => setRowIndexes((current) => ({ ...current, detection: rowIndex }))}
          onSaved={handleSaved}
        />
      ) : null}
      {activeWorkspace === "assistant" && currentItem?.workspace === "assistant" ? (
        <AssistantWorkspace
          item={currentItem}
          onNavigate={(rowIndex) => setRowIndexes((current) => ({ ...current, assistant: rowIndex }))}
          onSaved={handleSaved}
        />
      ) : null}
    </div>
  );
}
