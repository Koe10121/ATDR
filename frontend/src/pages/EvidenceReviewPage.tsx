import { FormEvent, useEffect, useMemo, useState } from "react";
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
  useCompleteEvidenceReviewMutation,
  useDetectionReviewItem,
  useEvidenceReviewStatus,
  useSaveAssistantReviewMutation,
  useSaveDetectionReviewMutation,
  useStartEvidenceReviewMutation
} from "../hooks/useApiQueries";
import type {
  AssistantReviewItem,
  AssistantReviewScores,
  DetectionReviewDecision,
  DetectionReviewDecisionGroup,
  DetectionReviewItem,
  EvidenceReviewOperation,
  EvidenceReviewProgress,
  EvidenceReviewWorkspace
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

function ProgressPanel({ progress }: { progress: EvidenceReviewProgress }) {
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
        <div className="mt-4 h-2 overflow-hidden rounded-full bg-line" aria-label={`${progress.progress_percent}% complete`}>
          <div className="h-full bg-teal transition-all" style={{ width: `${Math.min(100, progress.progress_percent)}%` }} />
        </div>
      </section>
    </>
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

export function EvidenceReviewPage() {
  const [activeWorkspace, setActiveWorkspace] = useState<EvidenceReviewWorkspace>("detection");
  const [rowIndexes, setRowIndexes] = useState<Record<EvidenceReviewWorkspace, number | null>>({ detection: null, assistant: null });
  const status = useEvidenceReviewStatus();
  const start = useStartEvidenceReviewMutation();
  const complete = useCompleteEvidenceReviewMutation();
  const progress = status.data?.[activeWorkspace];
  const detectionItem = useDetectionReviewItem(rowIndexes.detection, activeWorkspace === "detection" && Boolean(status.data?.detection.owned_by_current_user));
  const assistantItem = useAssistantReviewItem(rowIndexes.assistant, activeWorkspace === "assistant" && Boolean(status.data?.assistant.owned_by_current_user));
  const itemQuery = activeWorkspace === "detection" ? detectionItem : assistantItem;

  useEffect(() => {
    if (!progress?.owned_by_current_user || !progress.prepared || progress.total <= 0) return;
    setRowIndexes((current) => {
      if (current[activeWorkspace] !== null) return current;
      return { ...current, [activeWorkspace]: progress.next_pending_index ?? 0 };
    });
  }, [activeWorkspace, progress]);

  async function startWorkspace() {
    const result = await start.mutateAsync(activeWorkspace);
    const rowIndex = result.next_item?.row_index ?? result.progress.next_pending_index ?? (result.progress.total ? 0 : null);
    setRowIndexes((current) => ({ ...current, [activeWorkspace]: rowIndex }));
  }

  function handleSaved(result: EvidenceReviewOperation) {
    const rowIndex = result.next_item?.row_index ?? result.progress.next_pending_index;
    if (rowIndex !== null && rowIndex !== undefined) {
      setRowIndexes((current) => ({ ...current, [activeWorkspace]: rowIndex }));
    }
  }

  async function completeWorkspace() {
    const item = itemQuery.data;
    if (!item || !window.confirm("Close this completed human review workspace?")) return;
    await complete.mutateAsync({ workspace: activeWorkspace, revision: item.revision });
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
        {(["detection", "assistant"] as EvidenceReviewWorkspace[]).map((workspace) => (
          <button
            key={workspace}
            type="button"
            role="tab"
            aria-selected={activeWorkspace === workspace}
            className={`whitespace-nowrap border-b-2 px-4 py-3 text-sm font-black ${activeWorkspace === workspace ? "border-danger text-danger" : "border-transparent text-muted hover:text-text"}`}
            onClick={() => setActiveWorkspace(workspace)}
          >
            {workspace === "detection" ? "Detection Blind Review" : "Assistant Acceptance"}
          </button>
        ))}
      </div>

      {status.isLoading ? <LoadingPanel label="Loading evidence review status" /> : null}
      {status.isError ? <ErrorBanner error={status.error} fallback="Unable to load the protected review status." /> : null}
      {progress ? <ProgressPanel progress={progress} /> : null}

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

      {progress?.completed && currentItem ? (
        <section className="panel flex flex-wrap items-center justify-between gap-4" data-testid={`${activeWorkspace}-review-complete`}>
          <div className="flex items-start gap-3">
            <CheckCircle2 className="mt-0.5 text-success" size={20} />
            <div>
              <div className="font-black">All review items are valid</div>
              <div className="mt-1 text-sm text-muted">Closing records completion only. It does not import labels, tune a model, or execute a response.</div>
            </div>
          </div>
          <button className="btn-secondary" type="button" disabled={complete.isPending} onClick={completeWorkspace}>{complete.isPending ? "Closing" : "Close review"}</button>
          {complete.isError ? <ErrorBanner error={complete.error} fallback="Unable to close this review workspace." /> : null}
        </section>
      ) : null}
    </div>
  );
}
