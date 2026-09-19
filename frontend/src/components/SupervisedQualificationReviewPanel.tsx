import { useEffect, useMemo, useState } from "react";
import {
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  ClipboardCheck,
  LockKeyhole,
  ShieldCheck
} from "lucide-react";
import {
  useCloseSupervisedQualificationReviewMutation,
  useSaveSupervisedQualificationReviewMutation,
  useStartSupervisedQualificationReviewMutation,
  useSupervisedQualificationReviewItem,
  useSupervisedQualificationReviewItems,
  useSupervisedQualificationReviewStatus,
  useSupervisedQualificationStatus
} from "../hooks/useApiQueries";
import type { SupervisedQualificationReviewItem, SupervisedQualificationReviewOperation } from "../types/api";
import { Badge } from "./Badge";
import { EmptyState } from "./EmptyState";
import { ErrorBanner } from "./ErrorBanner";
import { IndependentDecisionForm } from "./IndependentDecisionForm";
import { LoadingPanel } from "./LoadingPanel";
import { MetricCard } from "./MetricCard";
import { SafeSelect } from "./SafeSelect";

function formatName(value: string): string {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function gateStatus(
  gate: Record<string, unknown> | undefined
): { observed: string; threshold: string; passed: boolean } {
  return {
    observed: gate?.observed === null || gate?.observed === undefined ? "Sealed" : String(gate.observed),
    threshold: gate?.threshold === undefined ? "Fixed gate" : String(gate.threshold),
    passed: gate?.status === "pass"
  };
}

function ReviewForm({
  item,
  onSaved
}: {
  item: SupervisedQualificationReviewItem;
  onSaved: (result: SupervisedQualificationReviewOperation) => void;
}) {
  const save = useSaveSupervisedQualificationReviewMutation();
  return (
    <IndependentDecisionForm
      item={item}
      onSaved={onSaved}
      onSubmit={(payload) => save.mutateAsync({ rowIndex: item.row_index, payload })}
      isPending={save.isPending}
      isError={save.isError}
      error={save.error}
      errorFallback="Unable to save this qualification decision."
      decisionAriaLabel="Supervised qualification final decision"
      testId="qualification-review-form"
    />
  );
}

export function SupervisedQualificationReviewPanel() {
  const [rowIndex, setRowIndex] = useState<number | null>(null);
  const [role, setRole] = useState("");
  const [coverageGroup, setCoverageGroup] = useState("");
  const [reviewState, setReviewState] = useState("all");
  const [offset, setOffset] = useState(0);
  const campaign = useSupervisedQualificationStatus();
  const status = useSupervisedQualificationReviewStatus();
  const start = useStartSupervisedQualificationReviewMutation();
  const close = useCloseSupervisedQualificationReviewMutation();
  const progress = status.data;
  const canOpen = Boolean(progress?.prepared && progress.owned_by_current_user);
  const item = useSupervisedQualificationReviewItem(rowIndex, canOpen);
  const pageParams = useMemo(
    () => ({
      offset,
      limit: 20,
      review_state: reviewState,
      ...(role ? { evidence_role: role } : {}),
      ...(coverageGroup ? { coverage_group: coverageGroup } : {})
    }),
    [coverageGroup, offset, reviewState, role]
  );
  const items = useSupervisedQualificationReviewItems(pageParams, canOpen);

  useEffect(() => {
    if (!canOpen || !progress?.total) return;
    setRowIndex((current) => current ?? progress.next_pending_index ?? 0);
  }, [canOpen, progress]);

  useEffect(() => {
    setOffset(0);
  }, [coverageGroup, reviewState, role]);

  async function startWorkspace() {
    const result = await start.mutateAsync();
    setRowIndex(result.next_item?.row_index ?? result.progress.next_pending_index ?? 0);
  }

  function handleSaved(result: SupervisedQualificationReviewOperation) {
    setRowIndex(result.next_item?.row_index ?? result.progress.next_pending_index ?? rowIndex);
  }

  async function closeWorkspace() {
    if (!progress || !window.confirm("Close this completed qualification review? Saved decisions will become immutable.")) return;
    await close.mutateAsync(progress.revision);
  }

  if (status.isLoading || campaign.isLoading) return <LoadingPanel label="Loading supervised qualification workspace" />;
  if (status.isError) return <ErrorBanner error={status.error} fallback="Unable to load qualification review status." />;
  if (campaign.isError) return <ErrorBanner error={campaign.error} fallback="Unable to validate qualification campaign custody." />;
  if (!progress || !campaign.data) return null;

  const sourceGate = gateStatus(campaign.data.qualification_gates.real_source_identities as Record<string, unknown> | undefined);
  const timeGate = gateStatus(campaign.data.qualification_gates.independent_time_windows as Record<string, unknown> | undefined);

  return (
    <div className="space-y-4" data-testid="supervised-qualification-review-panel">
      <section className="panel" data-testid="qualification-campaign-status">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="text-sm font-black uppercase tracking-wide text-muted">Fresh evidence qualification campaign</div>
            <div className="mt-1 text-sm text-muted">Consumed evidence is excluded. Evaluation labels stay sealed and no model runs automatically.</div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Badge value="Supervised Unqualified" />
            <Badge value="Rules Authoritative" />
            <Badge value="Simulation Only" />
          </div>
        </div>
        <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <div><div className="text-xs font-black uppercase text-muted">Fresh review rows</div><div className="mt-1 text-lg font-black">{campaign.data.protocol.selected_rows}</div></div>
          <div><div className="text-xs font-black uppercase text-muted">Locked strategies</div><div className="mt-1 text-lg font-black">{campaign.data.protocol.strategy_count}</div></div>
          <div><div className="text-xs font-black uppercase text-muted">Real sources</div><div className="mt-1 text-sm font-black">{sourceGate.observed} / {sourceGate.threshold} {sourceGate.passed ? "Passed" : "Required"}</div></div>
          <div><div className="text-xs font-black uppercase text-muted">Time windows</div><div className="mt-1 text-sm font-black">{timeGate.observed} / {timeGate.threshold} {timeGate.passed ? "Passed" : "Required"}</div></div>
        </div>
      </section>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4" data-testid="supervised_qualification-review-metrics">
        <MetricCard label="Reviewed" value={`${progress.reviewed}/${progress.total}`} detail="Independent decisions" tone="teal" />
        <MetricCard label="Remaining" value={progress.remaining} detail="Pending review" tone="amber" />
        <MetricCard label="Integrity" value={formatName(progress.integrity_status)} detail="Protected contract" tone={progress.integrity_status === "valid" ? "success" : "amber"} />
        <MetricCard label="Invalid" value={progress.invalid} detail="Must remain zero" tone={progress.invalid ? "danger" : "slate"} />
      </div>

      <section className="panel" data-testid="qualification-review-progress">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="text-sm font-black">Review progress</div>
            <div className="mt-1 text-sm text-muted">{progress.message}</div>
          </div>
          <Badge value={`${progress.progress_percent}%`} />
        </div>
        <div className="mt-4 h-2 overflow-hidden rounded-full bg-line" role="progressbar" aria-label="Qualification review progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={progress.progress_percent}>
          <div className="h-full bg-teal transition-all" style={{ width: `${Math.min(100, progress.progress_percent)}%` }} />
        </div>
      </section>

      <section className="panel" data-testid="qualification-safety-contract">
        <div className="flex items-start gap-3">
          <ShieldCheck className="mt-0.5 shrink-0 text-success" size={20} />
          <div>
            <div className="font-black">Prediction-blind evidence contract</div>
            <div className="mt-1 text-sm text-muted">Predictions, model scores, rule recommendations, raw logs, addresses, source identities, and future-evaluation class support are withheld.</div>
          </div>
        </div>
      </section>

      {!progress.prepared || !progress.owned_by_current_user ? (
        <section className="panel" data-testid="qualification-review-empty-state">
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
          {start.isError ? <div className="mt-4"><ErrorBanner error={start.error} fallback="Unable to start qualification review." /></div> : null}
        </section>
      ) : null}

      {canOpen ? (
        <>
          <section className="panel" data-testid="qualification-review-filters">
            <div className="grid gap-4 sm:grid-cols-3">
              <label className="text-sm font-bold">
                Evidence role
                <SafeSelect ariaLabel="Qualification evidence role" className="mt-2" value={role} options={[{ value: "", label: "All roles" }, ...Object.keys(progress.role_counts).map((value) => ({ value, label: formatName(value) }))]} onChange={setRole} />
              </label>
              <label className="text-sm font-bold">
                Coverage group
                <SafeSelect ariaLabel="Qualification coverage group" className="mt-2" value={coverageGroup} options={[{ value: "", label: "All groups" }, ...progress.coverage_groups.map((value) => ({ value, label: formatName(value) }))]} onChange={setCoverageGroup} />
              </label>
              <label className="text-sm font-bold">
                Review state
                <SafeSelect ariaLabel="Qualification review state" className="mt-2" value={reviewState} options={[{ value: "all", label: "All rows" }, { value: "pending", label: "Pending" }, { value: "reviewed", label: "Reviewed" }]} onChange={setReviewState} />
              </label>
            </div>
            {items.isError ? <div className="mt-4"><ErrorBanner error={items.error} fallback="Unable to filter qualification items." /></div> : null}
            {items.data ? (
              <div className="mt-4">
                <div className="flex flex-wrap gap-2" data-testid="qualification-item-list">
                  {items.data.items.map((entry) => (
                    <button key={entry.row_index} type="button" className={entry.row_index === rowIndex ? "btn-primary" : "btn-secondary"} onClick={() => setRowIndex(entry.row_index)}>
                      {entry.display_position} {entry.reviewed ? "Reviewed" : "Pending"}
                    </button>
                  ))}
                </div>
                <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-sm text-muted">
                  <span>{items.data.filtered_total} matching rows</span>
                  <div className="flex gap-2">
                    <button className="btn-secondary inline-flex items-center gap-2" type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 20))}><ArrowLeft size={15} /> Previous</button>
                    <button className="btn-secondary inline-flex items-center gap-2" type="button" disabled={offset + 20 >= items.data.filtered_total} onClick={() => setOffset(offset + 20)}>Next <ArrowRight size={15} /></button>
                  </div>
                </div>
              </div>
            ) : null}
          </section>

          {progress.completed && !progress.closed ? (
            <section className="panel flex flex-wrap items-center justify-between gap-4" data-testid="qualification-review-complete">
              <div className="flex items-start gap-3">
                <CheckCircle2 className="mt-0.5 text-success" size={20} />
                <div><div className="font-black">All decisions are valid</div><div className="mt-1 text-sm text-muted">Close to make decisions immutable. Evaluation and activation remain separate.</div></div>
              </div>
              <button className="btn-secondary" type="button" disabled={close.isPending} onClick={closeWorkspace}>{close.isPending ? "Closing" : "Close review"}</button>
              {close.isError ? <ErrorBanner error={close.error} fallback="Unable to close qualification review." /> : null}
            </section>
          ) : null}

          {item.isLoading ? <LoadingPanel label="Loading approved qualification evidence" /> : null}
          {item.isError ? <ErrorBanner error={item.error} fallback="Unable to open qualification evidence." /> : null}
          {item.data ? (
            <div className="space-y-4" data-testid="qualification-review-workspace">
              <section className="panel flex flex-wrap items-center justify-between gap-3">
                <button className="btn-secondary inline-flex items-center gap-2" type="button" disabled={item.data.row_index <= 0} onClick={() => setRowIndex(item.data.row_index - 1)}><ArrowLeft size={16} /> Previous</button>
                <div className="text-sm font-black">Item {item.data.display_position} of {item.data.total}</div>
                <button className="btn-secondary inline-flex items-center gap-2" type="button" disabled={item.data.row_index >= item.data.total - 1} onClick={() => setRowIndex(item.data.row_index + 1)}>Next <ArrowRight size={16} /></button>
              </section>
              <div className="grid min-w-0 gap-4 xl:grid-cols-[1.05fr_0.95fr]">
                <section className="panel min-w-0" data-testid="qualification-approved-evidence">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="text-sm font-black uppercase tracking-wide text-muted">Approved evidence</div>
                    <div className="flex flex-wrap gap-2"><Badge value={formatName(item.data.evidence_role)} /><Badge value={formatName(item.data.coverage_group)} /><Badge value="Predictions Withheld" /></div>
                  </div>
                  <dl className="mt-4 grid gap-x-6 gap-y-3 sm:grid-cols-2" data-testid="qualification-evidence-fields">
                    {Object.entries(item.data.evidence).map(([key, value]) => (
                      <div key={key} className="min-w-0 border-b border-line pb-2">
                        <dt className="text-xs font-black uppercase tracking-wide text-muted">{formatName(key)}</dt>
                        <dd className="mt-1 break-words text-sm font-semibold text-text">{value}</dd>
                      </div>
                    ))}
                  </dl>
                </section>
                <ReviewForm item={item.data} onSaved={handleSaved} />
              </div>
            </div>
          ) : null}
        </>
      ) : null}
    </div>
  );
}
