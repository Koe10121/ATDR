import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  Database,
  LockKeyhole,
  Save,
  ShieldCheck
} from "lucide-react";
import {
  useCloseSupervisedExpansionReviewMutation,
  useSaveSupervisedExpansionReviewMutation,
  useStartSupervisedExpansionReviewMutation,
  useSupervisedExpansionReviewItem,
  useSupervisedExpansionReviewItems,
  useSupervisedExpansionReviewStatus,
  useSupervisedExpansionStatus
} from "../hooks/useApiQueries";
import type {
  DetectionReviewDecision,
  SupervisedExpansionBatchProgress,
  SupervisedExpansionReviewItem,
  SupervisedExpansionReviewOperation
} from "../types/api";
import { Badge } from "./Badge";
import { ErrorBanner } from "./ErrorBanner";
import { LoadingPanel } from "./LoadingPanel";
import { MetricCard } from "./MetricCard";
import { SafeSelect } from "./SafeSelect";

const decisionOptions = [
  { value: "", label: "Select final decision" },
  { value: "benign", label: "Benign" },
  { value: "benign_unusual", label: "Benign unusual" },
  { value: "needs_context", label: "Needs context" },
  { value: "suspicious", label: "Suspicious" },
  { value: "malicious", label: "Malicious" }
];

function formatName(value: string): string {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function BatchReviewForm({
  item,
  onSaved
}: {
  item: SupervisedExpansionReviewItem;
  onSaved: (result: SupervisedExpansionReviewOperation) => void;
}) {
  const save = useSaveSupervisedExpansionReviewMutation();
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
      batchId: item.batch_id,
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
    <section className="panel min-w-0" data-testid="expansion-review-form">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="text-sm font-black uppercase tracking-wide text-muted">Independent decision</div>
        <Badge value={item.closed ? "Closed" : item.reviewed ? "Saved" : "Pending"} />
      </div>
      <form className="mt-4 space-y-4" onSubmit={submit}>
        <label className="block text-sm font-bold">
          Final decision
          <SafeSelect
            ariaLabel="Supplemental qualification final decision"
            className="mt-2"
            disabled={item.closed}
            value={decision}
            options={decisionOptions}
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

export function SupervisedEvidenceExpansionPanel() {
  const campaign = useSupervisedExpansionStatus();
  const review = useSupervisedExpansionReviewStatus();
  const start = useStartSupervisedExpansionReviewMutation();
  const close = useCloseSupervisedExpansionReviewMutation();
  const [batchId, setBatchId] = useState("");
  const [rowIndex, setRowIndex] = useState<number | null>(null);
  const [reviewState, setReviewState] = useState("all");
  const [offset, setOffset] = useState(0);
  const progress = review.data;
  const selectedBatch = progress?.batches.find((batch) => batch.batch_id === batchId);
  const canOpen = Boolean(selectedBatch?.owned_by_current_user);
  const pageParams = useMemo(
    () => ({ offset, limit: 20, review_state: reviewState }),
    [offset, reviewState]
  );
  const items = useSupervisedExpansionReviewItems(batchId, pageParams, canOpen);
  const item = useSupervisedExpansionReviewItem(batchId, rowIndex, canOpen);

  useEffect(() => {
    if (!progress?.batches.length) return;
    setBatchId((current) => current || progress.batches[0].batch_id);
  }, [progress]);

  useEffect(() => {
    setOffset(0);
    setRowIndex(selectedBatch?.next_pending_index ?? null);
  }, [batchId, selectedBatch?.next_pending_index]);

  async function startBatch(batch: SupervisedExpansionBatchProgress) {
    const result = await start.mutateAsync(batch.batch_id);
    setBatchId(batch.batch_id);
    setRowIndex(result.next_item?.row_index ?? null);
  }

  function handleSaved(result: SupervisedExpansionReviewOperation) {
    setRowIndex(result.next_item?.row_index ?? null);
  }

  async function closeBatch() {
    if (!selectedBatch) return;
    if (!window.confirm("Close this completed batch? Its decisions will become immutable.")) return;
    await close.mutateAsync({
      batchId: selectedBatch.batch_id,
      revision: selectedBatch.revision
    });
  }

  if (campaign.isLoading || review.isLoading) return <LoadingPanel label="Loading fresh evidence expansion" />;
  if (campaign.isError) return <ErrorBanner error={campaign.error} fallback="Unable to validate the evidence expansion." />;
  if (review.isError) return <ErrorBanner error={review.error} fallback="Unable to load supplemental review progress." />;
  if (!campaign.data || !progress) return null;

  const evidence = campaign.data.evidence ?? {};
  return (
    <div className="space-y-4" data-testid="supervised-evidence-expansion-panel">
      <section className="panel" data-testid="expansion-campaign-summary">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="text-sm font-black uppercase tracking-wide text-muted">Fresh comparable evidence expansion</div>
            <div className="mt-1 text-sm text-muted">The original 300-row boundary is preserved. Supplemental rows are prediction-blind, development-only, and reviewed in immutable batches.</div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Badge value="Append Only" />
            <Badge value="Evaluation Sealed" />
            <Badge value="Supervised Unqualified" />
          </div>
        </div>
        <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          <MetricCard label="Comparable capacity" value={campaign.data.protocol.total_comparable_capacity} detail="300 original + 700 supplemental" tone="teal" />
          <MetricCard label="Supplemental" value={campaign.data.protocol.supplemental_rows} detail="Development-safe rows" tone="amber" />
          <MetricCard label="Review batches" value={campaign.data.protocol.batch_count} detail={`${progress.closed_batch_count} closed`} tone="slate" />
          <MetricCard label="Real sources" value={`${evidence.real_source_identities ?? 0}/2`} detail="Second device required" tone="danger" />
          <MetricCard label="Time windows" value={evidence.independent_time_windows ?? 0} detail="Chronological support" tone="success" />
        </div>
      </section>

      <section className="panel" data-testid="expansion-safety-contract">
        <div className="flex items-start gap-3">
          <ShieldCheck className="mt-0.5 shrink-0 text-success" size={20} />
          <div>
            <div className="font-black">Qualification remains evidence-gated</div>
            <div className="mt-1 text-sm text-muted">No prediction hints, automated labels, training, evaluation, model activation, alert changes, or response actions occur in this phase.</div>
          </div>
        </div>
      </section>

      {!progress.available ? (
        <section className="panel" data-testid="expansion-unavailable">
          <div className="flex items-start gap-3">
            <Database className="mt-0.5 shrink-0 text-muted" size={20} />
            <div><div className="font-black">Supplemental pack not prepared</div><div className="mt-1 text-sm text-muted">{progress.message}</div></div>
          </div>
        </section>
      ) : (
        <>
          <section className="panel" data-testid="expansion-batch-selector">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div><div className="font-black">Protected review batches</div><div className="mt-1 text-sm text-muted">{progress.reviewed}/{progress.total} supplemental decisions complete. Total campaign capacity: {progress.combined_total}.</div></div>
              <Badge value={`${progress.progress_percent}%`} />
            </div>
            <div className="mt-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
              {progress.batches.map((batch) => (
                <button
                  key={batch.batch_id}
                  type="button"
                  className={batch.batch_id === batchId ? "btn-primary min-h-12 justify-between" : "btn-secondary min-h-12 justify-between"}
                  onClick={() => {
                    setBatchId(batch.batch_id);
                    setRowIndex(batch.next_pending_index ?? null);
                  }}
                >
                  <span>{formatName(batch.batch_id)}</span>
                  <span>{batch.reviewed}/{batch.total}{batch.closed ? " Closed" : ""}</span>
                </button>
              ))}
            </div>
          </section>

          {selectedBatch && !selectedBatch.owned_by_current_user ? (
            <section className="panel" data-testid="expansion-batch-access">
              <div className="flex items-start gap-3">
                <LockKeyhole className="mt-0.5 shrink-0 text-danger" size={20} />
                <div className="min-w-0 flex-1">
                  <div className="font-black">{selectedBatch.owner_assigned ? "Batch assigned" : "Batch ready"}</div>
                  <div className="mt-1 text-sm text-muted">{selectedBatch.owner_assigned ? "Only the assigned reviewer can open this evidence." : "Start this batch to bind it to your authenticated account."}</div>
                  {selectedBatch.can_review ? (
                    <button className="btn-primary mt-4" type="button" disabled={start.isPending} onClick={() => startBatch(selectedBatch)}>
                      {start.isPending ? "Opening" : "Start protected batch"}
                    </button>
                  ) : null}
                </div>
              </div>
              {start.isError ? <div className="mt-4"><ErrorBanner error={start.error} fallback="Unable to start this review batch." /></div> : null}
            </section>
          ) : null}

          {selectedBatch?.owned_by_current_user ? (
            <>
              <section className="panel" data-testid="expansion-review-navigation">
                <div className="flex flex-wrap items-end justify-between gap-4">
                  <label className="w-full max-w-64 text-sm font-bold">
                    Review state
                    <SafeSelect
                      ariaLabel="Supplemental review state"
                      className="mt-2"
                      value={reviewState}
                      options={[{ value: "all", label: "All rows" }, { value: "pending", label: "Pending" }, { value: "reviewed", label: "Reviewed" }]}
                      onChange={(value) => { setReviewState(value); setOffset(0); }}
                    />
                  </label>
                  <div className="text-sm font-semibold text-muted">{selectedBatch.reviewed}/{selectedBatch.total} reviewed</div>
                </div>
                {items.isError ? <div className="mt-4"><ErrorBanner error={items.error} fallback="Unable to list this review batch." /></div> : null}
                {items.data ? (
                  <div className="mt-4">
                    <div className="flex flex-wrap gap-2" data-testid="expansion-item-list">
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

              {selectedBatch.completed && !selectedBatch.closed ? (
                <section className="panel flex flex-wrap items-center justify-between gap-4" data-testid="expansion-batch-complete">
                  <div className="flex items-start gap-3"><CheckCircle2 className="mt-0.5 text-success" size={20} /><div><div className="font-black">Batch decisions are valid</div><div className="mt-1 text-sm text-muted">Close this batch to make its decisions immutable.</div></div></div>
                  <button className="btn-secondary" type="button" disabled={close.isPending} onClick={closeBatch}>{close.isPending ? "Closing" : "Close batch"}</button>
                  {close.isError ? <ErrorBanner error={close.error} fallback="Unable to close this batch." /> : null}
                </section>
              ) : null}

              {item.isLoading ? <LoadingPanel label="Loading approved supplemental evidence" /> : null}
              {item.isError ? <ErrorBanner error={item.error} fallback="Unable to open supplemental evidence." /> : null}
              {item.data ? (
                <div className="grid min-w-0 gap-4 xl:grid-cols-[1.05fr_0.95fr]" data-testid="expansion-review-workspace">
                  <section className="panel min-w-0" data-testid="expansion-approved-evidence">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div className="text-sm font-black uppercase tracking-wide text-muted">Approved evidence</div>
                      <div className="flex flex-wrap gap-2"><Badge value={formatName(item.data.evidence_role)} /><Badge value={formatName(item.data.coverage_group)} /><Badge value="Predictions Withheld" /></div>
                    </div>
                    <div className="mt-3 text-sm font-black">Item {item.data.display_position} of {item.data.total}</div>
                    <dl className="mt-4 grid gap-x-6 gap-y-3 sm:grid-cols-2" data-testid="expansion-evidence-fields">
                      {Object.entries(item.data.evidence).map(([key, value]) => (
                        <div key={key} className="min-w-0 border-b border-line pb-2">
                          <dt className="text-xs font-black uppercase tracking-wide text-muted">{formatName(key)}</dt>
                          <dd className="mt-1 break-words text-sm font-semibold text-text">{value}</dd>
                        </div>
                      ))}
                    </dl>
                  </section>
                  <BatchReviewForm item={item.data} onSaved={handleSaved} />
                </div>
              ) : null}
            </>
          ) : null}
        </>
      )}
    </div>
  );
}
