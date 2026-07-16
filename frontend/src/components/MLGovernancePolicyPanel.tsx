import { Badge } from "./Badge";
import { MetricCard } from "./MetricCard";
import type { SupervisedModelReport } from "../types/api";

type SocTriageMode = NonNullable<SupervisedModelReport["soc_triage_mode"]>;

interface MLGovernancePolicyPanelProps {
  mode?: SocTriageMode;
}

function displayValue(value: string | undefined, fallback: string) {
  return (value || fallback).replaceAll("_", " ");
}

export function MLGovernancePolicyPanel({ mode }: MLGovernancePolicyPanelProps) {
  const limitations = mode?.limitations ?? [];

  return (
    <section
      className="mt-4 rounded-lg border border-cyan/30 bg-cyan/10 p-4"
      aria-labelledby="ml-operating-policy-title"
      data-testid="ml-governance-policy"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-xs font-extrabold uppercase tracking-wide text-cyan">Current Operating Policy</div>
          <h3 id="ml-operating-policy-title" className="mt-1 text-lg font-black text-text">
            {displayValue(mode?.recommended_ai_mode, "SOC triage decision support")}
          </h3>
          <p className="mt-1 text-sm text-muted">
            Validation metrics come only from the canonical evidence snapshot above.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Badge value="Decision Support Only" />
          <Badge value="Not Production Promoted" />
          <Badge value="Response Automation Disabled" />
        </div>
      </div>

      <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="Primary Signal"
          value={displayValue(mode?.primary_signal, "rule and hybrid evidence")}
          detail="Detection evidence remains authoritative"
          tone="cyan"
        />
        <MetricCard
          label="Supervised Output"
          value={displayValue(mode?.flat_5_class_status, "diagnostic only")}
          detail="Ranking and analyst review support"
          tone="amber"
        />
        <MetricCard
          label="Model Promotion"
          value={mode?.production_promoted ? "Promoted" : "Not promoted"}
          detail="Activation remains a manual governance decision"
          tone={mode?.production_promoted ? "danger" : "teal"}
        />
        <MetricCard
          label="Auto Response"
          value={mode?.response_automation_allowed ? "Enabled" : "Disabled"}
          detail="No containment can be triggered by ML output"
          tone="danger"
        />
      </div>

      {limitations.length ? (
        <details className="mt-3">
          <summary className="cursor-pointer text-sm font-bold text-text">Current limitations</summary>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-muted">
            {limitations.slice(0, 6).map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </details>
      ) : null}
    </section>
  );
}
