import type { ReactNode } from "react";
import clsx from "clsx";
import { Badge } from "./Badge";

type EyebrowTone = "cyan" | "danger";
type BadgePlacement = "aside" | "under-title";

interface SocPageHeaderProps {
  eyebrow: string;
  title: string;
  description?: string;
  icon?: ReactNode;
  badges?: string[];
  badgePlacement?: BadgePlacement;
  actions?: ReactNode;
  context?: ReactNode;
  compact?: boolean;
  eyebrowTone?: EyebrowTone;
}

function HeaderBadges({ values }: { values: string[] }) {
  return (
    <div className="flex flex-wrap gap-2">
      {values.map((value) => (
        <Badge key={value} value={value} />
      ))}
    </div>
  );
}

export function SocPageHeader({
  eyebrow,
  title,
  description,
  icon,
  badges = [],
  badgePlacement = "aside",
  actions,
  context,
  compact = false,
  eyebrowTone = "danger"
}: SocPageHeaderProps) {
  const asideBadges = badgePlacement === "aside" ? badges : [];
  const titleBadges = badgePlacement === "under-title" ? badges : [];

  return (
    <section className="hero-panel">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div
            className={clsx(
              "flex items-center gap-2 text-sm font-black uppercase tracking-[0.18em]",
              eyebrowTone === "cyan" ? "text-cyan" : "text-danger"
            )}
          >
            {icon}
            {eyebrow}
          </div>
          <h1 className={clsx("mt-2 font-black", compact ? "text-2xl" : "text-3xl")}>{title}</h1>
          {description ? <p className="mt-2 max-w-3xl text-sm font-semibold text-muted">{description}</p> : null}
          {context}
          {titleBadges.length ? (
            <div className="mt-3">
              <HeaderBadges values={titleBadges} />
            </div>
          ) : null}
        </div>
        {actions || asideBadges.length ? (
          <div className="flex flex-wrap items-center justify-end gap-2">
            {asideBadges.length ? <HeaderBadges values={asideBadges} /> : null}
            {actions}
          </div>
        ) : null}
      </div>
    </section>
  );
}
