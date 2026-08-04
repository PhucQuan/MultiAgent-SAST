import type { ReactNode } from "react";

import { cn } from "@/lib/utils";
import type {
  EvidenceContext,
  ReviewerDisposition,
  Severity,
  TriageStatus,
} from "@/lib/report-types";

const severityLabels: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
  unknown: "Unknown",
};

const severityStyles: Record<Severity, string> = {
  critical: "border-sev-critical/25 bg-sev-critical/10 text-sev-critical",
  high: "border-sev-high/25 bg-sev-high/10 text-sev-high",
  medium: "border-sev-medium/30 bg-sev-medium/12 text-sev-medium",
  low: "border-sev-low/25 bg-sev-low/10 text-sev-low",
  info: "border-sev-info/25 bg-sev-info/10 text-sev-info",
  unknown: "border-border bg-surface-muted text-muted-foreground",
};

const severityDot: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
  unknown: "bg-muted-foreground",
};

const statusLabels: Record<TriageStatus, string> = {
  confirmed: "Confirmed",
  likely: "Likely",
  "needs-review": "Needs review",
  suppressed: "Suppressed",
  unknown: "Unknown",
};

export const dispositionLabels: Record<ReviewerDisposition, string> = {
  confirmed: "Confirmed",
  "needs-review": "Needs review",
  "false-positive": "False positive",
  suppressed: "Suppressed",
};

export function SeverityTag({
  severity,
  className,
}: {
  severity: Severity;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2 py-1 text-[10.5px] font-semibold tracking-wide",
        severityStyles[severity],
        className,
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", severityDot[severity])} />
      {severityLabels[severity]}
    </span>
  );
}

export function StatusTag({
  status,
  className,
}: {
  status: TriageStatus;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border border-border bg-surface-muted px-2 py-1 text-[10.5px] font-medium text-muted-foreground",
        status === "confirmed" && "border-primary/25 bg-primary/10 text-primary",
        status === "likely" && "border-sev-high/25 bg-sev-high/10 text-sev-high",
        status === "needs-review" &&
          "border-sev-medium/30 bg-sev-medium/10 text-sev-medium",
        className,
      )}
    >
      {statusLabels[status]}
    </span>
  );
}

export function MetaTag({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border border-border bg-background px-2 py-1 text-[11px] text-muted-foreground",
        className,
      )}
    >
      {children}
    </span>
  );
}

export function ConfidenceBar({ value }: { value: number | null }) {
  if (value === null) {
    return (
      <div className="flex items-center gap-2">
        <div className="h-1.5 w-16 rounded-full bg-border" />
        <span className="num text-[11px] text-muted-foreground">n/a</span>
      </div>
    );
  }

  const percent = Math.round(value * 100);

  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-border">
        <div
          className={cn(
            "h-full rounded-full",
            percent >= 80
              ? "bg-primary"
              : percent >= 60
                ? "bg-sev-medium"
                : "bg-muted-foreground",
          )}
          style={{ width: `${percent}%` }}
        />
      </div>
      <span className="num text-[11px] text-muted-foreground">{percent}%</span>
    </div>
  );
}

export function StatCell({
  label,
  value,
  tone = "default",
}: {
  label: string;
  value: string | number;
  tone?: "default" | "warn" | "primary";
}) {
  return (
    <div className="rounded-lg border border-border bg-surface px-3 py-2.5">
      <div className="truncate text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
      <div
        className={cn(
          "num mt-1 text-lg font-semibold",
          tone === "warn" && "text-sev-high",
          tone === "primary" && "text-primary",
        )}
      >
        {value}
      </div>
    </div>
  );
}

export function DetailSection({
  title,
  children,
  aside,
}: {
  title: string;
  children: ReactNode;
  aside?: ReactNode;
}) {
  return (
    <section className="border-b border-border px-5 py-4 last:border-b-0">
      <div className="mb-3 flex items-center justify-between gap-2">
        <h3 className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
          {title}
        </h3>
        {aside}
      </div>
      {children}
    </section>
  );
}

function contextToCode(context: EvidenceContext | null): string {
  if (!context) {
    return "";
  }

  if (context.lines.length) {
    return context.lines.join("\n");
  }

  return context.snippet ?? "";
}

export function CodeBlock({
  context,
  caption,
  emptyLabel = "No context attached.",
}: {
  context: EvidenceContext | null;
  caption?: string;
  emptyLabel?: string;
}) {
  const code = contextToCode(context);

  return (
    <div className="overflow-hidden rounded-lg border border-border bg-surface-muted">
      {caption ? (
        <div className="border-b border-border px-3 py-2 font-mono text-[11px] text-muted-foreground">
          {caption}
        </div>
      ) : null}
      <pre className="overflow-x-auto px-3 py-3 font-mono text-[11.5px] leading-6 text-foreground">
        {code || emptyLabel}
      </pre>
    </div>
  );
}

export function KeyValue({
  label,
  value,
}: {
  label: string;
  value: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1 rounded-lg border border-border bg-background px-3 py-2 sm:flex-row sm:items-center sm:justify-between">
      <span className="text-[10.5px] font-semibold uppercase tracking-wide text-muted-foreground">
        {label}
      </span>
      <span className="min-w-0 break-all text-[12.5px] text-foreground sm:text-right">
        {value}
      </span>
    </div>
  );
}
