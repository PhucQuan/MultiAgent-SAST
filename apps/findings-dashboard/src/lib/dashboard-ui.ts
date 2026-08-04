import type {
  ReportKind,
  ReviewerDisposition,
  Severity,
  TriageStatus,
} from "@/lib/report-types";

export type BadgeTone =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "good"
  | "teal"
  | "warn"
  | "muted"
  | "neutral";

export interface ReportSourceDescriptor {
  label: string;
  detail: string;
  tone: BadgeTone;
}

export function formatLabel(value: string): string {
  const acronymSet = new Set([
    "api",
    "ast",
    "cfg",
    "cli",
    "cwe",
    "dfg",
    "html",
    "http",
    "json",
    "llm",
    "owasp",
    "php",
    "pr",
    "sarif",
    "sql",
    "sqli",
    "ssrf",
    "sast",
    "xss",
    "yaml",
  ]);

  return value
    .replace(/[-_./]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .split(" ")
    .map((part) => {
      if (!part) {
        return part;
      }

      if (part === part.toUpperCase() && part.length <= 6) {
        return part;
      }

      if (acronymSet.has(part.toLowerCase())) {
        return part.toUpperCase();
      }

      return part.charAt(0).toUpperCase() + part.slice(1).toLowerCase();
    })
    .join(" ");
}

export function formatDateTime(value: string | null): string {
  if (!value) {
    return "Unknown time";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat("vi-VN", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

export function formatConfidence(value: number | null): string {
  if (value === null) {
    return "n/a";
  }

  return `${Math.round(value * 100)}%`;
}

export function shortenPath(filePath: string, keepSegments = 3): string {
  const normalized = filePath.replace(/\\/g, "/");
  const segments = normalized.split("/").filter(Boolean);

  if (segments.length <= keepSegments) {
    return normalized;
  }

  return `.../${segments.slice(-keepSegments).join("/")}`;
}

export function severityRank(severity: Severity): number {
  switch (severity) {
    case "critical":
      return 0;
    case "high":
      return 1;
    case "medium":
      return 2;
    case "low":
      return 3;
    case "info":
      return 4;
    default:
      return 5;
  }
}

export function triageRank(status: TriageStatus): number {
  switch (status) {
    case "confirmed":
      return 0;
    case "likely":
      return 1;
    case "needs-review":
      return 2;
    case "suppressed":
      return 3;
    default:
      return 4;
  }
}

export function severityTone(severity: Severity): BadgeTone {
  switch (severity) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
    case "info":
      return "low";
    default:
      return "neutral";
  }
}

export function triageTone(status: TriageStatus): BadgeTone {
  switch (status) {
    case "confirmed":
      return "good";
    case "likely":
      return "teal";
    case "needs-review":
      return "warn";
    case "suppressed":
      return "muted";
    default:
      return "neutral";
  }
}

export function reviewerTone(
  disposition: ReviewerDisposition | undefined,
): BadgeTone {
  switch (disposition) {
    case "confirmed":
      return "good";
    case "needs-review":
      return "warn";
    case "suppressed":
      return "muted";
    case "false-positive":
      return "neutral";
    default:
      return "neutral";
  }
}

export function reportKindTone(kind: ReportKind): BadgeTone {
  switch (kind) {
    case "workflow":
      return "teal";
    case "rich":
      return "good";
    case "triage":
      return "warn";
    case "legacy":
      return "muted";
    default:
      return "neutral";
  }
}

export function describeReportSource(sourcePath: string): ReportSourceDescriptor {
  const normalized = sourcePath.replace(/\\/g, "/").toLowerCase();

  if (normalized.startsWith("imported/")) {
    return {
      label: "Imported JSON",
      detail: "Ad hoc report imported into the dashboard",
      tone: "muted",
    };
  }

  if (normalized.startsWith("benchmark/")) {
    return {
      label: "Benchmark bundle",
      detail: "Reviewed benchmark corpus for thesis evaluation",
      tone: "teal",
    };
  }

  if (normalized.startsWith("manual_targets/")) {
    return {
      label: "Manual target",
      detail: "Hand-picked vulnerable sample used for product demo",
      tone: "good",
    };
  }

  if (normalized.startsWith("manual_smoke/")) {
    return {
      label: "Manual smoke",
      detail: "Quick CLI smoke run against a local sample",
      tone: "warn",
    };
  }

  if (normalized.startsWith("rule_review/") || normalized.startsWith("rule_review_smoke/")) {
    return {
      label: "Rule review",
      detail: "Reviewed scan bundle for rule QA and evidence checks",
      tone: "warn",
    };
  }

  if (normalized.startsWith("_workflow_smoke/")) {
    return {
      label: "Workflow smoke",
      detail: "Planner -> auditor -> skeptic -> judge smoke output",
      tone: "teal",
    };
  }

  if (normalized.startsWith("_triage_smoke/")) {
    return {
      label: "Triage smoke",
      detail: "Normalized triage schema smoke output",
      tone: "warn",
    };
  }

  return {
    label: "Workspace report",
    detail: "Normalized Aegis report discovered under reports/",
    tone: "neutral",
  };
}
