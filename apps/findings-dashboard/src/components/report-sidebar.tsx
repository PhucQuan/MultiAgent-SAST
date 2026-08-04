import { AlertCircle, Download, FileJson, RefreshCw, Trash2 } from "lucide-react";

import {
  describeReportSource,
  formatDateTime,
  formatLabel,
  reportKindTone,
  shortenPath,
  type BadgeTone,
} from "@/lib/dashboard-ui";
import { cn } from "@/lib/utils";
import type { ReportSummaryCard, ReviewerFeedbackStore } from "@/lib/report-types";

export interface ReportEntry extends ReportSummaryCard {
  origin: "workspace" | "imported";
}

function countFeedback(feedbackStore: ReviewerFeedbackStore) {
  const entries = Object.values(feedbackStore);

  return {
    confirmed: entries.filter((entry) => entry.disposition === "confirmed").length,
    falsePositive: entries.filter((entry) => entry.disposition === "false-positive")
      .length,
    needsReview: entries.filter((entry) => entry.disposition === "needs-review").length,
    suppressed: entries.filter((entry) => entry.disposition === "suppressed").length,
    muted: entries.filter((entry) => entry.muted).length,
    notes: entries.filter((entry) => entry.note && entry.note.length > 0).length,
  };
}

function toneClasses(tone: BadgeTone) {
  return cn(
    "inline-flex items-center rounded-sm border px-1.5 py-0.5 text-[10.5px] font-medium",
    tone === "good" && "border-primary/25 bg-primary/10 text-primary",
    tone === "teal" && "border-primary/25 bg-primary/10 text-primary",
    tone === "warn" && "border-sev-medium/25 bg-sev-medium/10 text-sev-medium",
    tone === "muted" && "border-border bg-surface-muted text-muted-foreground",
    tone === "neutral" && "border-border bg-surface-muted text-muted-foreground",
  );
}

function ReportItem({
  report,
  selected,
  onSelect,
}: {
  report: ReportEntry;
  selected: boolean;
  onSelect: () => void;
}) {
  const actionable =
    report.triageSummary.confirmed + report.triageSummary.likely;
  const sourceDescriptor = describeReportSource(report.sourcePath);

  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        "w-full border-l-2 border-transparent px-3 py-2.5 text-left transition-colors hover:bg-surface-muted",
        selected && "border-l-primary bg-accent/60",
      )}
    >
      <div className="truncate font-mono text-[12.5px] font-medium text-foreground">
        {report.shortName}
      </div>
      <div className="mt-0.5 truncate text-[11.5px] text-muted-foreground">
        {shortenPath(report.target, 4)}
      </div>
      <div className="mt-1 truncate text-[11.5px] text-muted-foreground">
        {sourceDescriptor.detail}
      </div>
      <div className="num mt-1.5 flex items-center gap-2 text-[11px] text-muted-foreground">
        <span>{sourceDescriptor.label}</span>
        <span className="text-border">|</span>
        <span>{formatLabel(report.reportKind)}</span>
        <span className="text-border">|</span>
        <span>{report.totalFindings} findings</span>
        <span className="text-border">|</span>
        <span className="text-sev-high">{actionable} likely + confirmed</span>
      </div>
      <div className="mt-1 flex flex-wrap gap-1.5">
        <span
          className={toneClasses(sourceDescriptor.tone)}
        >
          {sourceDescriptor.label}
        </span>
        <span
          className={toneClasses(reportKindTone(report.reportKind))}
        >
          {formatLabel(report.reportKind)}
        </span>
        {report.frameworkHints.slice(0, 2).map((hint) => (
          <span
            key={hint}
            className="inline-flex items-center rounded-sm border border-border px-1.5 py-0.5 text-[10.5px] text-muted-foreground"
          >
            {formatLabel(hint)}
          </span>
        ))}
      </div>
      <div className="num mt-1.5 text-[11px] text-muted-foreground">
        {formatDateTime(report.timestamp)}
      </div>
    </button>
  );
}

function QuickAction({
  icon: Icon,
  label,
  onClick,
  disabled = false,
}: {
  icon: typeof FileJson;
  label: string;
  onClick: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-[12.5px] text-foreground transition-colors hover:bg-surface-muted disabled:cursor-not-allowed disabled:opacity-50"
    >
      <Icon className="h-3.5 w-3.5 text-muted-foreground" />
      {label}
    </button>
  );
}

interface ReportSidebarProps {
  reports: ReportEntry[];
  selectedReportId: string | null;
  onSelectReport: (reportId: string) => void;
  onRefresh: () => void;
  onImportRequest: () => void;
  onExportFeedback: () => void;
  onClearMemory: () => void;
  feedbackStore: ReviewerFeedbackStore;
  loading: boolean;
  error: string | null;
}

export function ReportSidebar({
  reports,
  selectedReportId,
  onSelectReport,
  onRefresh,
  onImportRequest,
  onExportFeedback,
  onClearMemory,
  feedbackStore,
  loading,
  error,
}: ReportSidebarProps) {
  const counts = countFeedback(feedbackStore);
  const feedbackCount = Object.keys(feedbackStore).length;

  return (
    <div className="flex h-full flex-col overflow-y-auto bg-surface">
      <div className="border-b border-border px-3 py-2.5">
        <h2 className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
          Aegis reports
        </h2>
      </div>

      <div className="border-b border-border py-1">
        {loading && reports.length === 0 ? (
          <div className="px-3 py-4 text-[12.5px] text-muted-foreground">
            Loading workspace reports...
          </div>
        ) : null}

        {!loading && reports.length === 0 ? (
          <div className="px-3 py-4 text-[12.5px] leading-6 text-muted-foreground">
            No normalized Aegis report found yet. Run the CLI or import a saved
            JSON bundle.
          </div>
        ) : null}

        {reports.map((report) => (
          <ReportItem
            key={report.id}
            report={report}
            selected={report.id === selectedReportId}
            onSelect={() => onSelectReport(report.id)}
          />
        ))}
      </div>

      <div className="border-b border-border px-2 py-2">
        <div className="px-1 pb-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
          Quick actions
        </div>
        <QuickAction icon={FileJson} label="Import JSON report" onClick={onImportRequest} />
        <QuickAction icon={RefreshCw} label="Refresh reports" onClick={onRefresh} />
        <QuickAction
          icon={Download}
          label="Export feedback"
          onClick={onExportFeedback}
          disabled={feedbackCount === 0}
        />
        <QuickAction
          icon={Trash2}
          label="Clear local review state"
          onClick={onClearMemory}
          disabled={feedbackCount === 0}
        />
      </div>

      <div className="px-3 py-2.5">
        <div className="pb-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
          Local reviewer memory
        </div>
        <dl className="num space-y-1 text-[12px]">
          {[
            ["Confirmed", counts.confirmed],
            ["Needs review", counts.needsReview],
            ["False positive", counts.falsePositive],
            ["Suppressed", counts.suppressed],
            ["Muted", counts.muted],
            ["Notes saved", counts.notes],
          ].map(([label, value]) => (
            <div key={String(label)} className="flex justify-between">
              <dt className="text-muted-foreground">{label}</dt>
              <dd className="font-medium text-foreground">{value}</dd>
            </div>
          ))}
        </dl>
      </div>

      {error ? (
        <div className="border-t border-border px-3 py-3">
          <div className="flex items-start gap-2 rounded-sm border border-destructive/25 bg-destructive/8 px-3 py-2.5 text-[12.5px] text-destructive">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        </div>
      ) : null}
    </div>
  );
}
