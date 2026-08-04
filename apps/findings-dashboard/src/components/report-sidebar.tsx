import {
  AlertCircle,
  Download,
  FileJson,
  RefreshCw,
  Trash2,
} from "lucide-react";

import { MetaTag } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
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
    "inline-flex items-center rounded-full border px-2 py-1 text-[10.5px] font-medium",
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
  const actionable = report.triageSummary.confirmed + report.triageSummary.likely;
  const sourceDescriptor = describeReportSource(report.sourcePath);

  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        "w-full rounded-lg border px-3 py-3 text-left transition-colors hover:border-primary/30 hover:bg-accent/35",
        selected
          ? "border-primary bg-primary/6 shadow-sm"
          : "border-border bg-background",
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate text-[13px] font-semibold text-foreground">
            {report.shortName}
          </div>
          <div className="mt-1 truncate text-[11.5px] text-muted-foreground">
            {shortenPath(report.target, 4)}
          </div>
        </div>
        <span className={toneClasses(reportKindTone(report.reportKind))}>
          {formatLabel(report.reportKind)}
        </span>
      </div>

      <div className="mt-2 flex flex-wrap gap-1.5">
        <span className={toneClasses(sourceDescriptor.tone)}>{sourceDescriptor.label}</span>
        <MetaTag>{actionable} actionable</MetaTag>
        <MetaTag>{report.totalFindings} findings</MetaTag>
        {report.frameworkHints.slice(0, 2).map((hint) => (
          <MetaTag key={hint}>{formatLabel(hint)}</MetaTag>
        ))}
      </div>

      <div className="num mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
        <span>{report.scanProfile}</span>
        <span>{formatDateTime(report.timestamp)}</span>
      </div>
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
    <div className="flex h-full min-h-0 flex-col bg-surface">
      <div className="border-b border-border px-4 py-3">
        <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
          Reports
        </div>
        <div className="mt-1 text-[18px] font-semibold tracking-tight text-foreground">
          Explorer
        </div>
        <div className="mt-1 text-[12.5px] text-muted-foreground">
          {reports.length} report{reports.length === 1 ? "" : "s"} available in the
          local review console.
        </div>
      </div>

      <div className="border-b border-border px-4 py-3">
        <div className="grid grid-cols-2 gap-2">
          <Button
            size="sm"
            className="h-9 justify-start gap-1.5"
            onClick={onImportRequest}
          >
            <FileJson className="h-3.5 w-3.5" /> Import JSON
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-9 justify-start gap-1.5"
            onClick={onRefresh}
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-9 justify-start gap-1.5"
            onClick={onExportFeedback}
            disabled={feedbackCount === 0}
          >
            <Download className="h-3.5 w-3.5" /> Export
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-9 justify-start gap-1.5"
            onClick={onClearMemory}
            disabled={feedbackCount === 0}
          >
            <Trash2 className="h-3.5 w-3.5" /> Clear memory
          </Button>
        </div>
      </div>

      <div className="border-b border-border px-4 py-3">
        <div className="pb-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
          Local reviewer memory
        </div>
        <dl className="grid grid-cols-2 gap-2">
          {[
            ["Confirmed", counts.confirmed],
            ["Needs review", counts.needsReview],
            ["False positive", counts.falsePositive],
            ["Suppressed", counts.suppressed],
            ["Muted", counts.muted],
            ["Notes saved", counts.notes],
          ].map(([label, value]) => (
            <div
              key={String(label)}
              className="rounded-lg border border-border bg-background px-3 py-2"
            >
              <dt className="text-[10.5px] font-semibold uppercase tracking-wide text-muted-foreground">
                {label}
              </dt>
              <dd className="num mt-1 text-lg font-semibold text-foreground">{value}</dd>
            </div>
          ))}
        </dl>
      </div>

      <div className="flex min-h-0 flex-1 flex-col">
        <div className="flex items-center justify-between border-b border-border px-4 py-2">
          <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
            Saved reports
          </div>
          <div className="num text-[11px] text-muted-foreground">{reports.length} loaded</div>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-4 py-3">
          {loading && reports.length === 0 ? (
            <div className="rounded-lg border border-dashed border-border bg-background px-3 py-4 text-[12.5px] text-muted-foreground">
              Loading workspace reports...
            </div>
          ) : null}

          {!loading && reports.length === 0 ? (
            <div className="rounded-lg border border-dashed border-border bg-background px-3 py-4 text-[12.5px] leading-6 text-muted-foreground">
              No normalized Aegis report found yet. Run the CLI or import a saved
              JSON bundle.
            </div>
          ) : null}

          <div className="space-y-3">
            {reports.map((report) => (
              <ReportItem
                key={report.id}
                report={report}
                selected={report.id === selectedReportId}
                onSelect={() => onSelectReport(report.id)}
              />
            ))}
          </div>
        </div>
      </div>

      {error ? (
        <div className="border-t border-border px-4 py-3">
          <div className="flex items-start gap-2 rounded-lg border border-destructive/25 bg-destructive/8 px-3 py-2.5 text-[12.5px] text-destructive">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        </div>
      ) : null}
    </div>
  );
}
