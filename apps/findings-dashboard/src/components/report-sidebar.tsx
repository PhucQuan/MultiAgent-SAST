import {
  AlertCircle,
  Download,
  FileJson,
  RefreshCw,
  Trash2,
} from "lucide-react";

import {
  formatDateTime,
  formatLabel,
  shortenPath,
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
      <div className="num mt-1.5 flex items-center gap-2 text-[11px] text-muted-foreground">
        <span>{formatLabel(report.reportKind)}</span>
        <span className="text-border">|</span>
        <span>{report.totalFindings} findings</span>
        <span className="text-border">|</span>
        <span className="text-sev-high">{actionable} actionable</span>
      </div>
      <div className="num mt-0.5 text-[11px] text-muted-foreground">
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
  showArchiveReports: boolean;
  onToggleArchiveReports: () => void;
  totalReports: number;
  archiveReports: number;
  recentLimit: number;
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
  showArchiveReports,
  onToggleArchiveReports,
  totalReports,
  archiveReports,
  recentLimit,
}: ReportSidebarProps) {
  const counts = countFeedback(feedbackStore);
  const feedbackCount = Object.keys(feedbackStore).length;
  const hiddenArchiveCount = Math.max(totalReports - reports.length, 0);

  return (
    <div className="flex h-full flex-col overflow-y-auto bg-surface">
      <div className="border-b border-border px-3 py-2.5">
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
              Reports
            </div>
            <div className="mt-0.5 text-[12px] text-muted-foreground">
              {showArchiveReports
                ? `${totalReports} report${totalReports === 1 ? "" : "s"} loaded`
                : `${reports.length} recent scan${reports.length === 1 ? "" : "s"} shown`}
            </div>
          </div>

          {archiveReports > 0 ? (
            <button
              type="button"
              onClick={onToggleArchiveReports}
              className="rounded-sm border border-border px-2 py-1 text-[11px] font-medium text-foreground transition-colors hover:bg-surface-muted"
            >
              {showArchiveReports ? "Recent only" : "Show archive/demo"}
            </button>
          ) : null}
        </div>

        {!showArchiveReports && archiveReports > 0 ? (
          <div className="mt-2 text-[11.5px] leading-5 text-muted-foreground">
            Archive/demo reports are hidden by default. Showing up to {recentLimit} recent runs.
            {hiddenArchiveCount > 0
              ? ` ${hiddenArchiveCount} older report${hiddenArchiveCount === 1 ? "" : "s"} are hidden.`
              : ""}
          </div>
        ) : null}
      </div>

      {loading && reports.length === 0 ? (
        <div className="border-b border-border px-3 py-3">
          <div className="rounded-sm border border-dashed border-border bg-background px-3 py-4 text-[12.5px] text-muted-foreground">
            Loading workspace reports...
          </div>
        </div>
      ) : null}

      {!loading && reports.length === 0 ? (
        <div className="border-b border-border px-3 py-3">
          <div className="rounded-sm border border-dashed border-border bg-background px-3 py-4 text-[12.5px] leading-6 text-muted-foreground">
            No normalized Aegis report found yet. Run a local scan or import a JSON bundle.
          </div>
        </div>
      ) : null}

      {reports.length ? (
        <div className="border-b border-border py-1">
          {reports.map((report) => (
            <ReportItem
              key={report.id}
              report={report}
              selected={report.id === selectedReportId}
              onSelect={() => onSelectReport(report.id)}
            />
          ))}
        </div>
      ) : null}

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
          Reviewer memory
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
            <div key={String(label)} className="flex justify-between gap-3">
              <dt className="text-muted-foreground">{label}</dt>
              <dd className="font-medium text-foreground">{value}</dd>
            </div>
          ))}
        </dl>
      </div>

      {error ? (
        <div className="border-t border-border px-3 py-3">
          <div className="flex items-start gap-2 rounded-sm border border-destructive/25 bg-destructive/8 px-3 py-2.5 text-[12px] text-destructive">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        </div>
      ) : null}
    </div>
  );
}
