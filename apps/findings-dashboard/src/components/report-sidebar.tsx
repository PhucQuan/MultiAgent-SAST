import {
  AlertCircle,
  Download,
  FileJson,
  RefreshCw,
  Trash2,
} from "lucide-react";

import { MetaTag } from "@/components/status-badge";
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
    total: entries.length,
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
  const needsReview = report.triageSummary["needs-review"];

  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        "w-full rounded-xl border border-transparent bg-background px-3 py-3 text-left transition-colors hover:border-border hover:bg-surface-muted",
        selected && "border-primary/25 bg-primary/6 shadow-sm",
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="truncate font-mono text-[12px] font-medium text-foreground">
            {report.shortName}
          </div>
          <div className="mt-1 truncate text-[11.5px] text-muted-foreground">
            {shortenPath(report.target, 4)}
          </div>
        </div>
        <MetaTag className="shrink-0">
          {report.origin === "imported" ? "Imported" : "Workspace"}
        </MetaTag>
      </div>

      <div className="mt-2 flex flex-wrap gap-1.5">
        <MetaTag>{formatLabel(report.scanProfile)}</MetaTag>
        <MetaTag>{report.totalFindings} findings</MetaTag>
        <MetaTag className="border-primary/25 bg-primary/8 text-primary">
          {actionable} actionable
        </MetaTag>
        <MetaTag className="border-sev-medium/25 bg-sev-medium/8 text-sev-medium">
          {needsReview} review
        </MetaTag>
      </div>

      <div className="mt-2 text-[11px] text-muted-foreground">
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
      className="flex items-center gap-2 rounded-lg border border-border bg-background px-3 py-2 text-left text-[12px] text-foreground transition-colors hover:bg-surface-muted disabled:cursor-not-allowed disabled:opacity-50"
    >
      <Icon className="h-3.5 w-3.5 text-muted-foreground" />
      <span>{label}</span>
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
  const hiddenArchiveCount = Math.max(totalReports - reports.length, 0);

  return (
    <div className="bg-surface">
      <div className="border-b border-border px-4 py-4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
              Reports
            </div>
            <h2 className="mt-1 text-[15px] font-semibold tracking-tight text-foreground">
              Scan history
            </h2>
            <p className="mt-1 text-[12px] leading-5 text-muted-foreground">
              {showArchiveReports
                ? `${totalReports} reports available`
                : `${reports.length} recent runs shown`}
            </p>
          </div>

          {archiveReports > 0 ? (
            <button
              type="button"
              onClick={onToggleArchiveReports}
              className="rounded-lg border border-border px-2.5 py-1 text-[11px] font-medium text-foreground transition-colors hover:bg-surface-muted"
            >
              {showArchiveReports ? "Recent only" : "Show archive"}
            </button>
          ) : null}
        </div>

        {!showArchiveReports && archiveReports > 0 ? (
          <p className="mt-3 rounded-lg border border-border bg-background px-3 py-2 text-[11.5px] leading-5 text-muted-foreground">
            Archive and demo reports stay hidden by default. Showing up to{" "}
            {recentLimit} recent runs
            {hiddenArchiveCount > 0
              ? `, with ${hiddenArchiveCount} older report${hiddenArchiveCount === 1 ? "" : "s"} hidden.`
              : "."}
          </p>
        ) : null}
      </div>

      <div className="px-3 py-3">
        {loading && reports.length === 0 ? (
          <div className="rounded-xl border border-dashed border-border bg-background px-3 py-4 text-[12.5px] text-muted-foreground">
            Loading workspace reports...
          </div>
        ) : null}

        {!loading && reports.length === 0 ? (
          <div className="rounded-xl border border-dashed border-border bg-background px-3 py-4 text-[12.5px] leading-6 text-muted-foreground">
            No normalized Aegis report found yet. Run a local scan or import a
            JSON bundle.
          </div>
        ) : null}

        {reports.length ? (
          <div className="space-y-2">
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
      </div>

      <div className="border-t border-border px-4 py-4">
        <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
          Quick actions
        </div>
        <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-1 xl:grid-cols-2">
          <QuickAction icon={FileJson} label="Import report" onClick={onImportRequest} />
          <QuickAction icon={RefreshCw} label="Refresh" onClick={onRefresh} />
          <QuickAction
            icon={Download}
            label="Export memory"
            onClick={onExportFeedback}
            disabled={counts.total === 0}
          />
          <QuickAction
            icon={Trash2}
            label="Clear memory"
            onClick={onClearMemory}
            disabled={counts.total === 0}
          />
        </div>

        <div className="mt-3 flex flex-wrap gap-2">
          <MetaTag>{counts.total} reviewed</MetaTag>
          <MetaTag>{counts.muted} muted</MetaTag>
          <MetaTag>{counts.notes} notes</MetaTag>
        </div>

        {error ? (
          <div className="mt-3 flex items-start gap-2 rounded-xl border border-destructive/25 bg-destructive/8 px-3 py-2.5 text-[12px] text-destructive">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        ) : null}
      </div>
    </div>
  );
}
