import { Download, FileJson, Play, RefreshCw } from "lucide-react";

import { MetaTag, StatCell } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import {
  describeReportSource,
  formatDateTime,
  formatLabel,
  shortenPath,
} from "@/lib/dashboard-ui";
import type { ReportSummaryCard } from "@/lib/report-types";

interface TopBarProps {
  report: ReportSummaryCard | null;
  reportsLoaded: number;
  reviewedLocally: number;
  onImport: () => void;
  onRefresh: () => void;
  onExport: () => void;
  onRunScan: () => void;
  scanPending: boolean;
}

export function TopBar({
  report,
  reportsLoaded,
  reviewedLocally,
  onImport,
  onRefresh,
  onExport,
  onRunScan,
  scanPending,
}: TopBarProps) {
  const actionable =
    (report?.triageSummary.confirmed ?? 0) + (report?.triageSummary.likely ?? 0);
  const needsReview = report?.triageSummary["needs-review"] ?? 0;
  const criticalAndHigh =
    (report?.severitySummary.critical ?? 0) + (report?.severitySummary.high ?? 0);
  const sourceDescriptor = report ? describeReportSource(report.sourcePath) : null;

  return (
    <header className="border-b border-border bg-surface">
      <div className="grid gap-4 px-4 py-4 xl:grid-cols-[minmax(0,1fr)_320px_auto] xl:items-start">
        <div className="min-w-0">
          <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
            Aegis-SAST / Review Console
          </div>
          <h1 className="mt-2 text-[22px] font-semibold tracking-tight text-foreground">
            Static code findings
          </h1>
          <p className="mt-1 max-w-2xl text-[13px] leading-6 text-muted-foreground">
            Review normalized findings, AI triage decisions, and local reviewer
            feedback without leaving exported Aegis reports.
          </p>
          <div className="mt-3 flex flex-wrap gap-1.5">
            <MetaTag>{reportsLoaded} reports loaded</MetaTag>
            <MetaTag>
              {reviewedLocally} local review entr
              {reviewedLocally === 1 ? "y" : "ies"}
            </MetaTag>
            {report ? (
              <MetaTag>{sourceDescriptor?.label ?? "Workspace report"}</MetaTag>
            ) : (
              <MetaTag>No active report</MetaTag>
            )}
          </div>
        </div>

        <div className="rounded-lg border border-border bg-surface-muted px-4 py-3">
          <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
            Active report
          </div>
          <div className="mt-2 truncate text-[15px] font-semibold text-foreground">
            {report?.shortName ?? "No report selected"}
          </div>
          <div className="mt-1 truncate text-[12px] text-muted-foreground">
            {report
              ? shortenPath(report.target, 5)
              : "Pick a normalized report bundle to inspect"}
          </div>
          <div className="mt-3 flex flex-wrap gap-1.5">
            {report ? (
              <>
                <MetaTag>{sourceDescriptor?.label ?? "Workspace report"}</MetaTag>
                <MetaTag>{formatLabel(report.reportKind)}</MetaTag>
                <MetaTag>{report.scanProfile}</MetaTag>
              </>
            ) : null}
          </div>
          <div className="num mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[11.5px] text-muted-foreground">
            <span>{formatDateTime(report?.timestamp ?? null)}</span>
            {report ? <span>{report.totalFindings} findings</span> : null}
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-start gap-2 xl:justify-end">
          <Button
            size="sm"
            className="h-9 gap-1.5"
            onClick={onRunScan}
            disabled={scanPending}
          >
            {scanPending ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Play className="h-3.5 w-3.5" />
            )}{" "}
            {scanPending ? "Running scan" : "Run local scan"}
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-9 gap-1.5"
            onClick={onImport}
          >
            <FileJson className="h-3.5 w-3.5" /> Import JSON
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-9 gap-1.5"
            onClick={onRefresh}
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </Button>
          <Button size="sm" className="h-9 gap-1.5" onClick={onExport}>
            <Download className="h-3.5 w-3.5" /> Export feedback
          </Button>
        </div>
      </div>

      <div className="grid gap-2 border-t border-border bg-background/70 px-4 py-3 sm:grid-cols-2 xl:grid-cols-5">
        <StatCell label="Actionable now" value={actionable} tone="warn" />
        <StatCell label="Needs review" value={needsReview} />
        <StatCell label="Critical + high" value={criticalAndHigh} tone="warn" />
        <StatCell label="Reports loaded" value={reportsLoaded} />
        <StatCell label="Reviewer memory" value={reviewedLocally} tone="primary" />
      </div>
    </header>
  );
}
