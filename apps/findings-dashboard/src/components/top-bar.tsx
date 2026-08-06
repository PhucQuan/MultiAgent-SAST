import { Download, FileJson, Play, RefreshCw } from "lucide-react";

import { MetaTag } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { formatDateTime, formatLabel, shortenPath } from "@/lib/dashboard-ui";
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

  return (
    <header className="border-b border-border bg-surface">
      <div className="flex flex-col gap-4 px-4 py-4 xl:flex-row xl:items-start xl:justify-between">
        <div className="min-w-0">
          <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
            Aegis-SAST review layer
          </div>
          <h1 className="mt-1 text-[18px] font-semibold tracking-tight text-foreground">
            Aegis Review Console
          </h1>
          <p className="mt-1 max-w-3xl text-[12.5px] leading-6 text-muted-foreground">
            Review exported findings, run local scans, and keep reviewer
            feedback lightweight before sharing results in the thesis demo flow.
          </p>

          <div className="mt-3 flex flex-wrap items-center gap-2">
            <MetaTag>{reportsLoaded} reports loaded</MetaTag>
            <MetaTag>{reviewedLocally} local review entries</MetaTag>
            {report ? (
              <>
                <MetaTag>{formatLabel(report.reportKind)}</MetaTag>
                <MetaTag>{report.totalFindings} findings</MetaTag>
                <MetaTag className="border-primary/25 bg-primary/8 text-primary">
                  {actionable} actionable
                </MetaTag>
                <MetaTag className="border-sev-medium/25 bg-sev-medium/8 text-sev-medium">
                  {needsReview} needs review
                </MetaTag>
              </>
            ) : null}
          </div>

          <div className="mt-3 min-w-0 rounded-lg border border-border bg-background px-3 py-2.5">
            <div className="truncate font-mono text-[12px] font-medium text-foreground">
              {report?.shortName ?? "No report selected"}
            </div>
            <div className="mt-1 truncate text-[11.5px] text-muted-foreground">
              {report
                ? `${formatLabel(report.scanProfile)} | ${formatDateTime(report.timestamp)}`
                : "Choose a report from the sidebar to inspect findings."}
            </div>
            {report ? (
              <div className="mt-1 truncate font-mono text-[11px] text-muted-foreground">
                {shortenPath(report.target, 5)}
              </div>
            ) : null}
          </div>
        </div>

        <div className="flex shrink-0 flex-wrap items-center gap-2 xl:justify-end">
          <Button
            size="sm"
            className="h-9 gap-1.5 rounded-md px-3"
            onClick={onRunScan}
            disabled={scanPending}
          >
            {scanPending ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Play className="h-3.5 w-3.5" />
            )}{" "}
            {scanPending ? "Running scan" : "New local scan"}
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-9 gap-1.5 rounded-md px-3"
            onClick={onImport}
          >
            <FileJson className="h-3.5 w-3.5" /> Import report
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-9 gap-1.5 rounded-md px-3"
            onClick={onRefresh}
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </Button>
          {reviewedLocally > 0 ? (
            <Button
              variant="ghost"
              size="sm"
              className="h-9 gap-1.5 rounded-md px-3"
              onClick={onExport}
            >
              <Download className="h-3.5 w-3.5" /> Export memory
            </Button>
          ) : null}
        </div>
      </div>
    </header>
  );
}
