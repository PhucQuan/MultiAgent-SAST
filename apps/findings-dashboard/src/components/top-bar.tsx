import { Download, FileJson, Play, RefreshCw } from "lucide-react";

import { StatCell } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import {
  formatDateTime,
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

  return (
    <header className="border-b border-border bg-surface">
      <div className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-4 px-4 py-3 lg:flex lg:items-center lg:justify-between">
        <div className="min-w-0">
          <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
            Aegis-SAST
          </div>
          <h1 className="mt-1 truncate text-[15px] font-semibold tracking-tight text-foreground">
            Static code findings
          </h1>
          <p className="truncate text-[12px] text-muted-foreground">
            Local review console for exported Aegis reports and AI triage overlays
          </p>
        </div>

        <div className="hidden min-w-0 items-center gap-4 xl:flex">
          <div className="min-w-0 text-right">
            <div className="truncate font-mono text-[12.5px] font-medium text-foreground">
              {report?.shortName ?? "No report selected"}
            </div>
            <div className="num truncate text-[11.5px] text-muted-foreground">
              {report
                ? `${report.scanProfile} · ${formatDateTime(report.timestamp)} · ${report.totalFindings} findings`
                : "Select a report to inspect"}
            </div>
          </div>
        </div>

        <div className="flex shrink-0 flex-wrap items-center gap-2">
          <Button
            size="sm"
            className="h-8 gap-1.5"
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
            className="h-8 gap-1.5"
            onClick={onImport}
          >
            <FileJson className="h-3.5 w-3.5" /> Import JSON
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-8 gap-1.5"
            onClick={onRefresh}
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </Button>
          <Button size="sm" className="h-8 gap-1.5" onClick={onExport}>
            <Download className="h-3.5 w-3.5" /> Export feedback
          </Button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-t border-border bg-surface-muted px-4 py-2">
        <StatCell label="Actionable" value={actionable} tone="warn" />
        <StatCell label="Needs review" value={needsReview} />
        <StatCell label="Reports loaded" value={reportsLoaded} />
        <StatCell label="Reviewed locally" value={reviewedLocally} tone="primary" />
        {report ? (
          <div className="ml-auto hidden truncate font-mono text-[11.5px] text-muted-foreground xl:block">
            {shortenPath(report.target, 5)}
          </div>
        ) : null}
      </div>
    </header>
  );
}
