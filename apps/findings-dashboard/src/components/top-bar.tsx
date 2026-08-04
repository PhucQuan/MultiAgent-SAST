import { Download, FileJson, RefreshCw } from "lucide-react";

import { StatCell } from "@/components/status-badge";
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
}

export function TopBar({
  report,
  reportsLoaded,
  reviewedLocally,
  onImport,
  onRefresh,
  onExport,
}: TopBarProps) {
  const actionable =
    (report?.triageSummary.confirmed ?? 0) + (report?.triageSummary.likely ?? 0);
  const needsReview = report?.triageSummary["needs-review"] ?? 0;
  const sourceDescriptor = report ? describeReportSource(report.sourcePath) : null;

  return (
    <header className="border-b border-border bg-surface">
      <div className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-4 px-4 py-3 lg:flex lg:items-center lg:justify-between">
        <div className="min-w-0">
          <h1 className="truncate text-[15px] font-semibold tracking-tight text-foreground">
            Aegis-SAST Findings Dashboard
          </h1>
          <p className="truncate text-[12px] text-muted-foreground">
            {sourceDescriptor?.detail ??
              "Repo intake, AST or taint evidence, AI triage, and local reviewer memory."}
          </p>
        </div>

        <div className="hidden min-w-0 items-center gap-4 xl:flex">
          <div className="min-w-0 text-right">
            <div className="truncate font-mono text-[12.5px] font-medium text-foreground">
              {report?.shortName ?? "No report selected"}
            </div>
            <div className="num truncate text-[11.5px] text-muted-foreground">
              {report ? (
                <>
                  {sourceDescriptor?.label ?? "Workspace report"} |{" "}
                  {formatLabel(report.reportKind)} | {report.scanProfile} |{" "}
                  {formatDateTime(report.timestamp)} | {report.totalFindings} findings
                </>
              ) : (
                "Pick a normalized report bundle to inspect"
              )}
            </div>
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-2">
          <Button variant="outline" size="sm" className="h-8 gap-1.5" onClick={onImport}>
            <FileJson className="h-3.5 w-3.5" /> Import JSON
          </Button>
          <Button variant="outline" size="sm" className="h-8 gap-1.5" onClick={onRefresh}>
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </Button>
          <Button size="sm" className="h-8 gap-1.5" onClick={onExport}>
            <Download className="h-3.5 w-3.5" /> Export feedback
          </Button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-t border-border bg-surface-muted px-4 py-2">
        <StatCell label="Likely + confirmed" value={actionable} tone="warn" />
        <StatCell label="Needs review" value={needsReview} />
        <StatCell label="Reports loaded" value={reportsLoaded} />
        <StatCell label="Reviewer memory" value={reviewedLocally} tone="primary" />
        {report ? (
          <div className="ml-auto hidden truncate font-mono text-[11.5px] text-muted-foreground xl:block">
            {sourceDescriptor?.label ?? "Workspace report"} | {shortenPath(report.target, 5)}
          </div>
        ) : null}
      </div>
    </header>
  );
}
