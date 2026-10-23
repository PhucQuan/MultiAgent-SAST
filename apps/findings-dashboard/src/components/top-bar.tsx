"use client";
import { Button } from "@/components/ui/button";
import { useTheme } from "@/lib/theme";
import type { NormalizedFinding, ReportSummaryCard } from "@/lib/report-types";
interface TopBarProps {
  report: ReportSummaryCard | null;
  reportsLoaded: number;
  reviewedLocally: number;
  selectedFamily?: string | null;
  onSelectFamily?: (family: string | null) => void;
  onImport: () => void;
  onCopyLink: () => void;
  onRefresh: () => void;
  onExport: () => void;
  onExportSarif?: () => void;
  onExportPatch?: () => void;
  onRunScan: () => void;
  copyLinkDisabled: boolean;
  scanPending: boolean;
  findings: NormalizedFinding[];
  onOpenExplorer?: () => void;
}

export function TopBar({report, onImport, onRefresh, onExport, onExportSarif, onExportPatch, onRunScan, scanPending, findings}: TopBarProps) {
 const {toggleTheme}=useTheme();
 return <header className="flex min-h-16 flex-wrap items-center gap-3 border-b px-4 py-2">
  <strong>Aegis</strong><div className="min-w-0 flex-1"><div title={report?.target} className="truncate font-semibold">{report?.target || "Select a scan"}</div><div className="text-xs text-muted-foreground">{scanPending ? "Scanning" : report ? "Completed report" : "Ready"} / {findings.length} findings</div></div>
  <Button onClick={onRunScan}>{scanPending ? "Scan progress" : "Run Scan"}</Button>
  <Button variant="outline" onClick={onExport}>Export scan JSON</Button>
  <details className="relative"><summary className="cursor-pointer">More</summary><div className="absolute right-0 z-50 w-52 rounded border bg-background p-3 shadow-lg flex flex-col gap-3 text-sm">
   <button onClick={onImport}>Import report</button><button onClick={onRefresh}>Refresh reports</button><button onClick={toggleTheme}>Toggle theme</button>
   {onExportSarif && <button onClick={onExportSarif}>Export scan SARIF</button>}{onExportPatch && <button onClick={onExportPatch}>Export scan patches</button>}
   {report?.metrics.precision != null && <span>Precision: {(report.metrics.precision*100).toFixed(1)}%</span>}
  </div></details>
 </header>;
}
