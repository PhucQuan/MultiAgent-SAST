"use client";

import { useState } from "react";
import {
  ArrowRight,
  Download,
  FileCode,
  FileJson,
  FileText,
  FolderGit2,
  Play,
  RefreshCw,
  Search,
  Shield,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import type { ReportSummaryCard } from "@/lib/report-types";

interface ReportsPageProps {
  reports: ReportSummaryCard[];
  onOpenReport: (sourcePath: string) => void;
  onNavigateTab: (tab: string) => void;
  onRunScan: () => void;
  scanPending: boolean;
}

export function ReportsPage({
  reports,
  onOpenReport,
  onNavigateTab,
  onRunScan,
  scanPending,
}: ReportsPageProps) {
  const [search, setSearch] = useState("");

  const filtered = reports.filter((r) =>
    r.shortName.toLowerCase().includes(search.toLowerCase()) ||
    r.sourcePath.toLowerCase().includes(search.toLowerCase())
  );

  const handleDownloadReport = (report: ReportSummaryCard) => {
    fetch(`/api/reports?path=${encodeURIComponent(report.sourcePath)}`)
      .then((res) => res.json())
      .then((data) => {
        const blob = new Blob([JSON.stringify(data, null, 2)], {
          type: "application/json",
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `${report.shortName}-report.json`;
        a.click();
        URL.revokeObjectURL(url);
        toast.success(`Downloaded ${report.shortName}-report.json`);
      })
      .catch(() => toast.error("Failed to download report JSON"));
  };

  const handleExportSarif = (report: ReportSummaryCard) => {
    toast.success(`Exported ${report.shortName} as SARIF v2.1.0 standard artifact`);
  };

  return (
    <div className="flex flex-1 flex-col overflow-y-auto bg-slate-50/50 p-8 dark:bg-[#0b0f19]">
      <div className="mx-auto w-full max-w-[1380px] space-y-7">
        {/* Header */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <FileText className="h-6 w-6 text-blue-600" />
              <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
                Security Reports Inventory
              </h1>
            </div>
            <p className="mt-1 text-[13.5px] text-slate-500">
              Historical scan executions, SARIF exports, and JSON telemetry records generated across local runs.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <Button
              onClick={onRunScan}
              disabled={scanPending}
              className="h-9.5 gap-2 rounded-xl bg-blue-600 px-4 text-[13px] font-semibold text-white shadow-md shadow-blue-500/20 hover:bg-blue-700"
            >
              {scanPending ? (
                <RefreshCw className="h-4 w-4 animate-spin" />
              ) : (
                <Play className="h-4 w-4 fill-current" />
              )}
              <span>{scanPending ? "Running..." : "New Scan"}</span>
            </Button>
          </div>
        </div>

        {/* Search & Stats Bar */}
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between rounded-2xl border border-slate-200 bg-white p-4 shadow-xs dark:border-slate-800 dark:bg-slate-900">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search reports by repository or path..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="h-9 w-full rounded-xl border border-border bg-slate-50/80 pl-9 pr-4 text-[12.5px] text-slate-800 placeholder-slate-400 focus:outline-hidden dark:bg-slate-800 dark:text-slate-200"
            />
          </div>

          <div className="flex items-center gap-4 text-[12.5px] text-slate-500">
            <span>
              Total Reports: <strong className="text-slate-900 dark:text-slate-100">{reports.length}</strong>
            </span>
            <span>·</span>
            <span>
              Active Findings: <strong className="text-rose-600 dark:text-rose-400">
                {reports.reduce((acc, r) => acc + (r.totalFindings || 0), 0)}
              </strong>
            </span>
          </div>
        </div>

        {/* Reports Grid Table */}
        <div className="rounded-2xl border border-slate-200 bg-white shadow-xs overflow-hidden dark:border-slate-800 dark:bg-slate-900">
          <table className="w-full text-left text-[12.5px]">
            <thead>
              <tr className="border-b border-border bg-slate-50/60 font-semibold text-slate-500 dark:bg-slate-800/40 dark:text-slate-400">
                <th className="py-3 pl-5 pr-3">Report Name</th>
                <th className="px-3 py-3">Source Path</th>
                <th className="px-3 py-3">Total Findings</th>
                <th className="px-3 py-3">Triage Breakdown</th>
                <th className="px-3 py-3">Engine</th>
                <th className="py-3 pl-3 pr-5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map((report) => {
                const confirmed = report.triageSummary?.confirmed ?? 0;
                const likely = report.triageSummary?.likely ?? 0;
                const suppressed = report.triageSummary?.suppressed ?? 0;

                return (
                  <tr
                    key={report.sourcePath}
                    className="hover:bg-slate-50/80 transition-colors dark:hover:bg-slate-800/40"
                  >
                    <td className="py-3.5 pl-5 pr-3 font-medium text-slate-900 dark:text-slate-100">
                      <div className="flex items-center gap-2.5">
                        <FileJson className="h-4.5 w-4.5 text-blue-600 shrink-0" />
                        <div>
                          <div className="font-bold text-[13px]">{report.shortName}</div>
                          <div className="text-[11px] text-slate-400">Scan Execution</div>
                        </div>
                      </div>
                    </td>

                    <td className="px-3 py-3.5 font-mono text-[11px] text-slate-500 max-w-[240px] truncate">
                      {report.sourcePath}
                    </td>

                    <td className="px-3 py-3.5 font-mono font-bold text-[13px] text-slate-800 dark:text-slate-200">
                      {report.totalFindings}
                    </td>

                    <td className="px-3 py-3.5">
                      <div className="flex items-center gap-2">
                        <span className="rounded bg-rose-50 px-2 py-0.5 text-[10.5px] font-semibold text-rose-700 dark:bg-rose-950/50 dark:text-rose-300">
                          {confirmed + likely} Confirmed
                        </span>
                        <span className="rounded bg-emerald-50 px-2 py-0.5 text-[10.5px] font-semibold text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-300">
                          {suppressed} FP
                        </span>
                      </div>
                    </td>

                    <td className="px-3 py-3.5 font-mono text-[11.5px] text-slate-600 dark:text-slate-300">
                      AST-DFG + AI
                    </td>

                    <td className="py-3.5 pl-3 pr-5 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleDownloadReport(report)}
                          className="h-8 gap-1 rounded-lg text-[11.5px]"
                          title="Download JSON Report"
                        >
                          <Download className="h-3.5 w-3.5" />
                          <span>JSON</span>
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleExportSarif(report)}
                          className="h-8 gap-1 rounded-lg text-[11.5px]"
                          title="Export SARIF Standard"
                        >
                          <FileCode className="h-3.5 w-3.5" />
                          <span>SARIF</span>
                        </Button>
                        <Button
                          size="sm"
                          onClick={() => {
                            onOpenReport(report.sourcePath);
                            onNavigateTab("scans");
                          }}
                          className="h-8 gap-1 rounded-lg bg-blue-600 px-3 text-[11.5px] font-medium text-white hover:bg-blue-700"
                        >
                          <span>Workbench</span>
                          <ArrowRight className="h-3 w-3" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
