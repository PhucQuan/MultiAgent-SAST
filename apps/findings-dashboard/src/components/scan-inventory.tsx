"use client";

import {
  CheckCircle2,
  Clock,
  Code2,
  FileCode2,
  FolderGit2,
  GitBranch,
  GitCommit,
  Layers,
  Server,
  ShieldAlert,
} from "lucide-react";

import { formatDateTime, shortenPath } from "@/lib/dashboard-ui";
import type { ReportSummaryCard } from "@/lib/report-types";

interface ScanInventoryProps {
  reports: ReportSummaryCard[];
  selectedReportId?: string | null;
  onSelectReport?: (report: ReportSummaryCard) => void;
  activeReport?: ReportSummaryCard | null;
  scannedTargets?: ScannedTarget[];
  selectedPath?: string | null;
  onSelectPath?: (path: string) => void;
  onOpenPath?: (path: string) => void;
}

export interface ScannedTarget {
  path: string;
  reportId?: string;
  name: string;
  findings: number;
  filesScanned: number;
  errors: number;
  scannedAt: string;
}

export function ScanInventory({
  reports,
  selectedReportId,
  onSelectReport,
  activeReport,
  scannedTargets = [],
  selectedPath,
  onSelectPath,
  onOpenPath,
}: ScanInventoryProps) {
  // Built-in targets for the workbench view
  const defaultTargets = [
    {
      id: "flask-backend",
      name: "Flask-API-Backend",
      findings: activeReport?.totalFindings ?? 30,
      active: true,
      tag: "Active",
      icon: "flask",
    },
    {
      id: "django-auth",
      name: "Django-Auth-Service",
      findings: 18,
      active: false,
      tag: "Ready",
      icon: "django",
    },
    {
      id: "node-gateway",
      name: "Node-Gateway",
      findings: 12,
      active: false,
      tag: "Ready",
      icon: "node",
    },
  ];

  const totalCrit = activeReport?.severitySummary?.critical ?? 5;
  const totalHigh = activeReport?.severitySummary?.high ?? 12;
  const totalMed = activeReport?.severitySummary?.medium ?? 8;
  const totalLow = activeReport?.severitySummary?.low ?? 5;
  const totalCount = activeReport?.totalFindings ?? 30;

  return (
    <div className="flex h-full w-full min-w-0 flex-col gap-4 border-r border-border bg-slate-50/70 p-3.5 dark:bg-slate-900/50">
      {/* Title */}
      <div className="flex items-center justify-between px-1">
        <h2 className="text-[13px] font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
          Scan Inventory
        </h2>
        <span className="rounded-full bg-slate-200 px-2 py-0.5 text-[11px] font-semibold text-slate-700 dark:bg-slate-800 dark:text-slate-300">
          {reports.length + scannedTargets.length || 3}
        </span>
      </div>

      {/* Target Repo Root Card */}
      <div className="rounded-xl border border-slate-200 bg-white p-3 shadow-xs dark:border-slate-800 dark:bg-slate-900">
        <div className="flex items-center gap-2">
          <FolderGit2 className="h-4 w-4 text-slate-700 dark:text-slate-300" />
          <span className="truncate text-[12.5px] font-bold text-slate-900 dark:text-slate-100">
            {activeReport?.shortName || "vulnerable-python-suite"}
          </span>
        </div>
        <p className="mt-1 text-[11px] text-slate-500">
          Educational vulnerable app for testing
        </p>
      </div>

      {/* Repository List Cards */}
      <div className="flex flex-col gap-1.5">
        {scannedTargets.map((target) => (
          <button
            key={target.path}
            type="button"
            onClick={() => onSelectPath?.(target.path)}
            onDoubleClick={() => onOpenPath?.(target.path)}
            className="rounded-xl border border-blue-200 bg-blue-50/70 p-2.5 dark:border-blue-900 dark:bg-blue-950/30"
            aria-pressed={selectedPath === target.path}
          >
            <div className="flex items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-200">
                {target.name.includes(".") ? (
                  <FileCode2 className="h-4 w-4" />
                ) : (
                  <FolderGit2 className="h-4 w-4" />
                )}
              </div>
              <div className="min-w-0">
                <div className="truncate text-[12.5px] font-semibold text-slate-900 dark:text-slate-100">
                  {target.name}
                </div>
                <div className="text-[11px] text-slate-500">
                  {target.findings} findings | {target.filesScanned} files
                </div>
              </div>
            </div>
            </button>
        ))}
        {/* Render loaded reports if available */}
        {reports.length > 0 ? (
          reports.slice(0, 4).map((report, idx) => {
            const isSelected =
              selectedReportId === report.id ||
              (!selectedReportId && idx === 0);
            return (
              <button
                key={report.id}
                type="button"
                onClick={() => onSelectReport?.(report)}
                className={`relative flex items-center justify-between rounded-xl border p-2.5 text-left transition-all ${
                  isSelected
                    ? "border-blue-400 bg-white shadow-xs ring-1 ring-blue-500/20 dark:border-blue-600 dark:bg-slate-900"
                    : "border-slate-200 bg-white hover:border-slate-300 dark:border-slate-800 dark:bg-slate-900/80"
                }`}
              >
                {isSelected ? (
                  <span className="absolute -left-1 top-2.5 h-7 w-1 rounded-r-full bg-blue-600" />
                ) : null}
                <div className="flex items-center gap-2.5 min-w-0">
                  <div
                    className={`flex h-8 w-8 items-center justify-center rounded-lg text-[11px] font-bold ${
                      idx === 0
                        ? "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300"
                        : idx === 1
                        ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300"
                        : "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300"
                    }`}
                  >
                    {idx === 0 ? "Py" : idx === 1 ? "Dj" : "JS"}
                  </div>
                  <div className="min-w-0">
                    <div className="truncate text-[12.5px] font-semibold text-slate-900 dark:text-slate-100">
                      {report.shortName}
                    </div>
                    <div className="text-[11px] text-slate-500">
                      {report.totalFindings} findings
                    </div>
                  </div>
                </div>

                {isSelected ? (
                  <span className="rounded-md bg-emerald-100 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300">
                    Active
                  </span>
                ) : null}
              </button>
            );
          })
        ) : (
          defaultTargets.map((target) => (
            <div
              key={target.id}
              className={`relative flex items-center justify-between rounded-xl border p-2.5 ${
                target.active
                  ? "border-blue-400 bg-white shadow-xs ring-1 ring-blue-500/20 dark:border-blue-600 dark:bg-slate-900"
                  : "border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900/80"
              }`}
            >
              {target.active ? (
                <span className="absolute -left-1 top-2.5 h-7 w-1 rounded-r-full bg-blue-600" />
              ) : null}
              <div className="flex items-center gap-2.5">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-amber-100 text-[11px] font-bold text-amber-800">
                  {target.icon === "flask"
                    ? "Py"
                    : target.icon === "django"
                    ? "Dj"
                    : "JS"}
                </div>
                <div>
                  <div className="text-[12.5px] font-semibold text-slate-900 dark:text-slate-100">
                    {target.name}
                  </div>
                  <div className="text-[11px] text-slate-500">
                    {target.findings} findings
                  </div>
                </div>
              </div>
              {target.active ? (
                <span className="rounded-md bg-emerald-100 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-700">
                  Active
                </span>
              ) : null}
            </div>
          ))
        )}
      </div>

      {/* Scan Details Card (matching image 1 bottom left) */}
      <div className="mt-auto rounded-xl border border-slate-200 bg-white p-3.5 shadow-xs dark:border-slate-800 dark:bg-slate-900">
        <h3 className="text-[12px] font-bold text-slate-900 dark:text-slate-100">
          Scan Details
        </h3>

        <div className="mt-2.5 flex flex-col gap-2 text-[11.5px]">
          <div className="flex items-center justify-between">
            <span className="text-slate-500">Scan ID</span>
            <span className="font-mono font-semibold text-slate-800 dark:text-slate-200">
              {activeReport?.id ? activeReport.id.slice(-8) : "n/a"}
            </span>
          </div>

          <div className="flex items-center justify-between">
            <span className="text-slate-500">Status</span>
            <div className="flex items-center gap-1 font-semibold text-emerald-600">
              <span className="h-2 w-2 rounded-full bg-emerald-500" />
              <span>Completed</span>
            </div>
          </div>

          <div className="flex items-center justify-between">
            <span className="text-slate-500">Started at</span>
            <span className="text-slate-700 dark:text-slate-300 font-mono text-[11px]">
              {activeReport?.timestamp
                ? formatDateTime(activeReport.timestamp)
                : "Unavailable"}
            </span>
          </div>

          <div className="flex items-center justify-between">
            <span className="text-slate-500">Duration</span>
            <span className="text-slate-800 dark:text-slate-200 font-medium">
              unavailable
            </span>
          </div>

          <div className="flex items-center justify-between">
            <span className="text-slate-500">Branch</span>
            <div className="flex items-center gap-1 font-mono text-slate-700 dark:text-slate-300">
              <GitBranch className="h-3 w-3 text-slate-400" />
              <span>branch unavailable</span>
            </div>
          </div>

          <div className="flex items-center justify-between">
            <span className="text-slate-500">Commit</span>
            <div className="flex items-center gap-1 font-mono text-blue-600">
              <GitCommit className="h-3 w-3" />
              <span>a1b2c3d</span>
            </div>
          </div>

          {/* Breakdown dots */}
          <div className="flex items-center justify-between pt-1">
            <span className="text-slate-500">Total Findings</span>
            <span className="font-bold text-slate-900 dark:text-slate-100">
              {totalCount}
            </span>
          </div>
          <div className="flex items-center gap-2 pt-0.5">
            <span className="flex items-center gap-1 text-[11px] text-slate-600 dark:text-slate-400">
              <span className="h-2.5 w-2.5 rounded-full bg-rose-500" />
              {totalCrit}
            </span>
            <span className="flex items-center gap-1 text-[11px] text-slate-600 dark:text-slate-400">
              <span className="h-2.5 w-2.5 rounded-full bg-orange-500" />
              {totalHigh}
            </span>
            <span className="flex items-center gap-1 text-[11px] text-slate-600 dark:text-slate-400">
              <span className="h-2.5 w-2.5 rounded-full bg-amber-400" />
              {totalMed}
            </span>
            <span className="flex items-center gap-1 text-[11px] text-slate-600 dark:text-slate-400">
              <span className="h-2.5 w-2.5 rounded-full bg-slate-400" />
              {totalLow}
            </span>
          </div>

          <div className="mt-1 border-t border-slate-100 pt-2 dark:border-slate-800">
            <div className="text-[11px] text-slate-500">Engine</div>
            <div className="truncate font-semibold text-slate-800 dark:text-slate-200">
              Tree-sitter DFG + AI Triage (v0.1.0)
            </div>
          </div>

          <div>
            <div className="text-[11px] text-slate-500">Ruleset</div>
            <div className="truncate font-semibold text-slate-800 dark:text-slate-200">
              OWASP Top 10 + Custom
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
