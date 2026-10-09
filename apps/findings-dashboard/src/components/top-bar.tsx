"use client";

import {
  Bell,
  ChevronRight,
  Download,
  FileCode,
  FolderGit2,
  Moon,
  PanelLeft,
  Play,
  RefreshCw,
  Search,
  Sparkles,
  Sun,
} from "lucide-react";

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

export function TopBar({
  report,
  selectedFamily,
  onSelectFamily,
  onImport,
  onRefresh,
  onExportSarif,
  onExportPatch,
  onRunScan,
  scanPending,
  findings,
  onOpenExplorer,
}: TopBarProps) {
  const { theme, toggleTheme } = useTheme();

  const actionable =
    (report?.triageSummary.confirmed ?? 0) + (report?.triageSummary.likely ?? 0);
  const suppressed = report?.triageSummary.suppressed ?? 0;

  const familyPills = [
    { id: "CWE-89", name: "CWE-89 SQLi", family: "SQL_INJECTION" },
    { id: "CWE-78", name: "CWE-78 Command", family: "COMMAND_INJECTION" },
    { id: "CWE-22", name: "CWE-22 Path Traversal", family: "PATH_TRAVERSAL" },
    { id: "CWE-502", name: "CWE-502 Deser", family: "INSECURE_DESERIALIZATION" },
  ].map((pill) => ({
    ...pill,
    count: findings.filter((finding) => finding.family === pill.family).length,
  }));

  const precision = report?.metrics.precision;
  const owaspScore = report?.metrics.owaspScore;

  return (
    <header className="flex h-16 w-full items-center justify-between border-b border-border bg-white px-5 select-none dark:bg-slate-900">
      {/* Left: Breadcrumbs & Quick Filters */}
      <div className="flex min-w-0 flex-1 items-center gap-3 overflow-hidden pr-3">
        {/* Breadcrumb */}
        <div className="flex shrink-0 items-center gap-1.5 text-[13px] font-medium text-slate-500 dark:text-slate-400">
          <FolderGit2 className="h-4 w-4 text-slate-400 shrink-0" />
          <span className="hover:text-slate-800 dark:hover:text-slate-200">
            Repositories
          </span>
          <ChevronRight className="h-3.5 w-3.5 text-slate-300 shrink-0" />
          <span className="font-semibold text-slate-900 dark:text-slate-100 max-w-[200px] truncate">
            {report?.shortName || "vulnerable-python-suite"}
          </span>
          <ChevronRight className="h-3.5 w-3.5 text-slate-300 shrink-0" />
            <span className="rounded-md bg-slate-100 px-2 py-0.5 text-[12px] font-mono font-medium text-slate-700 dark:bg-slate-800 dark:text-slate-300">
            {report ? `${report.scanProfile} · ${report.timestamp ?? "timestamp unavailable"}` : "No report selected"}
          </span>
        </div>

        {/* Divider */}
        <div className="h-5 w-px shrink-0 bg-slate-200 dark:bg-slate-700" />

        {/* Quick Vulnerability Families Pills */}
        <div className="hidden min-w-0 items-center gap-1.5 overflow-x-auto xl:flex">
          <span className="shrink-0 text-[11.5px] font-semibold uppercase tracking-wider text-slate-400">
            Families:
          </span>
          {familyPills.map((pill) => {
            const isSelected = selectedFamily === pill.id;
            return (
              <button
                key={pill.id}
                type="button"
                onClick={() => onSelectFamily?.(isSelected ? null : pill.id)}
                className={`flex shrink-0 items-center gap-1.5 rounded-full px-3 py-1 text-[12px] font-medium transition-colors ${
                  isSelected
                    ? "bg-blue-600 text-white shadow-xs"
                    : "bg-slate-100 text-slate-700 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700"
                }`}
              >
                <span>{pill.name}</span>
                <span
                  className={`rounded-full px-1.5 text-[10.5px] ${
                    isSelected
                      ? "bg-blue-700 text-blue-100"
                      : "bg-slate-200 text-slate-600 dark:bg-slate-700 dark:text-slate-400"
                  }`}
                >
                  {pill.count}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Right: Metrics, Theme Switcher, Search, and Profile */}
      <div className="flex shrink-0 items-center gap-3">
        <button
          type="button"
          onClick={onOpenExplorer}
          aria-label="Open scan explorer"
          title="Open scan explorer"
          className="flex h-8.5 w-8.5 items-center justify-center rounded-lg border border-border text-muted-foreground hover:bg-surface-muted hover:text-foreground lg:hidden"
        >
          <PanelLeft className="h-4 w-4" />
        </button>
        {/* Precision & OWASP Score Badges */}
        <div className="hidden items-center gap-2 lg:flex">
          <div className="flex items-center gap-1.5 rounded-lg border border-emerald-200 bg-emerald-50 px-2.5 py-1 text-[12px] font-medium text-emerald-700 dark:border-emerald-800/40 dark:bg-emerald-950/40 dark:text-emerald-400">
            <Sparkles className="h-3.5 w-3.5" />
            <span>Precision:</span>
            <span className="font-bold">{precision == null ? "n/a" : `${(precision * 100).toFixed(1)}%`}</span>
          </div>

          <div className="flex items-center gap-1.5 rounded-lg border border-blue-200 bg-blue-50 px-2.5 py-1 text-[12px] font-medium text-blue-700 dark:border-blue-800/40 dark:bg-blue-950/40 dark:text-blue-400">
            <span>OWASP Score:</span>
            <span className="font-bold">{owaspScore == null ? "n/a" : `${(owaspScore * 100).toFixed(1)}%`}</span>
          </div>

          {/* Actionable / Suppressed counts */}
          <div className="flex items-center gap-1.5 rounded-lg border border-rose-200 bg-rose-50 px-2.5 py-1 text-[12px] font-medium text-rose-700 dark:border-rose-900/40 dark:bg-rose-950/40 dark:text-rose-400">
            <span className="font-bold">{actionable}</span>
            <span>Actionable</span>
          </div>

          <div className="flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-100 px-2.5 py-1 text-[12px] font-medium text-slate-700 dark:border-slate-800 dark:bg-slate-800 dark:text-slate-300">
            <span className="font-bold">{suppressed}</span>
            <span>Suppressed (FP)</span>
          </div>
        </div>

        {/* Theme Toggle Button (Light / Dark) */}
        <button
          type="button"
          onClick={toggleTheme}
          title={theme === "dark" ? "Switch to Light Mode" : "Switch to Dark Mode"}
          aria-label="Toggle Light/Dark Theme"
          className="flex h-8.5 w-8.5 items-center justify-center rounded-lg border border-slate-200 text-slate-600 transition-colors hover:bg-slate-100 hover:text-slate-900 dark:border-slate-800 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-white"
        >
          {theme === "dark" ? (
            <Sun className="h-4 w-4 text-amber-400 transition-transform hover:rotate-45" />
          ) : (
            <Moon className="h-4 w-4 text-slate-700 transition-transform hover:-rotate-12" />
          )}
        </button>

        {/* Global Search Box */}
        <div className="relative hidden md:block">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search anything..."
            className="h-9 w-44 rounded-lg border border-border bg-slate-50 pl-8 pr-9 text-[12.5px] text-slate-800 placeholder-slate-400 transition-all focus:w-60 focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-blue-500/30 dark:bg-slate-800 dark:text-slate-200"
          />
          <kbd className="absolute right-2 top-2 rounded bg-slate-200 px-1.5 py-0.5 text-[10px] font-semibold text-slate-500 dark:bg-slate-700 dark:text-slate-400">
            ⌘K
          </kbd>
        </div>

        {/* Export Actions */}
        {onExportSarif && (
          <Button
            variant="outline"
            size="sm"
            onClick={onExportSarif}
            title="Download SARIF v2.1.0 document for GitHub Code Scanning"
            className="hidden h-8.5 gap-1.5 rounded-lg border-slate-200 bg-white px-2.5 text-[12px] font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-800 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700 lg:inline-flex"
          >
            <Download className="h-3.5 w-3.5 text-slate-500" />
            <span>SARIF</span>
          </Button>
        )}

        {onExportPatch && (
          <Button
            variant="outline"
            size="sm"
            onClick={onExportPatch}
            title="Download AI remediation Unified Diff patch (.patch)"
            className="hidden h-8.5 gap-1.5 rounded-lg border-slate-200 bg-white px-2.5 text-[12px] font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-800 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700 lg:inline-flex"
          >
            <FileCode className="h-3.5 w-3.5 text-blue-600" />
            <span>.patch</span>
          </Button>
        )}

        {/* Trigger Scan Button */}
        <Button
          size="sm"
          onClick={onRunScan}
          disabled={scanPending}
          className="h-8.5 gap-1.5 rounded-lg bg-blue-600 px-3 text-[12.5px] font-medium text-white hover:bg-blue-700"
        >
          {scanPending ? (
            <RefreshCw className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Play className="h-3.5 w-3.5 fill-current" />
          )}
          <span className="hidden sm:inline">
            {scanPending ? "Scanning..." : "Run Scan"}
          </span>
        </Button>

        {/* Notification bell */}
        <button
          type="button"
          title="Notifications"
          className="relative flex h-8.5 w-8.5 items-center justify-center rounded-lg text-slate-500 hover:bg-slate-100 hover:text-slate-800 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-200"
        >
          <Bell className="h-4 w-4" />
          <span className="absolute right-2 top-2 h-1.5 w-1.5 rounded-full bg-rose-500 ring-2 ring-white dark:ring-slate-900" />
        </button>

        {/* User Avatar */}
        <div className="flex items-center gap-2 border-l border-border pl-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-slate-900 text-[12px] font-semibold text-white dark:bg-blue-600">
            PQ
          </div>
          <div className="hidden flex-col text-left xl:flex">
            <span className="text-[12px] font-semibold leading-tight text-slate-900 dark:text-slate-100">
              Phuc Quan
            </span>
            <span className="text-[10.5px] leading-tight text-slate-400">
              Lead Security
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}
