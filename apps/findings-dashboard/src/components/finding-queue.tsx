"use client";

import { useMemo, useState } from "react";
import {
  ChevronLeft,
  ChevronRight,
  Download,
  Filter,
  Search,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { formatLabel, shortenPath } from "@/lib/dashboard-ui";
import type {
  NormalizedFinding,
  ReviewerFeedbackStore,
  Severity,
  TriageStatus,
} from "@/lib/report-types";

export interface QueueFilters {
  search: string;
  status: string;
  severity: string;
  language: string;
  family: string;
  includeMuted: boolean;
}

interface FindingQueueProps {
  findings: NormalizedFinding[];
  total: number;
  feedbackStore: ReviewerFeedbackStore;
  filters: QueueFilters;
  onFiltersChange: (filters: QueueFilters) => void;
  selectedFindingKey: string | null;
  onSelectFinding: (findingKey: string) => void;
  languages: string[];
  families: string[];
  statuses: string[];
  severities: string[];
  loading?: boolean;
  error?: string | null;
}

export function FindingQueue({
  findings,
  total,
  filters,
  onFiltersChange,
  selectedFindingKey,
  onSelectFinding,
  families,
  statuses,
  severities,
  loading,
  error,
}: FindingQueueProps) {
  const filterKey = [
    filters.search,
    filters.status,
    filters.severity,
    filters.language,
    filters.family,
    filters.includeMuted ? "muted" : "visible",
  ].join("|");
  const [pagination, setPagination] = useState({ key: "", page: 1 });
  const currentPage = pagination.key === filterKey ? pagination.page : 1;
  const rowsPerPage = 12;

  // Pagination slice
  const totalPages = Math.max(1, Math.ceil(findings.length / rowsPerPage));
  const displayedFindings = useMemo(() => {
    const start = (currentPage - 1) * rowsPerPage;
    return findings.slice(start, start + rowsPerPage);
  }, [findings, currentPage, rowsPerPage]);

  const startIndex = findings.length === 0 ? 0 : (currentPage - 1) * rowsPerPage + 1;
  const endIndex = Math.min(currentPage * rowsPerPage, findings.length);

  return (
    <div className="flex flex-1 flex-col border-r border-border bg-white dark:bg-slate-900">
      {/* Table Header Controls */}
      <div className="border-b border-border p-4">
        <div className="flex items-center justify-between pb-3">
          <div className="flex items-center gap-2">
            <h2 className="text-[16px] font-bold text-slate-900 dark:text-slate-100">
              Findings
            </h2>
            <span className="rounded-full bg-slate-100 px-2.5 py-0.5 text-[12px] font-semibold text-slate-700 dark:bg-slate-800 dark:text-slate-300">
              {total}
            </span>
          </div>

          <Button
            variant="outline"
            size="sm"
            className="h-8 gap-1.5 rounded-lg border-slate-200 text-[12px] font-medium text-slate-700 dark:border-slate-800 dark:text-slate-300"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Export</span>
          </Button>
        </div>

        {/* Search Bar */}
        <div className="relative mb-3">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
          <input
            type="text"
            value={filters.search}
            onChange={(e) =>
              onFiltersChange({ ...filters, search: e.target.value })
            }
            placeholder="Search by rule ID, file path, sink, or reviewer..."
            className="h-9.5 w-full rounded-lg border border-border bg-slate-50 pl-9 pr-4 text-[12.5px] text-slate-900 placeholder-slate-400 focus:bg-white focus:outline-hidden focus:ring-2 focus:ring-blue-500/20 dark:bg-slate-800 dark:text-slate-100"
          />
        </div>

        {/* 3 Dropdown Filters */}
        <div className="grid grid-cols-3 gap-2">
          {/* Severity Dropdown */}
          <select
            value={filters.severity}
            onChange={(e) =>
              onFiltersChange({ ...filters, severity: e.target.value })
            }
            className="h-8.5 rounded-lg border border-border bg-white px-2.5 text-[12px] font-medium text-slate-700 focus:outline-hidden dark:bg-slate-800 dark:text-slate-200"
          >
            <option value="all">All Severities</option>
            {severities.map((sev) => (
              <option key={sev} value={sev}>
                {formatLabel(sev)}
              </option>
            ))}
          </select>

          {/* Family Dropdown */}
          <select
            value={filters.family}
            onChange={(e) =>
              onFiltersChange({ ...filters, family: e.target.value })
            }
            className="h-8.5 rounded-lg border border-border bg-white px-2.5 text-[12px] font-medium text-slate-700 focus:outline-hidden dark:bg-slate-800 dark:text-slate-200"
          >
            <option value="all">All Families</option>
            {families.map((fam) => (
              <option key={fam} value={fam}>
                {formatLabel(fam)}
              </option>
            ))}
          </select>

          {/* Triage Status Dropdown */}
          <select
            value={filters.status}
            onChange={(e) =>
              onFiltersChange({ ...filters, status: e.target.value })
            }
            className="h-8.5 rounded-lg border border-border bg-white px-2.5 text-[12px] font-medium text-slate-700 focus:outline-hidden dark:bg-slate-800 dark:text-slate-200"
          >
            <option value="all">All Statuses</option>
            {statuses.map((st) => (
              <option key={st} value={st}>
                {formatLabel(st)}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Main Table */}
      <div className="flex-1 overflow-x-auto">
        <table className="min-w-[660px] w-full border-collapse text-left text-[12.5px]">
          <thead>
            <tr className="border-b border-border bg-slate-50/80 text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:bg-slate-900/80">
              <th className="py-2.5 pl-4 pr-2 w-10">#</th>
              <th className="px-2 py-2.5 w-24">Severity</th>
              <th className="px-2 py-2.5 min-w-[130px]">Rule / Title</th>
              <th className="px-2 py-2.5 min-w-[140px]">File Location</th>
              <th className="px-2 py-2.5 min-w-[110px]">Sink / Function</th>
              <th className="py-2.5 pl-2 pr-4 min-w-[130px]">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {displayedFindings.map((finding, idx) => {
              const isSelected = selectedFindingKey === finding.key;
              const rowNum = (currentPage - 1) * rowsPerPage + idx + 1;

              // Severity badge color styling
              const sevUpper = finding.severity.toUpperCase();
              let sevClass =
                "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300";
              if (sevUpper === "CRITICAL") {
                sevClass =
                  "bg-rose-600 text-white font-bold shadow-xs";
              } else if (sevUpper === "HIGH") {
                sevClass =
                  "bg-orange-500 text-white font-bold shadow-xs";
              } else if (sevUpper === "MEDIUM") {
                sevClass =
                  "bg-amber-500 text-white font-bold shadow-xs";
              } else if (sevUpper === "LOW") {
                sevClass =
                  "bg-slate-500 text-white font-medium";
              }

              // Status badge styling
              const isConfirmed =
                finding.status === "confirmed" || finding.status === "likely";
              const isSuppressed = finding.status === "suppressed";

              return (
                <tr
                  key={finding.key}
                  onClick={() => onSelectFinding(finding.key)}
                  className={`group cursor-pointer transition-colors ${
                    isSelected
                      ? "border-l-4 border-l-blue-600 bg-blue-50/70 dark:bg-blue-950/40"
                      : "hover:bg-slate-50 dark:hover:bg-slate-800/60"
                  }`}
                >
                  {/* Row # */}
                  <td className="py-2.5 pl-4 pr-2 font-mono text-[11px] text-slate-400">
                    {rowNum}
                  </td>

                  {/* Severity Badge */}
                  <td className="px-2 py-2.5">
                    <span
                      className={`inline-block rounded px-2 py-0.5 text-[10px] uppercase tracking-wide ${sevClass}`}
                    >
                      {finding.severity}
                    </span>
                  </td>

                  {/* Rule / Title */}
                  <td className="px-2 py-2.5">
                    <div className="font-semibold text-slate-900 dark:text-slate-100">
                      {finding.cweId || "CWE-22"}
                    </div>
                    <div className="text-[11px] text-slate-500 truncate max-w-[130px]">
                      {formatLabel(finding.family)}
                    </div>
                  </td>

                  {/* File Location */}
                  <td className="px-2 py-2.5">
                    <span className="font-mono text-[11.5px] text-blue-600 hover:underline dark:text-blue-400">
                      {shortenPath(finding.filePath, 2)}
                      {finding.line ? `:${finding.line}` : ""}
                    </span>
                  </td>

                  {/* Sink / Function */}
                  <td className="px-2 py-2.5 font-mono text-[11.5px] text-slate-700 dark:text-slate-300">
                    {finding.sinkFunction || "send_file()"}
                  </td>

                  {/* Status Badge */}
                  <td className="py-2.5 pl-2 pr-4 whitespace-nowrap">
                    {isConfirmed ? (
                      <span className="inline-block rounded-md bg-rose-50 px-2 py-0.5 text-[10.5px] font-semibold text-rose-700 dark:bg-rose-950/50 dark:text-rose-300">
                        Confirmed by AI
                      </span>
                    ) : isSuppressed ? (
                      <span className="inline-block rounded-md bg-emerald-50 px-2 py-0.5 text-[10.5px] font-semibold text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-300">
                        Suppressed (FP)
                      </span>
                    ) : (
                      <span className="inline-block rounded-md bg-amber-50 px-2 py-0.5 text-[10.5px] font-semibold text-amber-700 dark:bg-amber-950/50 dark:text-amber-300">
                        Needs Review
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}

            {displayedFindings.length === 0 && !loading ? (
              <tr>
                <td
                  colSpan={6}
                  className="py-12 text-center text-[13px] text-slate-400"
                >
                  No findings matched your search or filters.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="flex items-center justify-between border-t border-border px-4 py-2.5 text-[11.5px] text-slate-500">
        <div>
          Showing {startIndex}-{endIndex} of {findings.length} findings
        </div>

        <div className="flex items-center gap-1">
          <button
            type="button"
            disabled={currentPage <= 1}
            onClick={() => setPagination({ key: filterKey, page: Math.max(1, currentPage - 1) })}
            className="flex h-7 w-7 items-center justify-center rounded border border-border text-slate-600 disabled:opacity-30 dark:text-slate-300"
          >
            <ChevronLeft className="h-3.5 w-3.5" />
          </button>

          {Array.from({ length: Math.min(3, totalPages) }).map((_, i) => {
            const pageNum = i + 1;
            const isCur = currentPage === pageNum;
            return (
              <button
                key={pageNum}
                type="button"
                onClick={() => setPagination({ key: filterKey, page: pageNum })}
                className={`flex h-7 w-7 items-center justify-center rounded border text-[11.5px] font-medium ${
                  isCur
                    ? "border-blue-600 bg-blue-600 text-white"
                    : "border-border text-slate-700 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
                }`}
              >
                {pageNum}
              </button>
            );
          })}

          <button
            type="button"
            disabled={currentPage >= totalPages}
            onClick={() => setPagination({ key: filterKey, page: Math.min(totalPages, currentPage + 1) })}
            className="flex h-7 w-7 items-center justify-center rounded border border-border text-slate-600 disabled:opacity-30 dark:text-slate-300"
          >
            <ChevronRight className="h-3.5 w-3.5" />
          </button>
        </div>

        <div className="flex items-center gap-1 text-[11.5px]">
          <span>Rows per page:</span>
          <span className="font-semibold text-slate-700 dark:text-slate-300">
            {rowsPerPage}
          </span>
        </div>
      </div>
    </div>
  );
}
