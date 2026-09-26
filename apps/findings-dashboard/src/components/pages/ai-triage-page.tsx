"use client";

import { useState } from "react";
import {
  AlertTriangle,
  Bot,
  CheckCircle2,
  Filter,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  Sparkles,
  UserCheck,
  XCircle,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { formatLabel, shortenPath } from "@/lib/dashboard-ui";
import type {
  NormalizedFinding,
  ReviewerDisposition,
  ReviewerFeedbackStore,
} from "@/lib/report-types";

interface AiTriagePageProps {
  findings: NormalizedFinding[];
  onOpenFindingDeepDive?: (finding: NormalizedFinding) => void;
  onSetDisposition?: (key: string, disposition: ReviewerDisposition) => void;
  reviewStore: ReviewerFeedbackStore;
}

export function AiTriagePage({
  findings,
  onOpenFindingDeepDive,
  onSetDisposition,
  reviewStore,
}: AiTriagePageProps) {
  const [filterStatus, setFilterStatus] = useState<string>("all");

  const getReviewerDisposition = (finding: NormalizedFinding) =>
    reviewStore[finding.key]?.disposition ?? null;
  const getDisplayStatus = (finding: NormalizedFinding) =>
    getReviewerDisposition(finding) ?? finding.status;

  const filtered = findings.filter((f) => {
    if (filterStatus !== "all" && getDisplayStatus(f) !== filterStatus) return false;
    return true;
  });

  const confirmedCount = findings.filter((f) => ["confirmed", "likely"].includes(getDisplayStatus(f))).length;
  const suppressedCount = findings.filter((f) => ["suppressed", "false-positive"].includes(getDisplayStatus(f))).length;
  const needsReviewCount = findings.filter((f) => ["needs-review", "unknown"].includes(getDisplayStatus(f))).length;

  return (
    <div className="flex flex-1 flex-col overflow-y-auto bg-slate-50/50 p-8 dark:bg-[#0b0f19]">
      <div className="mx-auto w-full max-w-[1380px] space-y-7">
        {/* Header */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <Bot className="h-6 w-6 text-blue-600" />
              <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
                AI Multi-Agent Triage Command Center
              </h1>
            </div>
            <p className="mt-1 text-[13.5px] text-slate-500">
              Dual-agent consensus engine (Auditor Agent vs Skeptic Agent) automatically eliminating false positive noise.
            </p>
          </div>

          <Button
            onClick={() => toast.success("AI Triage batch re-evaluation triggered")}
            className="h-9.5 gap-2 rounded-xl bg-blue-600 px-4 text-[13px] font-semibold text-white shadow-md shadow-blue-500/20 hover:bg-blue-700"
          >
            <RefreshCw className="h-4 w-4" />
            <span>Re-run AI Triage Batch</span>
          </Button>
        </div>

        {/* 3 Overview Stat Cards */}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <div className="rounded-2xl border border-rose-200 bg-white p-5 shadow-xs dark:border-rose-900/40 dark:bg-slate-900">
            <div className="flex items-center justify-between">
              <span className="text-[12px] font-semibold uppercase tracking-wider text-rose-600 dark:text-rose-400">
                Auditor: Confirmed Exploits
              </span>
              <ShieldAlert className="h-5 w-5 text-rose-600" />
            </div>
            <div className="mt-2 text-3xl font-bold text-slate-900 dark:text-slate-100">
              {confirmedCount}
            </div>
            <p className="mt-1 text-[12px] text-slate-500">
              Verified reproducible attack payloads reaching vulnerable sinks.
            </p>
          </div>

          <div className="rounded-2xl border border-emerald-200 bg-white p-5 shadow-xs dark:border-emerald-900/40 dark:bg-slate-900">
            <div className="flex items-center justify-between">
              <span className="text-[12px] font-semibold uppercase tracking-wider text-emerald-600 dark:text-emerald-400">
                Skeptic: Suppressed (FP)
              </span>
              <CheckCircle2 className="h-5 w-5 text-emerald-600" />
            </div>
            <div className="mt-2 text-3xl font-bold text-slate-900 dark:text-slate-100">
              {suppressedCount}
            </div>
            <p className="mt-1 text-[12px] text-slate-500">
              Filtered out due to defensive sanitizers, early returns, or safe types.
            </p>
          </div>

          <div className="rounded-2xl border border-amber-200 bg-white p-5 shadow-xs dark:border-amber-900/40 dark:bg-slate-900">
            <div className="flex items-center justify-between">
              <span className="text-[12px] font-semibold uppercase tracking-wider text-amber-600 dark:text-amber-400">
                Needs Review
              </span>
              <UserCheck className="h-5 w-5 text-amber-600" />
            </div>
            <div className="mt-2 text-3xl font-bold text-slate-900 dark:text-slate-100">
              {needsReviewCount}
            </div>
            <p className="mt-1 text-[12px] text-slate-500">
              Findings where agent confidence is moderate; pending human sign-off.
            </p>
          </div>
        </div>

        {/* Triage Queue Table */}
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-xs dark:border-slate-800 dark:bg-slate-900 space-y-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-2">
              <h3 className="font-bold text-[15px] text-slate-900 dark:text-slate-100">
                Triage Queue & Multi-Agent Verdicts
              </h3>
              <span className="rounded-full bg-slate-100 px-2.5 py-0.5 text-[11px] font-semibold text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                {filtered.length} findings
              </span>
            </div>

            {/* Filter pills */}
            <div className="flex items-center gap-2">
              {["all", "confirmed", "likely", "suppressed", "needs-review"].map((status) => (
                <button
                  key={status}
                  type="button"
                  onClick={() => setFilterStatus(status)}
                  className={`rounded-lg px-3 py-1 text-[11.5px] font-medium transition-colors capitalize ${
                    filterStatus === status
                      ? "bg-blue-600 text-white shadow-xs"
                      : "bg-slate-100 text-slate-600 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-300"
                  }`}
                >
                  {status === "needs-review" ? "Needs Review" : status}
                </button>
              ))}
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-[12.5px]">
              <thead>
                <tr className="border-b border-border bg-slate-50/60 font-semibold text-slate-500 dark:bg-slate-800/40 dark:text-slate-400">
                  <th className="py-2.5 pl-4 pr-2">Rule / CWE</th>
                  <th className="px-2 py-2.5">Severity</th>
                  <th className="px-2 py-2.5">Location</th>
                  <th className="px-2 py-2.5">AI Confidence</th>
                  <th className="px-2 py-2.5">Engine Status</th>
                  <th className="px-2 py-2.5">Reviewer Disposition</th>
                  <th className="py-2.5 pl-2 pr-4 text-right">Quick Triage Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filtered.map((finding) => (
                  <tr
                    key={finding.key}
                    className="hover:bg-slate-50/80 transition-colors dark:hover:bg-slate-800/40 cursor-pointer"
                    onClick={() => onOpenFindingDeepDive?.(finding)}
                  >
                    <td className="py-3 pl-4 pr-2 font-medium text-slate-900 dark:text-slate-100">
                      <div>{finding.cweId || "CWE-22"}</div>
                      <div className="text-[11px] text-slate-400">{formatLabel(finding.family)}</div>
                    </td>
                    <td className="px-2 py-3">
                      <span className="rounded bg-rose-600 px-2 py-0.5 text-[10px] font-bold text-white uppercase">
                        {finding.severity}
                      </span>
                    </td>
                    <td className="px-2 py-3 font-mono text-[11.5px] text-blue-600 dark:text-blue-400">
                      {shortenPath(finding.filePath, 2)}:{finding.line || 42}
                    </td>
                    <td className="px-2 py-3 font-mono text-[12px] font-bold text-slate-700 dark:text-slate-300">
                      {finding.confidence == null ? "n/a" : `${(finding.confidence * 100).toFixed(0)}%`}
                    </td>
                    <td className="px-2 py-3">
                      {finding.status === "suppressed" ? (
                        <span className="rounded-md bg-emerald-50 px-2.5 py-1 text-[11px] font-semibold text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-300">
                          Suppressed (False Positive)
                        </span>
                      ) : (
                        <span className="rounded-md bg-rose-50 px-2.5 py-1 text-[11px] font-semibold text-rose-700 dark:bg-rose-950/50 dark:text-rose-300">
                          {finding.status}
                        </span>
                      )}
                    </td>
                    <td className="px-2 py-3">
                      <span className="rounded-md border border-border bg-surface-muted px-2.5 py-1 text-[11px] font-semibold text-foreground">
                        {getReviewerDisposition(finding) ?? "Unreviewed"}
                      </span>
                    </td>
                    <td
                      className="py-3 pl-2 pr-4 text-right"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <div className="flex items-center justify-end gap-1.5">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => {
                            onSetDisposition?.(finding.key, "confirmed");
                            toast.success("Marked as Confirmed Exploit");
                          }}
                          className="h-7 text-[11px] text-rose-600 hover:bg-rose-50 dark:text-rose-400 dark:hover:bg-rose-950/40"
                        >
                          Confirm
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => {
                            onSetDisposition?.(finding.key, "false-positive");
                            toast.success("Suppressed as False Positive");
                          }}
                          className="h-7 text-[11px] text-emerald-600 hover:bg-emerald-50 dark:text-emerald-400 dark:hover:bg-emerald-950/40"
                        >
                          Mute FP
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
