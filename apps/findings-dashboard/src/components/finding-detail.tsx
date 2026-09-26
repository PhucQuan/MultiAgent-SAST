"use client";

import { useState } from "react";
import {
  AlertTriangle,
  Bot,
  CheckCircle2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronUp,
  Code2,
  Copy,
  ExternalLink,
  GitBranch,
  GitPullRequest,
  Info,
  Maximize2,
  RotateCcw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Volume2,
  VolumeX,
  XCircle,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { formatConfidence, formatLabel, shortenPath } from "@/lib/dashboard-ui";
import type {
  NormalizedFinding,
  ReviewerDisposition,
  ReviewerFeedback,
} from "@/lib/report-types";

interface FindingDetailProps {
  finding: NormalizedFinding | null;
  feedback?: ReviewerFeedback;
  loading?: boolean;
  onDisposition?: (disposition: ReviewerDisposition) => void;
  onMuteToggle?: (muted: boolean) => void;
  onSaveNote?: (note: string) => void;
  onReset?: () => void;
  currentIndex?: number;
  totalCount?: number;
  onNavigate?: (direction: "prev" | "next") => void;
  onExpand?: () => void;
}

export function FindingDetail({
  finding,
  feedback,
  loading,
  onDisposition,
  currentIndex = 1,
  totalCount = 30,
  onNavigate,
  onExpand,
}: FindingDetailProps) {
  const [activeTab, setActiveTab] = useState<
    "overview" | "taint" | "code" | "ai" | "remediation" | "references"
  >("overview");
  const [taintTraceOpen, setTaintTraceOpen] = useState(true);

  if (!finding) {
    return (
      <div className="flex h-full w-[480px] shrink-0 flex-col items-center justify-center border-l border-border bg-slate-50/50 p-6 text-center text-slate-400 dark:bg-slate-900/40">
        <Shield className="h-10 w-10 text-slate-300 dark:text-slate-700" />
        <p className="mt-3 text-[13px]">Select a finding to inspect exploit path and remediation.</p>
      </div>
    );
  }

  // Derived properties
  const sevUpper = finding.severity.toUpperCase();
  let sevBadgeClass = "bg-rose-600 text-white";
  if (sevUpper === "HIGH") sevBadgeClass = "bg-orange-500 text-white";
  if (sevUpper === "MEDIUM") sevBadgeClass = "bg-amber-500 text-white";
  if (sevUpper === "LOW") sevBadgeClass = "bg-slate-500 text-white";

  const steps = finding.taintFlowSteps || [];
  const patch = finding.remediationPatch;
  const ledger = finding.multiAgentLedger;

  return (
    <div className="flex h-full w-[490px] shrink-0 flex-col overflow-y-auto border-l border-border bg-white dark:bg-slate-900">
      {/* Top Navigation Bar */}
      <div className="flex items-center justify-between border-b border-border px-5 py-3 text-[12.5px]">
        <h2 className="font-bold text-slate-900 dark:text-slate-100">
          Vulnerability Details & Exploit Path
        </h2>

        <div className="flex items-center gap-1.5 text-slate-500">
          <button
            type="button"
            onClick={() => onNavigate?.("prev")}
            className="flex h-7 w-7 items-center justify-center rounded border border-border text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
          <span className="font-medium text-[11.5px] text-slate-700 dark:text-slate-300">
            {currentIndex} of {totalCount}
          </span>
          <button
            type="button"
            onClick={() => onNavigate?.("next")}
            className="flex h-7 w-7 items-center justify-center rounded border border-border text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
          >
            <ChevronRight className="h-4 w-4" />
          </button>

          {/* Full-screen expand icon */}
          <button
            type="button"
            onClick={onExpand}
            title="Expand Full View"
            className="ml-1 flex h-7 w-7 items-center justify-center rounded border border-border text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
          >
            <Maximize2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* Vulnerability Title Header */}
      <div className="border-b border-border p-5">
        <div className="flex items-start gap-3">
          <span
            className={`mt-0.5 rounded px-2 py-0.5 text-[11px] font-bold uppercase tracking-wider ${sevBadgeClass}`}
          >
            {finding.severity}
          </span>
          <div>
            <h1 className="text-[16px] font-bold text-slate-900 dark:text-slate-100">
              {finding.cweId}: {formatLabel(finding.family)} in {finding.sinkFunction || "send_file()"}
            </h1>
            <p className="mt-1 text-[12px] leading-5 text-slate-600 dark:text-slate-400">
              {finding.message ||
                "Arbitrary file access via unsanitized user input in download endpoint."}
            </p>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="mt-4 flex items-center gap-1 border-b border-border/80">
          {(
            [
              "overview",
              "taint",
              "code",
              "ai",
              "remediation",
              "references",
            ] as const
          ).map((tab) => (
            <button
              key={tab}
              type="button"
              onClick={() => setActiveTab(tab)}
              className={`border-b-2 px-3 py-1.5 text-[12px] font-semibold transition-colors capitalize ${
                activeTab === tab
                  ? "border-blue-600 text-blue-600 dark:text-blue-400"
                  : "border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200"
              }`}
            >
              {tab === "overview"
                ? "Overview"
                : tab === "taint"
                ? "Taint Flow"
                : tab === "code"
                ? "Code"
                : tab === "ai"
                ? "AI Analysis"
                : tab === "remediation"
                ? "Remediation"
                : "References"}
            </button>
          ))}
        </div>
      </div>

      {/* Main Tab Content */}
      <div className="flex-1 space-y-5 p-5">
        {/* 1. Taint Flow Trace (Vertical Stepper) */}
        <div className="rounded-xl border border-slate-200 bg-white shadow-xs dark:border-slate-800 dark:bg-slate-900">
          <div
            onClick={() => setTaintTraceOpen(!taintTraceOpen)}
            className="flex cursor-pointer items-center justify-between border-b border-border/80 px-4 py-3"
          >
            <div className="flex items-center gap-2">
              <span className="font-bold text-[13px] text-slate-900 dark:text-slate-100">
                Taint Flow Trace
              </span>
              <span className="rounded-full bg-slate-100 px-2 py-0.5 text-[10.5px] font-semibold text-slate-600 dark:bg-slate-800 dark:text-slate-400">
                3 Steps
              </span>
            </div>
            {taintTraceOpen ? (
              <ChevronUp className="h-4 w-4 text-slate-400" />
            ) : (
              <ChevronDown className="h-4 w-4 text-slate-400" />
            )}
          </div>

          {taintTraceOpen && (
            <div className="space-y-4 p-4">
              {steps.map((step, idx) => {
                const isFirst = idx === 0;
                const isLast = idx === steps.length - 1;

                let circleClass = "bg-amber-500 text-white";
                let codeBgClass = "bg-slate-50 border-slate-200 dark:bg-slate-950 dark:border-slate-800";
                if (step.role === "propagation") {
                  circleClass = "bg-blue-600 text-white";
                } else if (step.role === "sink") {
                  circleClass = "bg-rose-600 text-white";
                  codeBgClass = "bg-rose-50/50 border-rose-200 dark:bg-rose-950/20 dark:border-rose-900/40";
                }

                return (
                  <div key={step.stepNumber} className="relative flex items-start gap-3">
                    {/* Circle number */}
                    <div className="relative flex flex-col items-center">
                      <div
                        className={`flex h-6 w-6 items-center justify-center rounded-full text-[11px] font-bold shadow-xs ${circleClass}`}
                      >
                        {step.stepNumber}
                      </div>
                      {!isLast && (
                        <div className="h-16 w-0.5 bg-slate-200 dark:bg-slate-800" />
                      )}
                    </div>

                    {/* Step details */}
                    <div className="flex-1 pb-1">
                      <div className="flex items-center justify-between">
                        <span className="text-[12.5px] font-bold text-slate-900 dark:text-slate-100">
                          {step.label}
                        </span>
                        <span className="text-[10.5px] text-slate-500 truncate max-w-[200px]">
                          {step.subLabel}
                        </span>
                      </div>

                      {/* Code box */}
                      <div
                        className={`mt-1.5 rounded-lg border p-2.5 font-mono text-[11.5px] leading-relaxed text-slate-900 dark:text-slate-100 ${codeBgClass}`}
                      >
                        {step.codeSnippet}
                      </div>

                      {/* File location */}
                      <div className="mt-1 text-[11px] text-slate-500">
                        Line {step.line} | in{" "}
                        <span className="font-mono text-slate-700 dark:text-slate-300">
                          {shortenPath(step.file, 3)}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* 2. AI Multi-Agent Verdict (Auditor, Skeptic, Final Verdict) */}
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs dark:border-slate-800 dark:bg-slate-900">
          <div className="flex items-center gap-2 pb-3">
            <Bot className="h-4 w-4 text-blue-600" />
            <h3 className="font-bold text-[13px] text-slate-900 dark:text-slate-100">
              AI Multi-Agent Verdict
            </h3>
          </div>

          <div className="space-y-3">
            {/* Top Row: Auditor & Skeptic agents */}
            <div className="grid grid-cols-1 gap-2.5 text-[11.5px] sm:grid-cols-2">
              {/* Auditor Agent */}
              <div className="rounded-lg border border-rose-200 bg-rose-50/50 p-3 dark:border-rose-900/40 dark:bg-rose-950/20">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5 font-bold text-rose-700 dark:text-rose-400">
                    <ShieldAlert className="h-3.5 w-3.5 shrink-0" />
                    <span>Auditor Agent</span>
                  </div>
                  <span className="rounded bg-rose-200/60 px-1.5 py-0.5 text-[10px] font-semibold text-rose-800 dark:bg-rose-900/60 dark:text-rose-300">
                    Attack Path
                  </span>
                </div>
                <p className="mt-2 text-[11.5px] leading-relaxed text-slate-700 dark:text-slate-300">
                  {ledger?.auditorChecks?.[0] ||
                    "Validated exploit payload reaches dangerous sink without sanitization."}
                </p>
              </div>

              {/* Skeptic Agent */}
              <div className="rounded-lg border border-blue-200 bg-blue-50/50 p-3 dark:border-blue-900/40 dark:bg-blue-950/20">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5 font-bold text-blue-700 dark:text-blue-400">
                    <Shield className="h-3.5 w-3.5 shrink-0" />
                    <span>Skeptic Agent</span>
                  </div>
                  <span className="rounded bg-blue-200/60 px-1.5 py-0.5 text-[10px] font-semibold text-blue-800 dark:bg-blue-900/60 dark:text-blue-300">
                    Defense Check
                  </span>
                </div>
                <p className="mt-2 text-[11.5px] leading-relaxed text-slate-700 dark:text-slate-300">
                  {ledger?.skepticChecks?.[0] ||
                    "No guardrails, sanitization or allowlists detected in call scope."}
                </p>
              </div>
            </div>

            {/* Bottom Row: Final Verdict Banner (Full Width) */}
            <div className="rounded-lg border border-emerald-200 bg-emerald-50/60 p-3 dark:border-emerald-900/50 dark:bg-emerald-950/30">
              <div className="flex flex-wrap items-center justify-between gap-1.5">
                <div className="flex items-center gap-1.5 font-bold text-emerald-700 dark:text-emerald-400">
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
                  <span className="text-[12px]">{ledger?.finalVerdictStatus || finding.status}</span>
                </div>
                <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-[10.5px] font-semibold text-emerald-800 dark:bg-emerald-900/60 dark:text-emerald-300">
                  {ledger?.confidenceText || (finding.confidence == null ? "Confidence unavailable" : `${Math.round(finding.confidence * 100)}% confidence`)}
                </span>
              </div>
              <p className="mt-1.5 text-[11.5px] leading-relaxed text-slate-700 dark:text-slate-300">
                {ledger?.summary ||
                  "This is a real security issue and should be fixed."}
              </p>
            </div>
          </div>
        </div>

        {/* 3. Suggested Remediation (AI Generated Patch) */}
        {patch && (
          <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs dark:border-slate-800 dark:bg-slate-900">
            <div className="flex items-center justify-between pb-3">
              <div className="flex items-center gap-2">
                <Code2 className="h-4 w-4 text-emerald-600" />
                <h3 className="font-bold text-[13px] text-slate-900 dark:text-slate-100">
                  Suggested Remediation (AI Generated Patch)
                </h3>
              </div>

              <Button
                size="sm"
                disabled
                title="Feature in preview"
                className="h-7 gap-1.5 rounded-lg bg-blue-600 px-2.5 text-[11.5px] font-medium text-white hover:bg-blue-700"
              >
                <GitPullRequest className="h-3.5 w-3.5" />
                <span>Patch / PR (Preview)</span>
              </Button>
            </div>

            <div className="mb-2 flex items-center justify-between text-[11px] text-slate-500">
              <span className="font-mono">{shortenPath(patch.filePath, 3)}</span>
              <button
                type="button"
                aria-label="Copy remediation patch"
                title="Copy remediation patch"
                className="flex items-center gap-1 text-slate-500 hover:text-slate-800 dark:hover:text-slate-200"
              >
                <Copy className="h-3 w-3" />
                <span>Copy</span>
              </button>
            </div>

            {/* Code Diff Block */}
            <div className="overflow-hidden rounded-lg border border-slate-800 bg-[#0F172A] font-mono text-[11.5px] text-slate-200">
              {patch.diffLines.map((line, i) => {
                let rowBg = "";
                let textColor = "text-slate-300";
                let sign = " ";
                if (line.type === "remove") {
                  rowBg = "bg-rose-950/60";
                  textColor = "text-rose-300";
                  sign = "-";
                } else if (line.type === "add") {
                  rowBg = "bg-emerald-950/60";
                  textColor = "text-emerald-300 font-semibold";
                  sign = "+";
                }

                return (
                  <div
                    key={i}
                    className={`flex items-center px-3 py-0.5 ${rowBg}`}
                  >
                    <span className="w-6 select-none text-[10px] text-slate-500">
                      {line.lineNum ?? ""}
                    </span>
                    <span className="w-4 select-none text-slate-500">{sign}</span>
                    <span className={`flex-1 whitespace-pre ${textColor}`}>
                      {line.text}
                    </span>
                  </div>
                );
              })}
            </div>

            <p className="mt-2 text-[11px] text-slate-500">
              {patch.explanation}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
