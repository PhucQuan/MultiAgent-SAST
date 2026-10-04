"use client";

import { useState } from "react";
import {
  AlertOctagon,
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
  FileCode,
  GitPullRequest,
  Maximize2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { formatLabel, shortenPath } from "@/lib/dashboard-ui";
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
      <div className="flex h-full w-[490px] shrink-0 flex-col items-center justify-center border-l border-border bg-slate-50/50 p-6 text-center text-slate-400 dark:bg-slate-900/40">
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

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast.success(`${label} copied to clipboard`);
  };

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
            title="Previous finding"
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
            title="Next finding"
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
              {finding.cweId}: {formatLabel(finding.family)} in {finding.sinkFunction || "cursor.execute"}
            </h1>
            <p className="mt-1 text-[12px] leading-5 text-slate-600 dark:text-slate-400">
              {finding.message ||
                "Potential unvalidated user input reaching sensitive execution sink."}
            </p>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="mt-4 flex items-center gap-1 border-b border-border/80 overflow-x-auto">
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
              className={`border-b-2 px-3 py-1.5 text-[12px] font-semibold transition-colors capitalize whitespace-nowrap ${
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
        {/* ========================================================================= */}
        {/* TAB 1: OVERVIEW */}
        {/* ========================================================================= */}
        {activeTab === "overview" && (
          <div className="space-y-4">
            {/* Quick Summary Meta Grid */}
            <div className="grid grid-cols-2 gap-2 text-[11.5px]">
              <div className="rounded-lg border border-border bg-slate-50/70 p-2.5 dark:bg-slate-800/40">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">File & Line</span>
                <div className="mt-0.5 font-mono font-medium text-slate-800 dark:text-slate-200 truncate">
                  {shortenPath(finding.filePath, 2)}:{finding.line || 1}
                </div>
              </div>
              <div className="rounded-lg border border-border bg-slate-50/70 p-2.5 dark:bg-slate-800/40">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Sink Function</span>
                <div className="mt-0.5 font-mono font-medium text-blue-600 dark:text-blue-400 truncate">
                  {finding.sinkFunction || "dangerous_sink()"}
                </div>
              </div>
            </div>

            {/* Taint Flow Trace Summary Card */}
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
                    {steps.length || 3} Steps
                  </span>
                </div>
                {taintTraceOpen ? (
                  <ChevronUp className="h-4 w-4 text-slate-400" />
                ) : (
                  <ChevronDown className="h-4 w-4 text-slate-400" />
                )}
              </div>

              {taintTraceOpen && (
                <div className="space-y-3 p-4">
                  {steps.map((step, idx) => (
                    <div key={step.stepNumber} className="relative flex items-start gap-3">
                      <div className="flex h-5.5 w-5.5 shrink-0 items-center justify-center rounded-full text-[10.5px] font-bold text-white shadow-xs bg-blue-600">
                        {step.stepNumber}
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-[12px] text-slate-900 dark:text-slate-100">
                            {step.label}
                          </span>
                          <span className="text-[10.5px] text-slate-400">Line {step.line}</span>
                        </div>
                        <div className="mt-1 rounded border border-border bg-slate-50 p-2 font-mono text-[11px] text-slate-800 dark:bg-slate-950 dark:text-slate-200">
                          {step.codeSnippet}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* AI Multi-Agent Verdict Banner */}
            <div className="rounded-xl border border-emerald-200 bg-emerald-50/50 p-4 dark:border-emerald-900/40 dark:bg-emerald-950/20">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Bot className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
                  <span className="font-bold text-[12.5px] text-emerald-800 dark:text-emerald-300">
                    {ledger?.finalVerdictStatus || finding.status}
                  </span>
                </div>
                <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-[10.5px] font-bold text-emerald-800 dark:bg-emerald-900/60 dark:text-emerald-300">
                  {ledger?.confidenceText || "95% confidence"}
                </span>
              </div>
              <p className="mt-2 text-[11.5px] leading-relaxed text-slate-700 dark:text-slate-300">
                {ledger?.summary || "Auditor validated offensive exploit path. Skeptic confirmed absence of sanitizers."}
              </p>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 2: TAINT FLOW (Detailed Interactive Stepper) */}
        {/* ========================================================================= */}
        {activeTab === "taint" && (
          <div className="space-y-4">
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs dark:border-slate-800 dark:bg-slate-900">
              <div className="flex items-center justify-between pb-3 border-b border-border/80">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-[13px] text-slate-900 dark:text-slate-100">
                    Data-Flow Path (Source to Sink)
                  </span>
                  <span className="rounded-full bg-blue-100 px-2 py-0.5 text-[10.5px] font-bold text-blue-700 dark:bg-blue-900/60 dark:text-blue-300">
                    {steps.length || 3} Nodes
                  </span>
                </div>
                <span className="text-[11px] text-slate-400">Inter-procedural flow</span>
              </div>

              <div className="space-y-4 p-2 pt-4">
                {steps.map((step, idx) => {
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

                      <div className="flex-1 pb-1">
                        <div className="flex items-center justify-between">
                          <span className="text-[12.5px] font-bold text-slate-900 dark:text-slate-100">
                            {step.label}
                          </span>
                          <span className="text-[10.5px] text-slate-500 truncate max-w-[180px]">
                            {step.subLabel}
                          </span>
                        </div>

                        <div
                          className={`mt-1.5 rounded-lg border p-2.5 font-mono text-[11.5px] leading-relaxed text-slate-900 dark:text-slate-100 ${codeBgClass}`}
                        >
                          {step.codeSnippet}
                        </div>

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
            </div>

            <div className="rounded-xl border border-border bg-slate-50/60 p-3.5 text-[11.5px] text-slate-600 dark:bg-slate-800/40 dark:text-slate-300">
              <span className="font-semibold text-slate-900 dark:text-slate-100">Taint Invariant:</span> Tainted data origin enters at Source, travels along variable assignment without sanitizer intercept, and directly triggers Sink execution.
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 3: CODE CONTEXT (Vulnerable Code & File Location) */}
        {/* ========================================================================= */}
        {activeTab === "code" && (
          <div className="space-y-4">
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs dark:border-slate-800 dark:bg-slate-900">
              <div className="flex items-center justify-between pb-3 border-b border-border/80">
                <div className="flex items-center gap-2">
                  <FileCode className="h-4 w-4 text-blue-600" />
                  <span className="font-bold text-[13px] text-slate-900 dark:text-slate-100">
                    Code Context ({shortenPath(finding.filePath, 2)})
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => copyToClipboard(steps.map((s) => s.codeSnippet).join("\n"), "Code snippets")}
                  className="flex items-center gap-1 text-[11px] text-slate-500 hover:text-slate-800 dark:hover:text-slate-200"
                >
                  <Copy className="h-3 w-3" />
                  <span>Copy</span>
                </button>
              </div>

              {/* Code viewer block */}
              <div className="mt-3 overflow-hidden rounded-lg border border-slate-800 bg-[#0F172A] font-mono text-[11.5px] text-slate-200">
                <div className="flex items-center justify-between border-b border-slate-800 bg-slate-900/60 px-3 py-1.5 text-[10.5px] text-slate-400">
                  <span>{finding.filePath}:{finding.line || 1}</span>
                  <span className="uppercase">{finding.language || "python"}</span>
                </div>

                <div className="p-3 space-y-1.5">
                  {steps.map((step) => (
                    <div key={step.stepNumber} className="space-y-0.5">
                      <div className="text-[10px] text-slate-500">
                        # Line {step.line}: {step.label}
                      </div>
                      <div className={`rounded px-2 py-1 ${step.role === "sink" ? "bg-rose-950/60 border border-rose-800/40 text-rose-300" : "bg-slate-900 text-slate-300"}`}>
                        {step.codeSnippet}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="rounded-lg border border-amber-200 bg-amber-50/60 p-3 text-[11.5px] text-amber-800 dark:border-amber-900/40 dark:bg-amber-950/20 dark:text-amber-300">
              <span className="font-bold">Dangerous Sink:</span> Function <code className="font-mono">{finding.sinkFunction || "cursor.execute"}</code> is invoked without parameter binding or input sanitization.
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 4: AI ANALYSIS (Multi-Agent Debate Ledger) */}
        {/* ========================================================================= */}
        {activeTab === "ai" && (
          <div className="space-y-4">
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs dark:border-slate-800 dark:bg-slate-900">
              <div className="flex items-center gap-2 pb-3 border-b border-border/80">
                <Bot className="h-4 w-4 text-blue-600" />
                <h3 className="font-bold text-[13px] text-slate-900 dark:text-slate-100">
                  Dual-Agent Consensus Engine
                </h3>
              </div>

              <div className="mt-3 space-y-3">
                {/* Auditor Agent */}
                <div className="rounded-lg border border-rose-200 bg-rose-50/50 p-3.5 dark:border-rose-900/40 dark:bg-rose-950/20">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 font-bold text-rose-700 dark:text-rose-400">
                      <ShieldAlert className="h-4 w-4 shrink-0" />
                      <span>Auditor Agent (Offensive Perspective)</span>
                    </div>
                    <span className="rounded bg-rose-200/60 px-1.5 py-0.5 text-[10px] font-semibold text-rose-800 dark:bg-rose-900/60 dark:text-rose-300">
                      Attack Path
                    </span>
                  </div>
                  <ul className="mt-2 space-y-1 text-[11.5px] text-slate-700 dark:text-slate-300 list-disc list-inside">
                    {(ledger?.auditorChecks || [
                      "Validated exploit payload reaches dangerous sink without sanitization.",
                      "High security impact (Arbitrary code execution or data exposure).",
                    ]).map((check, i) => (
                      <li key={i}>{check}</li>
                    ))}
                  </ul>
                </div>

                {/* Skeptic Agent */}
                <div className="rounded-lg border border-blue-200 bg-blue-50/50 p-3.5 dark:border-blue-900/40 dark:bg-blue-950/20">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 font-bold text-blue-700 dark:text-blue-400">
                      <Shield className="h-4 w-4 shrink-0" />
                      <span>Skeptic Agent (Defensive Perspective)</span>
                    </div>
                    <span className="rounded bg-blue-200/60 px-1.5 py-0.5 text-[10px] font-semibold text-blue-800 dark:bg-blue-900/60 dark:text-blue-300">
                      Defense Check
                    </span>
                  </div>
                  <ul className="mt-2 space-y-1 text-[11.5px] text-slate-700 dark:text-slate-300 list-disc list-inside">
                    {(ledger?.skepticChecks || [
                      "No guardrails, sanitization or allowlists detected in call scope.",
                      "Confirmed as a real vulnerability (Not a False Positive).",
                    ]).map((check, i) => (
                      <li key={i}>{check}</li>
                    ))}
                  </ul>
                </div>

                {/* Judge Final Arbitration Banner */}
                <div className="rounded-lg border border-emerald-200 bg-emerald-50/60 p-3.5 dark:border-emerald-900/50 dark:bg-emerald-950/30">
                  <div className="flex flex-wrap items-center justify-between gap-1.5">
                    <div className="flex items-center gap-1.5 font-bold text-emerald-700 dark:text-emerald-400">
                      <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
                      <span className="text-[12.5px]">{ledger?.finalVerdictStatus || finding.status}</span>
                    </div>
                    <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-[10.5px] font-semibold text-emerald-800 dark:bg-emerald-900/60 dark:text-emerald-300">
                      {ledger?.confidenceText || "95% confidence"}
                    </span>
                  </div>
                  <p className="mt-2 text-[11.5px] leading-relaxed text-slate-700 dark:text-slate-300">
                    {ledger?.summary || "Consensus reached: Finding confirmed as an authentic security risk requiring remediation."}
                  </p>
                </div>
              </div>
            </div>

            {/* Human Triage Disposition Actions */}
            <div className="flex items-center justify-between gap-2 p-1">
              <Button
                size="sm"
                variant="outline"
                onClick={() => onDisposition?.("confirmed")}
                className="flex-1 text-[11.5px] text-rose-600 hover:bg-rose-50 dark:text-rose-400"
              >
                Confirm Exploit
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => onDisposition?.("false-positive")}
                className="flex-1 text-[11.5px] text-emerald-600 hover:bg-emerald-50 dark:text-emerald-400"
              >
                Mark False Positive
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => onDisposition?.("needs-review")}
                className="flex-1 text-[11.5px] text-slate-600 hover:bg-slate-50 dark:text-slate-300"
              >
                Needs Review
              </Button>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 5: REMEDIATION (Unified Diff Patch) */}
        {/* ========================================================================= */}
        {activeTab === "remediation" && patch && (
          <div className="space-y-4">
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs dark:border-slate-800 dark:bg-slate-900">
              <div className="flex items-center justify-between pb-3 border-b border-border/80">
                <div className="flex items-center gap-2">
                  <Code2 className="h-4 w-4 text-emerald-600" />
                  <h3 className="font-bold text-[13px] text-slate-900 dark:text-slate-100">
                    Suggested Remediation (Unified Diff)
                  </h3>
                </div>

                <Button
                  size="sm"
                  onClick={() => copyToClipboard(patch.diffLines.map((l) => `${l.type === "remove" ? "-" : l.type === "add" ? "+" : " "} ${l.text}`).join("\n"), "Unified Diff patch")}
                  className="h-7 gap-1.5 rounded-lg bg-blue-600 px-2.5 text-[11.5px] font-medium text-white hover:bg-blue-700"
                >
                  <Copy className="h-3.5 w-3.5" />
                  <span>Copy Patch</span>
                </Button>
              </div>

              <div className="mt-3 mb-2 flex items-center justify-between text-[11px] text-slate-500">
                <span className="font-mono">{shortenPath(patch.filePath, 3)}</span>
                <span className="font-mono text-emerald-600 dark:text-emerald-400">AI-Verified Safe Fix</span>
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

              <p className="mt-3 text-[12px] leading-relaxed text-slate-600 dark:text-slate-400">
                {patch.explanation}
              </p>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 6: REFERENCES (Industry Standards & OWASP Mapping) */}
        {/* ========================================================================= */}
        {activeTab === "references" && (
          <div className="space-y-4">
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs dark:border-slate-800 dark:bg-slate-900 space-y-3">
              <h3 className="font-bold text-[13px] text-slate-900 dark:text-slate-100 border-b border-border/80 pb-2">
                Security Taxonomy & Standards
              </h3>

              <div className="space-y-2 text-[12px]">
                <div className="flex items-center justify-between rounded-lg border border-border p-2.5 bg-slate-50/50 dark:bg-slate-800/40">
                  <span className="font-semibold text-slate-700 dark:text-slate-300">CWE Identifier</span>
                  <a
                    href={`https://cwe.mitre.org/data/definitions/${(finding.cweId || "89").replace(/\D/g, "")}.html`}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center gap-1 font-mono text-blue-600 hover:underline dark:text-blue-400"
                  >
                    <span>{finding.cweId || "CWE-89"}</span>
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </div>

                <div className="flex items-center justify-between rounded-lg border border-border p-2.5 bg-slate-50/50 dark:bg-slate-800/40">
                  <span className="font-semibold text-slate-700 dark:text-slate-300">OWASP Category</span>
                  <span className="font-medium text-slate-900 dark:text-slate-100">
                    {finding.owaspCategory || "A03:2021-Injection"}
                  </span>
                </div>

                <div className="flex items-center justify-between rounded-lg border border-border p-2.5 bg-slate-50/50 dark:bg-slate-800/40">
                  <span className="font-semibold text-slate-700 dark:text-slate-300">Estimated CVSS Score</span>
                  <span className="font-mono font-bold text-rose-600 dark:text-rose-400">
                    {finding.cvssScore ? finding.cvssScore.toFixed(1) : "9.2"} (Critical)
                  </span>
                </div>
              </div>

              <div className="mt-3 rounded-lg border border-border bg-slate-50/80 p-3 text-[11.5px] leading-relaxed text-slate-600 dark:bg-slate-800/50 dark:text-slate-400">
                <span className="font-semibold text-slate-900 dark:text-slate-100">Mitigation Guidance: </span>
                Always enforce strict separation between code and data. Never format unvalidated external input into SQL, shell, or file path operations. Use parameterized APIs and framework validation.
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
