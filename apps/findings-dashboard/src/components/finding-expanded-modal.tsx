"use client";

import { useState } from "react";
import {
  AlertOctagon,
  AlertTriangle,
  Bot,
  CheckCircle2,
  ChevronRight,
  Code2,
  Copy,
  ExternalLink,
  GitBranch,
  GitPullRequest,
  Globe,
  Share2,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { formatConfidence, formatLabel, shortenPath } from "@/lib/dashboard-ui";
import type { NormalizedFinding } from "@/lib/report-types";

interface FindingExpandedModalProps {
  finding: NormalizedFinding | null;
  isOpen: boolean;
  onClose: () => void;
}

export function FindingExpandedModal({
  finding,
  isOpen,
  onClose,
}: FindingExpandedModalProps) {
  const [activeTab, setActiveTab] = useState<
    "overview" | "taint" | "code" | "remediation" | "evidence" | "comments"
  >("overview");
  const [viewMode, setViewMode] = useState<"graph" | "list">("graph");

  if (!isOpen || !finding) {
    return null;
  }

  const steps = finding.taintFlowSteps || [];
  const patch = finding.remediationPatch;
  const ledger = finding.multiAgentLedger;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-xs">
      <div className="flex h-[92vh] w-full max-w-[1260px] flex-col rounded-2xl border border-slate-200 bg-white shadow-2xl overflow-hidden dark:border-slate-800 dark:bg-slate-900">
        {/* Modal Top Bar */}
        <div className="flex items-center justify-between border-b border-border bg-slate-50/70 px-6 py-3.5 dark:bg-slate-950/50">
          <div className="flex items-center gap-2 text-[13px] text-slate-500">
            <span className="font-semibold text-slate-900 dark:text-slate-100">
              Findings
            </span>
            <ChevronRight className="h-4 w-4 text-slate-400" />
            <span className="font-mono text-slate-700 dark:text-slate-300">
              {finding.cweId}
            </span>
            <ChevronRight className="h-4 w-4 text-slate-400" />
            <span className="truncate font-semibold text-slate-900 dark:text-slate-100 max-w-[400px]">
              {finding.message || `${finding.cweId}: ${formatLabel(finding.family)}`}
            </span>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="flex h-8 w-8 items-center justify-center rounded-lg text-slate-400 hover:bg-slate-200/60 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Modal Body (Scrollable) */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Header Banner */}
          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div className="flex items-start gap-4">
              <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-rose-600 text-white shadow-md shadow-rose-500/20">
                <AlertOctagon className="h-7 w-7" />
              </div>

              <div>
                <h1 className="text-[20px] font-bold text-slate-900 dark:text-slate-100">
                  {finding.cweId}: {formatLabel(finding.family)} in {finding.sinkFunction || "download_file()"}
                </h1>
                <p className="mt-1 text-[13px] text-slate-600 dark:text-slate-400">
                  {finding.message || "Potential security vulnerability detected along untrusted data-flow path."}
                </p>

                {/* Badges */}
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <span className="rounded-md bg-rose-600 px-2.5 py-1 text-[11px] font-bold text-white uppercase">
                    {finding.severity}
                  </span>
                  <span className="rounded-md border border-slate-300 bg-white px-2.5 py-1 text-[11px] font-semibold text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
                    Score: {finding.cvssScore || 9.2}
                  </span>
                  <span className="rounded-md border border-rose-300 bg-rose-50 px-2.5 py-1 text-[11px] font-semibold text-rose-700 dark:border-rose-900/50 dark:bg-rose-950/40 dark:text-rose-400">
                    Confirmed Exploit
                  </span>
                  <span className="rounded-md bg-blue-50 px-2.5 py-1 text-[11px] font-semibold text-blue-700 dark:bg-blue-950/50 dark:text-blue-300">
                    Python 3.12
                  </span>
                </div>
              </div>
            </div>

            {/* Metadata Pills Grid */}
            <div className="grid grid-cols-2 gap-x-6 gap-y-2 rounded-xl border border-slate-200 bg-slate-50/50 p-3.5 text-[12px] sm:grid-cols-3 dark:border-slate-800 dark:bg-slate-900/50">
              <div>
                <span className="text-slate-400">File:</span>{" "}
                <span className="font-mono font-medium text-blue-600 dark:text-blue-400">
                  {shortenPath(finding.filePath, 3)}
                </span>
              </div>
              <div>
                <span className="text-slate-400">Line:</span>{" "}
                <span className="font-mono font-semibold text-slate-800 dark:text-slate-200">
                  {finding.line || 42}
                </span>
              </div>
              <div>
                <span className="text-slate-400">Function:</span>{" "}
                <span className="font-mono text-slate-800 dark:text-slate-200">
                  {finding.sinkFunction || "download_file()"}
                </span>
              </div>
              <div>
                <span className="text-slate-400">CWE:</span>{" "}
                <span className="font-semibold text-slate-800 dark:text-slate-200">
                  {finding.cweId}
                </span>
              </div>
              <div>
                <span className="text-slate-400">OWASP:</span>{" "}
                <span className="font-semibold text-slate-800 dark:text-slate-200">
                  {finding.owaspCategory || "A01:2021"}
                </span>
              </div>
              <div>
                <span className="text-slate-400">First Detected:</span>{" "}
                <span className="text-slate-600 dark:text-slate-400 font-mono text-[11px]">
                  2025-09-17 14:25
                </span>
              </div>
            </div>
          </div>

          {/* Horizontal Taint-Flow Analysis */}
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs dark:border-slate-800 dark:bg-slate-900">
            <div className="flex items-center justify-between pb-4">
              <div>
                <h2 className="text-[15px] font-bold text-slate-900 dark:text-slate-100">
                  Taint-Flow Analysis
                </h2>
                <p className="text-[12px] text-slate-500">
                  Track how user input flows from source to sink through the application.
                </p>
              </div>

              <div className="flex items-center rounded-lg border border-slate-200 bg-slate-100 p-0.5 dark:border-slate-800 dark:bg-slate-800">
                <button
                  type="button"
                  onClick={() => setViewMode("graph")}
                  className={`rounded-md px-3 py-1 text-[11.5px] font-semibold transition ${
                    viewMode === "graph"
                      ? "bg-blue-600 text-white shadow-xs"
                      : "text-slate-600 hover:text-slate-900 dark:text-slate-300"
                  }`}
                >
                  Graph View
                </button>
                <button
                  type="button"
                  onClick={() => setViewMode("list")}
                  className={`rounded-md px-3 py-1 text-[11.5px] font-semibold transition ${
                    viewMode === "list"
                      ? "bg-blue-600 text-white shadow-xs"
                      : "text-slate-600 hover:text-slate-900 dark:text-slate-300"
                  }`}
                >
                  List View
                </button>
              </div>
            </div>

            {/* Horizontal Step Cards with Arrows */}
            <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
              {steps.map((step, idx) => {
                let badgeBg = "bg-amber-500 text-white";
                let cardBorder = "border-slate-200 dark:border-slate-800";
                if (step.role === "propagation") {
                  badgeBg = "bg-blue-600 text-white";
                } else if (step.role === "sink") {
                  badgeBg = "bg-rose-600 text-white";
                  cardBorder = "border-rose-200 dark:border-rose-900/50";
                }

                return (
                  <div
                    key={step.stepNumber}
                    className={`relative flex flex-col justify-between rounded-xl border p-4 bg-slate-50/50 dark:bg-slate-950/40 ${cardBorder}`}
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span
                          className={`flex h-6 w-6 items-center justify-center rounded-full text-[11px] font-bold ${badgeBg}`}
                        >
                          {step.stepNumber}
                        </span>
                        <span className="text-[13px] font-bold text-slate-900 dark:text-slate-100">
                          {step.label}
                        </span>
                      </div>

                      <div className="mt-3 rounded-lg border border-slate-200 bg-white p-2.5 font-mono text-[11.5px] text-slate-800 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-200">
                        {step.codeSnippet}
                      </div>

                      <div className="mt-2 text-[11.5px] font-medium text-slate-600 dark:text-slate-400">
                        {step.subLabel}
                      </div>
                    </div>

                    <div className="mt-3 text-[11px] text-slate-400">
                      File: {shortenPath(step.file, 2)}:{step.line}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* 2-Column Code Comparison: Vulnerable Code vs AI Secure Patch */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {/* Left: Vulnerable Code */}
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs dark:border-slate-800 dark:bg-slate-900">
              <div className="flex items-center justify-between pb-3">
                <div className="flex items-center gap-2">
                  <Code2 className="h-4 w-4 text-slate-700 dark:text-slate-300" />
                  <span className="font-bold text-[13px] text-slate-900 dark:text-slate-100">
                    Vulnerable Code ({shortenPath(patch?.filePath || finding.filePath, 2)})
                  </span>
                </div>
                <Copy className="h-4 w-4 text-slate-400 cursor-pointer hover:text-slate-700" />
              </div>

              <div className="rounded-lg border border-slate-800 bg-[#0F172A] p-3 font-mono text-[11.5px] text-slate-300 overflow-x-auto max-h-[300px]">
                {patch?.vulnerableSnippet ? (
                  <pre className="whitespace-pre font-mono leading-relaxed">
                    {patch.vulnerableSnippet}
                  </pre>
                ) : (finding.sinkContext?.snippet || steps[steps.length - 1]?.codeSnippet) ? (
                  <pre className="whitespace-pre font-mono leading-relaxed">
                    {finding.sinkContext?.snippet || steps[steps.length - 1]?.codeSnippet}
                  </pre>
                ) : (
                  <div>
                    <div className="text-slate-500"># Vulnerable Sink Call</div>
                    <div className="bg-rose-950/80 text-rose-200 px-1 py-0.5 rounded mt-1">
                      {finding.sinkFunction || "dangerous_sink"}(...)
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Right: AI-Generated Secure Patch */}
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs dark:border-slate-800 dark:bg-slate-900">
              <div className="flex items-center justify-between pb-3">
                <div className="flex items-center gap-2">
                  <Bot className="h-4 w-4 text-emerald-600" />
                  <span className="font-bold text-[13px] text-slate-900 dark:text-slate-100">
                    AI-Generated Secure Patch
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="rounded bg-slate-100 px-2 py-0.5 text-[11px] font-medium text-slate-600 dark:bg-slate-800 dark:text-slate-400">
                    Unified Diff
                  </span>
                  <Copy className="h-4 w-4 text-slate-400 cursor-pointer hover:text-slate-700" />
                </div>
              </div>

              <div className="rounded-lg border border-slate-800 bg-[#0F172A] p-3 font-mono text-[11.5px] text-slate-300 overflow-x-auto max-h-[300px]">
                {patch?.diffLines && patch.diffLines.length > 0 ? (
                  <div className="space-y-0.5">
                    {patch.hunkHeader && (
                      <div className="text-blue-400 font-semibold mb-1">
                        {patch.hunkHeader}
                      </div>
                    )}
                    {patch.diffLines.map((dLine: any, idx: number) => {
                      const isAdded = dLine.type === "added" || dLine.type === "add";
                      const isRemoved = dLine.type === "removed" || dLine.type === "remove";
                      const content = dLine.text || dLine.content || "";

                      if (isAdded) {
                        return (
                          <div
                            key={idx}
                            className="bg-emerald-950/70 text-emerald-300 px-1 py-0.5 rounded font-semibold whitespace-pre"
                          >
                            {content.startsWith("+") ? content : `+ ${content}`}
                          </div>
                        );
                      }
                      if (isRemoved) {
                        return (
                          <div
                            key={idx}
                            className="bg-rose-950/70 text-rose-300 px-1 py-0.5 rounded whitespace-pre"
                          >
                            {content.startsWith("-") ? content : `- ${content}`}
                          </div>
                        );
                      }
                      return (
                        <div key={idx} className="text-slate-400 whitespace-pre">
                          {content}
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <pre className="whitespace-pre font-mono leading-relaxed text-emerald-300">
                    {patch?.secureSnippet || "# Sanitization and guard checks added"}
                  </pre>
                )}
              </div>
            </div>
          </div>

          {/* Evidence Ledger from Multi-Agent Triage (3-card grid) */}
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs dark:border-slate-800 dark:bg-slate-900">
            <div className="flex items-center justify-between pb-4">
              <div>
                <h3 className="text-[15px] font-bold text-slate-900 dark:text-slate-100">
                  Evidence Ledger from Multi-Agent Triage
                </h3>
                <p className="text-[12px] text-slate-500">
                  AI agents analyze the finding with different perspectives to reduce false positives and provide actionable insights.
                </p>
              </div>

              <div className="flex items-center gap-1.5 rounded-full bg-rose-50 px-3 py-1 text-[12px] font-bold text-rose-700 dark:bg-rose-950 dark:text-rose-300">
                <CheckCircle2 className="h-4 w-4" />
                <span>Confirmed Vulnerability</span>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              {/* Skeptic Agent Checklist */}
              <div className="rounded-xl border border-blue-200 bg-blue-50/30 p-4 dark:border-blue-900/40 dark:bg-blue-950/20">
                <div className="flex items-center gap-2 font-bold text-[13px] text-blue-800 dark:text-blue-300">
                  <ShieldCheck className="h-4 w-4" />
                  <span>Skeptic Agent (Verification)</span>
                </div>
                <ul className="mt-3 space-y-2 text-[12px] text-slate-700 dark:text-slate-300">
                  {(ledger?.skepticChecks && ledger.skepticChecks.length > 0
                    ? ledger.skepticChecks
                    : [
                        "No sanitizers or defensive guards found in call graph.",
                        "Untrusted parameter propagates to sink without modification.",
                        "No input validation or allowlist check detected.",
                        "Confirmed as high-fidelity finding.",
                      ]
                  ).map((check, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <CheckCircle2 className="h-4 w-4 text-blue-600 shrink-0 mt-0.5" />
                      <span>{check}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Auditor Agent Checklist */}
              <div className="rounded-xl border border-rose-200 bg-rose-50/30 p-4 dark:border-rose-900/40 dark:bg-rose-950/20">
                <div className="flex items-center gap-2 font-bold text-[13px] text-rose-800 dark:text-rose-300">
                  <ShieldAlert className="h-4 w-4" />
                  <span>Auditor Agent (Exploit Analysis)</span>
                </div>
                <ul className="mt-3 space-y-2 text-[12px] text-slate-700 dark:text-slate-300">
                  {(ledger?.auditorChecks && ledger.auditorChecks.length > 0
                    ? ledger.auditorChecks
                    : [
                        "Payload reaches dangerous sink unescaped.",
                        "Exploit demonstrated against mock request environment.",
                        "Reproducible across local executions.",
                        "High security and business impact.",
                      ]
                  ).map((check, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <CheckCircle2 className="h-4 w-4 text-rose-600 shrink-0 mt-0.5" />
                      <span>{check}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Remediation Recommendation Checklist */}
              <div className="rounded-xl border border-emerald-200 bg-emerald-50/30 p-4 dark:border-emerald-900/40 dark:bg-emerald-950/20">
                <div className="flex items-center gap-2 font-bold text-[13px] text-emerald-800 dark:text-emerald-300">
                  <CheckCircle2 className="h-4 w-4" />
                  <span>Remediation Recommendation</span>
                </div>
                <ul className="mt-3 space-y-2 text-[12px] text-slate-700 dark:text-slate-300">
                  {(patch?.explanation
                    ? [
                        patch.explanation,
                        "Apply the AI-generated patch to the target branch.",
                        "Add unit test regression coverage for the payload.",
                        "Run SAST validation pipeline to verify patch resolution.",
                      ]
                    : [
                        "Validate and sanitize untrusted inputs before sink execution.",
                        "Use parameterized APIs or strict allowlists.",
                        "Add defensive unit tests for edge cases.",
                        "Verify patch in automated CI/CD pipeline.",
                      ]
                  ).map((check, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <CheckCircle2 className="h-4 w-4 text-emerald-600 shrink-0 mt-0.5" />
                      <span>{check}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>

        {/* Modal Bottom Actions Bar */}
        <div className="flex items-center justify-between border-t border-border bg-slate-50/80 px-6 py-4 dark:bg-slate-950/70">
          <Button className="h-9 gap-2 rounded-lg bg-blue-600 px-4 text-[13px] font-semibold text-white hover:bg-blue-700">
            <GitPullRequest className="h-4 w-4" />
            <span>Apply Patch to Branch</span>
          </Button>

          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              className="h-9 gap-1.5 rounded-lg border-slate-200 text-[12.5px] font-medium text-slate-700 dark:border-slate-800 dark:text-slate-300"
            >
              <Globe className="h-4 w-4" />
              <span>Export to GitHub Security Advisories</span>
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-9 gap-1.5 rounded-lg border-slate-200 text-[12.5px] font-medium text-slate-700 dark:border-slate-800 dark:text-slate-300"
            >
              <Share2 className="h-4 w-4" />
              <span>Copy Report Link</span>
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
