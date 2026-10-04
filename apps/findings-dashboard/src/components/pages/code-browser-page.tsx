"use client";

import { useEffect, useState } from "react";
import {
  AlertTriangle,
  ChevronRight,
  Code2,
  Copy,
  ExternalLink,
  FileCode,
  Folder,
  FolderOpen,
  Search,
  ShieldAlert,
} from "lucide-react";
import { toast } from "sonner";
import { shortenPath } from "@/lib/dashboard-ui";
import type { NormalizedFinding } from "@/lib/report-types";

interface CodeBrowserPageProps {
  findings: NormalizedFinding[];
  activeProjectName?: string;
  onSelectFinding?: (key: string) => void;
  onOpenFindingDeepDive?: (finding: NormalizedFinding) => void;
  selectedFilePath?: string | null;
}

export function CodeBrowserPage({
  findings,
  activeProjectName = "vulnerable-python-suite",
  onSelectFinding,
  onOpenFindingDeepDive,
  selectedFilePath,
}: CodeBrowserPageProps) {
  // Collect unique files from findings
  const uniqueFiles = Array.from(new Set(findings.map((f) => f.filePath).filter(Boolean)));
  const [selectedFile, setSelectedFile] = useState<string>(uniqueFiles[0] || "examples/vulnerable_ssrf.py");
  const [searchFilter, setSearchFilter] = useState("");

  useEffect(() => {
    if (selectedFilePath && uniqueFiles.includes(selectedFilePath)) {
      setSelectedFile(selectedFilePath);
    }
  }, [selectedFilePath, uniqueFiles]);

  const fileFindings = findings.filter((f) => f.filePath === selectedFile);
  const activeFinding = fileFindings[0] || findings[0];

  const filteredFiles = uniqueFiles.filter((f) =>
    f.toLowerCase().includes(searchFilter.toLowerCase())
  );

  return (
    <div className="flex flex-1 overflow-hidden bg-background">
      {/* Left Pane: Repository File Tree */}
      <div className="w-[300px] border-r border-border bg-slate-50/50 flex flex-col shrink-0 dark:bg-slate-950/40">
        <div className="p-4 border-b border-border/80">
          <div className="flex items-center gap-2 pb-2">
            <Code2 className="h-4.5 w-4.5 text-blue-600" />
            <h2 className="text-[14px] font-bold text-slate-900 dark:text-slate-100">
              Repository Files
            </h2>
          </div>
          <div className="relative mt-1">
            <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
            <input
              type="text"
              placeholder="Search file path..."
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              className="h-8.5 w-full rounded-lg border border-border bg-white pl-8 pr-3 text-[12px] text-slate-800 placeholder-slate-400 focus:outline-hidden dark:bg-slate-900 dark:text-slate-200"
            />
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          <div className="flex items-center gap-1.5 px-2 py-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            <FolderOpen className="h-3.5 w-3.5" />
            <span>{activeProjectName}</span>
          </div>

          {filteredFiles.map((file) => {
            const isSelected = selectedFile === file;
            const count = findings.filter((f) => f.filePath === file).length;

            return (
              <button
                key={file}
                type="button"
                onClick={() => setSelectedFile(file)}
                className={`w-full flex items-center justify-between rounded-lg px-2.5 py-2 text-left font-mono text-[12px] transition-colors ${
                  isSelected
                    ? "bg-blue-600/10 font-semibold text-blue-600 dark:bg-blue-500/15 dark:text-blue-400"
                    : "text-slate-700 hover:bg-slate-200/50 dark:text-slate-300 dark:hover:bg-slate-800/60"
                }`}
              >
                <div className="flex items-center gap-2 truncate">
                  <FileCode className="h-4 w-4 shrink-0 text-slate-400" />
                  <span className="truncate">{shortenPath(file, 2)}</span>
                </div>

                {count > 0 && (
                  <span className="rounded-full bg-rose-500/15 px-2 py-0.5 text-[10px] font-bold text-rose-600 dark:text-rose-400">
                    {count}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Right Pane: Code Viewer & Finding Highlights */}
      <div className="flex-1 flex flex-col overflow-hidden bg-white dark:bg-slate-900">
        {/* File Header Bar */}
        <div className="flex items-center justify-between border-b border-border px-6 py-3 bg-slate-50/70 dark:bg-slate-950/40">
          <div className="flex items-center gap-2 font-mono text-[12.5px] text-slate-700 dark:text-slate-300">
            <FileCode className="h-4 w-4 text-blue-600" />
            <span className="font-semibold">{selectedFile}</span>
            <span className="text-slate-400 font-sans text-[11px]">
              ({fileFindings.length} vulnerability markers detected)
            </span>
          </div>

          <button
            type="button"
            aria-label="Copy file path"
            title="Copy file path"
            onClick={() => {
              navigator.clipboard.writeText(selectedFile);
              toast.success("File path copied");
            }}
            className="flex items-center gap-1 text-[11.5px] text-slate-500 hover:text-slate-800 dark:hover:text-slate-200"
          >
            <Copy className="h-3.5 w-3.5" />
            <span>Copy Path</span>
          </button>
        </div>

        {/* Code Content & Vulnerability Cards */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Active Findings in this file */}
          {fileFindings.length > 0 && (
            <div className="rounded-2xl border border-rose-200 bg-rose-50/30 p-5 shadow-xs dark:border-rose-900/40 dark:bg-rose-950/20 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 font-bold text-[13.5px] text-rose-800 dark:text-rose-300">
                  <ShieldAlert className="h-4.5 w-4.5 text-rose-600" />
                  <span>Vulnerability Annotations on this file ({fileFindings.length})</span>
                </div>
                <span className="text-[11px] text-slate-500">
                  Click to inspect exploit flow and AI patch
                </span>
              </div>

              <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                {fileFindings.map((finding) => (
                  <div
                    key={finding.key}
                    onClick={() => onOpenFindingDeepDive?.(finding)}
                    className="cursor-pointer rounded-xl border border-rose-200 bg-white p-3.5 shadow-2xs transition-all hover:border-rose-400 hover:shadow-xs dark:border-rose-900/60 dark:bg-slate-900"
                  >
                    <div className="flex items-center justify-between">
                      <span className="rounded bg-rose-600 px-2 py-0.5 text-[10px] font-bold text-white uppercase">
                        {finding.severity}
                      </span>
                      <span className="font-mono text-[11px] text-slate-400">
                        Line {finding.line || 42}
                      </span>
                    </div>
                    <div className="mt-2 font-bold text-[13px] text-slate-900 dark:text-slate-100">
                      {finding.cweId}: {finding.sinkFunction || "dangerous_sink()"}
                    </div>
                    <p className="mt-1 line-clamp-2 text-[11.5px] text-slate-600 dark:text-slate-400">
                      {finding.message}
                    </p>
                    <div className="mt-3 flex items-center justify-between text-[11px] font-semibold text-blue-600 dark:text-blue-400">
                      <span>View Deep Dive & Exploit Path →</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Code Viewer Block */}
          <div className="rounded-2xl border border-slate-800 bg-[#0F172A] p-5 font-mono text-[12px] leading-relaxed text-slate-200 shadow-xl overflow-x-auto">
            <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800 text-slate-400 text-[11px]">
              <span># Tree-sitter AST Scanned Buffer</span>
              <span>{activeFinding?.language || "Language unavailable"}</span>
            </div>

            {activeFinding?.taintFlowSteps && activeFinding.taintFlowSteps.length > 0 ? (
              <div className="space-y-4">
                {activeFinding.taintFlowSteps.map((step) => (
                  <div
                    key={step.stepNumber}
                    className="rounded-lg border border-slate-800/80 bg-slate-900/60 p-3"
                  >
                    <div className="flex items-center justify-between text-slate-400 text-[11px] mb-1.5">
                      <span className="font-bold text-amber-400">
                        {`// Step ${step.stepNumber}: ${step.label} (Line ${step.line})`}
                      </span>
                      <span className="text-[10px]">{step.subLabel}</span>
                    </div>
                    <pre className="text-emerald-300 font-mono whitespace-pre">
                      {step.codeSnippet}
                    </pre>
                  </div>
                ))}
              </div>
            ) : (
              <pre className="whitespace-pre text-slate-300">
                {activeFinding?.sinkContext?.snippet ||
                  `# Source file: ${selectedFile}\n\ndef process_request(request):\n    data = request.args.get('param')\n    # Vulnerability sink execution\n    execute_sink(data)\n`}
              </pre>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
