'use client';

import {
  startTransition,
  useDeferredValue,
  useEffect,
  useEffectEvent,
  useRef,
  useState,
  useSyncExternalStore,
} from "react";
import { PanelLeft, X } from "lucide-react";
import { toast } from "sonner";

import { FindingDetail } from "@/components/finding-detail";
import { FindingQueue, type QueueFilters } from "@/components/finding-queue";
import { ReportSidebar, type ReportEntry } from "@/components/report-sidebar";
import { MetaTag } from "@/components/status-badge";
import { TopBar } from "@/components/top-bar";
import { Checkbox } from "@/components/ui/checkbox";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Sheet, SheetContent, SheetTitle } from "@/components/ui/sheet";
import { Toaster } from "@/components/ui/sonner";
import {
  describeReportSource,
  formatDateTime,
  formatLabel,
  severityRank,
  shortenPath,
  triageRank,
} from "@/lib/dashboard-ui";
import { normalizeReport, summarizeReport } from "@/lib/report-adapter";
import {
  clearReviewEntry,
  readReviewStore,
  serializeReviewStore,
  updateReviewStore,
  writeReviewStore,
} from "@/lib/review-store";
import type {
  NormalizedFinding,
  NormalizedReport,
  ReportSummaryCard,
  ReviewerDisposition,
  ReviewerFeedbackStore,
  Severity,
  TriageStatus,
} from "@/lib/report-types";

type ReportsIndexResponse = {
  reports?: ReportSummaryCard[];
  meta?: {
    totalReports: number;
    activeReports: number;
    archiveReports: number;
    includeArchive: boolean;
    recentLimit: number;
  };
  error?: string;
};

type ReportDetailResponse = {
  report?: NormalizedReport;
  error?: string;
};

type ScanApiResponse = {
  scan?: {
    selectedReportPath?: string | null;
    summary?: {
      files_scanned?: number;
      total_vulnerabilities?: number;
    };
    ai?: {
      requested?: boolean;
      enabled?: boolean;
      error?: string | null;
    };
  };
  error?: string;
};

type ScanJobStatus = "queued" | "running" | "completed" | "failed";

type ScanJobProgress = {
  stage: string | null;
  message: string | null;
  totalFiles: number | null;
  filesScanned: number | null;
  filesProcessed: number | null;
  findings: number | null;
  errors: number | null;
  currentFile: string | null;
  indexedFunctions: number | null;
  durationSeconds: number | null;
};

type ScanJobResponse = {
  job?: {
    id: string;
    status: ScanJobStatus;
    targetPath: string;
    enableAi: boolean;
    maxDepth: number;
    progressEvery: number;
    startedAt: string;
    updatedAt: string;
    finishedAt: string | null;
    progress: ScanJobProgress;
    logs: string[];
    result: ScanApiResponse["scan"] | null;
    error: string | null;
  };
  error?: string;
};

const emptyFilters: QueueFilters = {
  search: "",
  status: "all",
  severity: "all",
  language: "all",
  family: "all",
  includeMuted: false,
};

const defaultReportsMeta = {
  totalReports: 0,
  activeReports: 0,
  archiveReports: 0,
  includeArchive: false,
  recentLimit: 12,
};

const emptyScanJobProgress: ScanJobProgress = {
  stage: null,
  message: null,
  totalFiles: null,
  filesScanned: null,
  filesProcessed: null,
  findings: null,
  errors: null,
  currentFile: null,
  indexedFunctions: null,
  durationSeconds: null,
};

function sortByTimestamp<
  T extends { timestamp: string | null; totalFindings: number; id?: string; sourcePath?: string },
>(values: T[]): T[] {
  return [...values].sort((left, right) => {
    const leftTime = left.timestamp ? Date.parse(left.timestamp) : 0;
    const rightTime = right.timestamp ? Date.parse(right.timestamp) : 0;

    if (leftTime !== rightTime) {
      return rightTime - leftTime;
    }

    if (left.totalFindings !== right.totalFindings) {
      return right.totalFindings - left.totalFindings;
    }

    return (left.id ?? left.sourcePath ?? "").localeCompare(
      right.id ?? right.sourcePath ?? "",
    );
  });
}

function isKnownSeverity(
  value: Severity,
): value is Exclude<Severity, "unknown"> {
  return value !== "unknown";
}

function isKnownStatus(
  value: TriageStatus,
): value is Exclude<TriageStatus, "unknown"> {
  return value !== "unknown";
}

function createImportId(fileName: string): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return `imported/${crypto.randomUUID()}-${fileName}`;
  }

  return `imported/${Date.now()}-${Math.random().toString(16).slice(2)}-${fileName}`;
}

function sortFindings(
  findings: NormalizedFinding[],
  feedbackStore: ReviewerFeedbackStore,
): NormalizedFinding[] {
  return [...findings].sort((left, right) => {
    const leftMuted = feedbackStore[left.key]?.muted === true ? 1 : 0;
    const rightMuted = feedbackStore[right.key]?.muted === true ? 1 : 0;

    if (leftMuted !== rightMuted) {
      return leftMuted - rightMuted;
    }

    const statusDelta = triageRank(left.status) - triageRank(right.status);
    if (statusDelta !== 0) {
      return statusDelta;
    }

    const severityDelta =
      severityRank(left.severity) - severityRank(right.severity);
    if (severityDelta !== 0) {
      return severityDelta;
    }

    const confidenceDelta = (right.confidence ?? -1) - (left.confidence ?? -1);
    if (confidenceDelta !== 0) {
      return confidenceDelta;
    }

    return (left.line ?? 0) - (right.line ?? 0);
  });
}

function useMediaQuery(query: string) {
  return useSyncExternalStore(
    (onStoreChange) => {
      if (typeof window === "undefined") {
        return () => undefined;
      }

      const mediaQuery = window.matchMedia(query);
      const handler = () => onStoreChange();

      mediaQuery.addEventListener("change", handler);
      return () => mediaQuery.removeEventListener("change", handler);
    },
    () =>
      typeof window !== "undefined" ? window.matchMedia(query).matches : false,
    () => false,
  );
}

function useHydrated() {
  return useSyncExternalStore(
    () => () => undefined,
    () => true,
    () => false,
  );
}

function SummaryStatCard({
  label,
  value,
  accent = "default",
}: {
  label: string;
  value: string | number;
  accent?: "default" | "primary" | "warning";
}) {
  return (
    <div className="rounded-xl border border-border bg-background px-3 py-3">
      <div className="text-[10.5px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
        {label}
      </div>
      <div
        className={[
          "mt-1 num text-[20px] font-semibold tracking-tight",
          accent === "primary"
            ? "text-primary"
            : accent === "warning"
              ? "text-sev-high"
              : "text-foreground",
        ].join(" ")}
      >
        {value}
      </div>
    </div>
  );
}

function SelectedReportPanel({
  report,
  totalFindings,
  selectedFindings,
  reviewedLocally,
}: {
  report: ReportEntry | null;
  totalFindings: number;
  selectedFindings: number;
  reviewedLocally: number;
}) {
  if (!report) {
    return (
      <div className="rounded-2xl border border-dashed border-border bg-surface px-4 py-5">
        <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
          Current workspace
        </div>
        <h2 className="mt-1 text-[18px] font-semibold tracking-tight text-foreground">
          No report selected
        </h2>
        <p className="mt-2 max-w-2xl text-[12.5px] leading-6 text-muted-foreground">
          Import a JSON report or run a local scan to populate the review queue.
        </p>
      </div>
    );
  }

  const sourceDescriptor = describeReportSource(report.sourcePath);
  const actionable = report.triageSummary.confirmed + report.triageSummary.likely;

  return (
    <div className="rounded-2xl border border-border bg-surface px-4 py-4">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <MetaTag className="border-primary/25 bg-primary/8 text-primary">
              {sourceDescriptor.label}
            </MetaTag>
            <MetaTag>{formatLabel(report.reportKind)}</MetaTag>
            <MetaTag>{formatLabel(report.scanProfile)}</MetaTag>
          </div>
          <h2 className="mt-3 text-[18px] font-semibold tracking-tight text-foreground">
            {report.shortName}
          </h2>
          <p className="mt-1 text-[12.5px] leading-6 text-muted-foreground">
            {sourceDescriptor.detail}
          </p>
          <div className="mt-3 space-y-1 text-[12px] text-muted-foreground">
            <div className="font-mono">{shortenPath(report.target, 6)}</div>
            <div>
              Last updated {formatDateTime(report.timestamp)}
              {report.frameworkHints.length
                ? ` | ${report.frameworkHints.map((item) => formatLabel(item)).join(", ")}`
                : ""}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 xl:min-w-[420px]">
          <SummaryStatCard label="Total findings" value={totalFindings} />
          <SummaryStatCard label="Visible now" value={selectedFindings} accent="primary" />
          <SummaryStatCard label="Actionable" value={actionable} accent="warning" />
          <SummaryStatCard label="Local memory" value={reviewedLocally} />
        </div>
      </div>
    </div>
  );
}

function DashboardShellContent({ hydrated }: { hydrated: boolean }) {
  const [workspaceReports, setWorkspaceReports] = useState<ReportSummaryCard[]>([]);
  const [importedReports, setImportedReports] = useState<NormalizedReport[]>([]);
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null);
  const [loadedWorkspaceReport, setLoadedWorkspaceReport] =
    useState<NormalizedReport | null>(null);
  const [selectedFindingKey, setSelectedFindingKey] = useState<string | null>(null);
  const [loadingWorkspaceReports, setLoadingWorkspaceReports] = useState(true);
  const [listError, setListError] = useState<string | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);
  const [reportsMeta, setReportsMeta] = useState(defaultReportsMeta);
  const [reviewStore, setReviewStore] = useState<ReviewerFeedbackStore>(() =>
    hydrated ? readReviewStore() : {},
  );
  const [filters, setFilters] = useState<QueueFilters>(emptyFilters);
  const [showArchiveReports, setShowArchiveReports] = useState(false);
  const [explorerOpen, setExplorerOpen] = useState(false);
  const [detailOpen, setDetailOpen] = useState(false);
  const [scanSheetOpen, setScanSheetOpen] = useState(false);
  const [scanTargetPath, setScanTargetPath] = useState("");
  const [scanEnableAi, setScanEnableAi] = useState(false);
  const [scanMaxDepth, setScanMaxDepth] = useState("5");
  const [scanJobId, setScanJobId] = useState<string | null>(null);
  const [scanJobStatus, setScanJobStatus] = useState<ScanJobStatus | null>(null);
  const [scanJobProgress, setScanJobProgress] =
    useState<ScanJobProgress>(emptyScanJobProgress);
  const [scanJobLogs, setScanJobLogs] = useState<string[]>([]);
  const [scanJobResult, setScanJobResult] =
    useState<ScanApiResponse["scan"] | null>(null);
  const [scanJobError, setScanJobError] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const handledScanJobRef = useRef<string | null>(null);
  const deferredSearch = useDeferredValue(filters.search);
  const hasSidebar = useMediaQuery("(min-width: 1024px)");
  const scanRunning = scanJobStatus === "queued" || scanJobStatus === "running";

  useEffect(() => {
    if (!hydrated) {
      return;
    }

    writeReviewStore(reviewStore);
  }, [hydrated, reviewStore]);

  async function refreshWorkspaceReports(
    showToast = false,
    includeArchive = showArchiveReports,
  ): Promise<ReportSummaryCard[]> {
    setLoadingWorkspaceReports(true);

    try {
      const response = await fetch(
        includeArchive ? "/api/reports?includeArchive=1" : "/api/reports",
        { cache: "no-store" },
      );
      const data = (await response.json()) as ReportsIndexResponse;

      if (!response.ok) {
        throw new Error(data.error ?? "Unable to load workspace reports.");
      }

      const nextReports = sortByTimestamp(data.reports ?? []);
      setWorkspaceReports(nextReports);
      setReportsMeta({
        ...defaultReportsMeta,
        ...data.meta,
        includeArchive,
      });
      setListError(null);

      if (showToast) {
        toast.success("Reports refreshed", {
          description: includeArchive
            ? `${nextReports.length} report${
                nextReports.length === 1 ? "" : "s"
              } loaded.`
            : `${nextReports.length} recent scan${
                nextReports.length === 1 ? "" : "s"
              } shown.`,
        });
      }

      return nextReports;
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Unable to load workspace reports.";

      setWorkspaceReports([]);
      setReportsMeta({
        ...defaultReportsMeta,
        includeArchive,
      });
      setListError(message);

      if (showToast) {
        toast.error("Refresh failed", { description: message });
      }

      return [];
    } finally {
      setLoadingWorkspaceReports(false);
    }
  }

  useEffect(() => {
    let cancelled = false;

    void (async () => {
      try {
        const response = await fetch(
          showArchiveReports ? "/api/reports?includeArchive=1" : "/api/reports",
          { cache: "no-store" },
        );
        const data = (await response.json()) as ReportsIndexResponse;

        if (!response.ok) {
          throw new Error(data.error ?? "Unable to load workspace reports.");
        }

        if (!cancelled) {
          setWorkspaceReports(sortByTimestamp(data.reports ?? []));
          setReportsMeta({
            ...defaultReportsMeta,
            ...data.meta,
            includeArchive: showArchiveReports,
          });
          setListError(null);
        }
      } catch (error) {
        if (!cancelled) {
          setWorkspaceReports([]);
          setReportsMeta({
            ...defaultReportsMeta,
            includeArchive: showArchiveReports,
          });
          setListError(
            error instanceof Error
              ? error.message
              : "Unable to load workspace reports.",
          );
        }
      } finally {
        if (!cancelled) {
          setLoadingWorkspaceReports(false);
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [showArchiveReports]);

  const importedEntries: ReportEntry[] = sortByTimestamp(
    importedReports.map((report) => ({
      ...summarizeReport(report),
      origin: "imported" as const,
    })),
  );
  const workspaceEntries: ReportEntry[] = workspaceReports.map((report) => ({
    ...report,
    origin: "workspace" as const,
  }));
  const reportEntries = sortByTimestamp([...importedEntries, ...workspaceEntries]);

  const effectiveSelectedReportId =
    selectedReportId && reportEntries.some((report) => report.id === selectedReportId)
      ? selectedReportId
      : reportEntries[0]?.id ?? null;

  const selectedImportedReport =
    importedReports.find((report) => report.id === effectiveSelectedReportId) ?? null;
  const selectedWorkspaceReport =
    workspaceReports.find((report) => report.id === effectiveSelectedReportId) ?? null;
  const selectedReportSummary =
    reportEntries.find((report) => report.id === effectiveSelectedReportId) ?? null;

  function handleOpenScanSheet() {
    if (!scanTargetPath.trim() && selectedReportSummary?.target) {
      setScanTargetPath(selectedReportSummary.target);
    }

    setScanSheetOpen(true);
  }

  function applyScanJob(job: NonNullable<ScanJobResponse["job"]>) {
    setScanJobId(job.id);
    setScanJobStatus(job.status);
    setScanJobProgress(job.progress ?? emptyScanJobProgress);
    setScanJobLogs(job.logs ?? []);
    setScanJobResult(job.result ?? null);
    setScanJobError(job.error ?? null);
  }

  const finalizeCompletedScan = useEffectEvent(
    async (job: NonNullable<ScanJobResponse["job"]>) => {
      if (handledScanJobRef.current === job.id) {
        return;
      }

      handledScanJobRef.current = job.id;

      const nextReports = await refreshWorkspaceReports(false);
      const selectedReportPath = job.result?.selectedReportPath;
      const nextSelectedReportId = selectedReportPath ?? nextReports[0]?.id ?? null;

      if (nextSelectedReportId) {
        startTransition(() => {
          setSelectedReportId(nextSelectedReportId);
          setSelectedFindingKey(null);
          setFilters(emptyFilters);
        });
        setLoadedWorkspaceReport(null);
        setReportError(null);
      }

      const filesScanned = job.result?.summary?.files_scanned ?? 0;
      const findings = job.result?.summary?.total_vulnerabilities ?? 0;
      const aiRequested = job.result?.ai?.requested === true;
      const aiEnabled = job.result?.ai?.enabled === true;
      const aiDetail = aiRequested
        ? aiEnabled
          ? "AI triage overlay applied."
          : job.result?.ai?.error
            ? `AI unavailable: ${job.result.ai.error}`
            : "AI triage unavailable for this run."
        : "Deterministic triage only.";

      if (filesScanned === 0) {
        toast("Scan finished with no supported files", {
          description: `Check the target path or local analyzer availability. ${aiDetail}`,
        });
        return;
      }

      toast.success("Local scan complete", {
        description: `${filesScanned} file${
          filesScanned === 1 ? "" : "s"
        } scanned, ${findings} finding${
          findings === 1 ? "" : "s"
        }. ${aiDetail}`,
      });
    },
  );

  const finalizeFailedScan = useEffectEvent(
    (job: NonNullable<ScanJobResponse["job"]>) => {
      if (handledScanJobRef.current === job.id) {
        return;
      }

      handledScanJobRef.current = job.id;
      toast.error("Scan failed", {
        description: job.error ?? "Unable to run the local scan.",
      });
    },
  );

  useEffect(() => {
    if (!scanJobId || !scanRunning) {
      return;
    }

    let cancelled = false;

    const pollJob = async () => {
      try {
        const response = await fetch(
          `/api/scan?jobId=${encodeURIComponent(scanJobId)}`,
          { cache: "no-store" },
        );
        const data = (await response.json()) as ScanJobResponse;

        if (!response.ok || !data.job) {
          throw new Error(data.error ?? "Unable to load scan status.");
        }

        if (cancelled) {
          return;
        }

        applyScanJob(data.job);

        if (data.job.status === "completed") {
          await finalizeCompletedScan(data.job);
        } else if (data.job.status === "failed") {
          finalizeFailedScan(data.job);
        }
      } catch (error) {
        if (cancelled) {
          return;
        }

        const message =
          error instanceof Error ? error.message : "Unable to load scan status.";
        setScanJobStatus("failed");
        setScanJobError(message);
        toast.error("Scan status failed", { description: message });
      }
    };

    void pollJob();
    const intervalId = window.setInterval(() => {
      void pollJob();
    }, 1500);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [scanJobId, scanRunning]);

  useEffect(() => {
    if (
      !effectiveSelectedReportId ||
      selectedImportedReport ||
      !selectedWorkspaceReport
    ) {
      return;
    }

    if (loadedWorkspaceReport?.id === effectiveSelectedReportId) {
      return;
    }

    let cancelled = false;

    void (async () => {
      try {
        const response = await fetch(
          `/api/reports?path=${encodeURIComponent(selectedWorkspaceReport.sourcePath)}`,
          { cache: "no-store" },
        );
        const data = (await response.json()) as ReportDetailResponse;

        if (!response.ok || !data.report) {
          throw new Error(data.error ?? "Unable to load selected report.");
        }

        if (!cancelled) {
          setLoadedWorkspaceReport(data.report);
          setReportError(null);
        }
      } catch (error) {
        if (!cancelled) {
          const message =
            error instanceof Error
              ? error.message
              : "Unable to load selected report.";

          setLoadedWorkspaceReport(null);
          setReportError(message);
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [
    effectiveSelectedReportId,
    loadedWorkspaceReport?.id,
    selectedImportedReport,
    selectedWorkspaceReport,
  ]);

  const selectedReport =
    selectedImportedReport ??
    (loadedWorkspaceReport?.id === effectiveSelectedReportId
      ? loadedWorkspaceReport
      : null);
  const loadingSelectedReport = Boolean(
    effectiveSelectedReportId &&
      !selectedImportedReport &&
      selectedWorkspaceReport &&
      loadedWorkspaceReport?.id !== effectiveSelectedReportId &&
      !reportError,
  );

  const allFindings = selectedReport?.findings ?? [];

  const statusOptions = Array.from(
    new Set(allFindings.map((finding) => finding.status).filter(isKnownStatus)),
  ).sort((left, right) => triageRank(left) - triageRank(right));
  const severityOptions = Array.from(
    new Set(allFindings.map((finding) => finding.severity).filter(isKnownSeverity)),
  ).sort((left, right) => severityRank(left) - severityRank(right));
  const languageOptions = Array.from(
    new Set(
      allFindings
        .map((finding) => finding.language)
        .filter((language) => language && language !== "unknown"),
    ),
  ).sort((left, right) => left.localeCompare(right));
  const familyOptions = Array.from(
    new Set(allFindings.map((finding) => finding.family)),
  ).sort((left, right) => left.localeCompare(right));

  const searchNeedle = deferredSearch.trim().toLowerCase();
  const filteredFindings = sortFindings(
    allFindings.filter((finding) => {
      const feedback = reviewStore[finding.key];

      if (!filters.includeMuted && feedback?.muted) {
        return false;
      }

      if (filters.status !== "all" && finding.status !== filters.status) {
        return false;
      }

      if (filters.severity !== "all" && finding.severity !== filters.severity) {
        return false;
      }

      if (filters.language !== "all" && finding.language !== filters.language) {
        return false;
      }

      if (filters.family !== "all" && finding.family !== filters.family) {
        return false;
      }

      if (!searchNeedle) {
        return true;
      }

      const haystack = [
        finding.id,
        finding.family,
        finding.message,
        finding.filePath,
        finding.explanation,
        finding.recommendation,
        finding.knowledgeCards.join(" "),
        finding.reasonCodes.join(" "),
        finding.reasoningNotes.join(" "),
        feedback?.note ?? "",
      ]
        .join(" ")
        .toLowerCase();

      return haystack.includes(searchNeedle);
    }),
    reviewStore,
  );

  const effectiveSelectedFindingKey =
    selectedFindingKey &&
    filteredFindings.some((finding) => finding.key === selectedFindingKey)
      ? selectedFindingKey
      : filteredFindings[0]?.key ?? null;

  const selectedFinding =
    filteredFindings.find((finding) => finding.key === effectiveSelectedFindingKey) ??
    null;

  function handleSelectReport(reportId: string) {
    startTransition(() => {
      setSelectedReportId(reportId);
      setSelectedFindingKey(null);
      setFilters(emptyFilters);
    });
    setReportError(null);
    setExplorerOpen(false);
  }

  function handleSelectFinding(findingKey: string) {
    startTransition(() => {
      setSelectedFindingKey(findingKey);
    });
    setDetailOpen(true);
  }

  function handleImportRequest() {
    fileInputRef.current?.click();
  }

  async function handleRunScan() {
    const targetPath = scanTargetPath.trim();
    if (!targetPath) {
      toast.error("Target path is required", {
        description: "Enter a local file or repository path before starting a scan.",
      });
      return;
    }

    const parsedDepth = Number(scanMaxDepth);
    const maxDepth = Number.isFinite(parsedDepth)
      ? Math.max(1, Math.min(parsedDepth, 20))
      : 5;

    setScanJobId(null);
    setScanJobStatus("queued");
    setScanJobProgress({
      ...emptyScanJobProgress,
      stage: "queued",
      message: "Submitting local scan request.",
    });
    setScanJobLogs(["Preparing local scan request..."]);
    setScanJobResult(null);
    setScanJobError(null);
    handledScanJobRef.current = null;

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          targetPath,
          enableAi: scanEnableAi,
          maxDepth,
        }),
      });
      const data = (await response.json()) as ScanJobResponse;

      if (!response.ok || !data.job) {
        throw new Error(data.error ?? "Unable to start the local scan.");
      }

      applyScanJob(data.job);
      toast("Local scan started", {
        description: "Progress and logs will update live in this panel.",
      });
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Unable to start the local scan.";

      setScanJobStatus("failed");
      setScanJobError(message);
      setScanJobLogs((current) => [...current, `Failed to start scan: ${message}`]);
      toast.error("Scan failed", { description: message });
    }
  }

  async function handleImportFiles(files: FileList | null) {
    if (!files?.length) {
      return;
    }

    const nextReports: NormalizedReport[] = [];
    const issues: string[] = [];

    for (const file of Array.from(files)) {
      try {
        const content = await file.text();
        const parsed = JSON.parse(content) as unknown;
        const report = normalizeReport(parsed, createImportId(file.name));

        if (!report) {
          issues.push(`${file.name}: unsupported report shape.`);
          continue;
        }

        nextReports.push(report);
      } catch {
        issues.push(`${file.name}: invalid JSON.`);
      }
    }

    if (nextReports.length) {
      setImportedReports((current) => sortByTimestamp([...nextReports, ...current]));
      setReportError(null);

      startTransition(() => {
        setSelectedReportId(nextReports[0].id);
        setSelectedFindingKey(null);
        setFilters(emptyFilters);
      });

      toast.success("Imported report bundle", {
        description: `${nextReports.length} report${
          nextReports.length === 1 ? "" : "s"
        } loaded into the dashboard.`,
      });
    }

    if (issues.length) {
      toast("Some files were skipped", {
        description: issues.join(" "),
      });
    }
  }

  function handleExportFeedback() {
    const content = serializeReviewStore(reviewStore);
    const blob = new Blob([content], { type: "application/json" });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    const timestamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");

    link.href = url;
    link.download = `aegis-review-feedback-${timestamp}.json`;
    link.click();

    window.URL.revokeObjectURL(url);

    toast.success("Feedback exported", {
      description: `Saved ${Object.keys(reviewStore).length} local review entr${
        Object.keys(reviewStore).length === 1 ? "y" : "ies"
      }.`,
    });
  }

  function handleClearMemory() {
    setReviewStore({});
    toast.success("Local review state cleared", {
      description: "Reviewer dispositions, notes, and muted flags were removed.",
    });
  }

  function handleSetDisposition(
    findingKey: string,
    disposition: ReviewerDisposition | null,
  ) {
    setReviewStore((current) =>
      updateReviewStore(current, findingKey, { disposition }),
    );
  }

  function handleSetMuted(findingKey: string, muted: boolean) {
    setReviewStore((current) => updateReviewStore(current, findingKey, { muted }));
  }

  function handleSaveNote(findingKey: string, note: string) {
    setReviewStore((current) => updateReviewStore(current, findingKey, { note }));
    toast.success("Note saved locally");
  }

  function handleClearFeedback(findingKey: string) {
    setReviewStore((current) => clearReviewEntry(current, findingKey));
    toast.success("Local review reset", {
      description: "Disposition, note, and mute state were removed for this finding.",
    });
  }

  const scanProgressPercent =
    scanJobProgress.totalFiles &&
    scanJobProgress.totalFiles > 0 &&
    scanJobProgress.filesProcessed !== null
      ? Math.max(
          0,
          Math.min(
            100,
            Math.round(
              (scanJobProgress.filesProcessed / scanJobProgress.totalFiles) * 100,
            ),
          ),
        )
      : null;

  const scanStatusLabel =
    scanJobStatus === "queued"
      ? "Queued"
      : scanJobStatus === "running"
        ? "Running"
        : scanJobStatus === "completed"
          ? "Completed"
          : scanJobStatus === "failed"
            ? "Failed"
            : "Idle";

  const scanStatusClassName =
    scanJobStatus === "completed"
      ? "border-emerald-300 bg-emerald-50 text-emerald-700"
      : scanJobStatus === "failed"
        ? "border-destructive/30 bg-destructive/10 text-destructive"
        : scanRunning
          ? "border-primary/25 bg-primary/8 text-primary"
          : "border-border bg-surface text-muted-foreground";

  const explorer = (
    <ReportSidebar
      reports={reportEntries}
      selectedReportId={effectiveSelectedReportId}
      onSelectReport={handleSelectReport}
      onRefresh={() => void refreshWorkspaceReports(true)}
      onImportRequest={handleImportRequest}
      onExportFeedback={handleExportFeedback}
      onClearMemory={handleClearMemory}
      feedbackStore={reviewStore}
      loading={loadingWorkspaceReports}
      error={listError}
      showArchiveReports={showArchiveReports}
      onToggleArchiveReports={() =>
        setShowArchiveReports((current) => !current)
      }
      totalReports={reportsMeta.totalReports}
      archiveReports={reportsMeta.archiveReports}
      recentLimit={reportsMeta.recentLimit}
    />
  );

  const detail = (
    <FindingDetail
      key={selectedFinding?.key ?? "empty-detail"}
      finding={selectedFinding}
      feedback={selectedFinding ? reviewStore[selectedFinding.key] : undefined}
      loading={loadingSelectedReport}
      onDisposition={(disposition) =>
        selectedFinding && handleSetDisposition(selectedFinding.key, disposition)
      }
      onToggleMute={() =>
        selectedFinding &&
        handleSetMuted(selectedFinding.key, !reviewStore[selectedFinding.key]?.muted)
      }
      onSaveNote={(note) => {
        if (!selectedFinding) {
          return;
        }
        handleSaveNote(selectedFinding.key, note);
      }}
      onReset={() => {
        if (!selectedFinding) {
          return;
        }
        handleClearFeedback(selectedFinding.key);
      }}
    />
  );

  return (
    <div className="flex min-h-[100dvh] flex-col bg-background">
      <input
        ref={fileInputRef}
        type="file"
        accept=".json,application/json"
        multiple
        className="sr-only"
        onChange={(event) => {
          void handleImportFiles(event.target.files);
          event.target.value = "";
        }}
      />

      <TopBar
        report={selectedReportSummary}
        reportsLoaded={reportEntries.length}
        reviewedLocally={Object.keys(reviewStore).length}
        onImport={handleImportRequest}
        onRefresh={() => void refreshWorkspaceReports(true)}
        onExport={handleExportFeedback}
        onRunScan={handleOpenScanSheet}
        scanPending={scanRunning}
      />

      {!hasSidebar ? (
        <div className="flex items-center gap-2 border-b border-border bg-surface px-3 py-1.5">
          <Button
            variant="ghost"
            size="sm"
            className="h-7 gap-1.5 px-2 text-[12.5px]"
            onClick={() => setExplorerOpen(true)}
          >
            <PanelLeft className="h-3.5 w-3.5" /> Reports
          </Button>
          <span className="truncate font-mono text-[12px] text-muted-foreground">
            {selectedReportSummary?.shortName ?? "No report selected"}
          </span>
        </div>
      ) : null}

      {!selectedReportSummary && !loadingWorkspaceReports ? (
        <div className="border-b border-border bg-sev-medium/8 px-4 py-3 text-[12.5px] text-foreground">
          No normalized Aegis report is loaded yet. Run the CLI to export a
          report bundle or import a saved JSON file.
        </div>
      ) : null}

      {selectedReport?.errors.length ? (
        <div className="border-b border-border bg-sev-medium/8 px-4 py-3 text-[12.5px] text-foreground">
          This report recorded {selectedReport.errors.length} scan error
          {selectedReport.errors.length === 1 ? "" : "s"}. Review the raw report if
          a file seems to be missing from the findings queue.
        </div>
      ) : null}

      <div className="grid flex-1 grid-cols-1 lg:grid-cols-[292px_minmax(0,1fr)]">
        {hasSidebar ? (
          <div className="border-r border-border bg-surface">{explorer}</div>
        ) : null}

        <div className="min-w-0 bg-background">
          <div className="border-b border-border px-4 py-4">
            <SelectedReportPanel
              report={selectedReportSummary}
              totalFindings={allFindings.length}
              selectedFindings={filteredFindings.length}
              reviewedLocally={Object.keys(reviewStore).length}
            />

            {scanJobStatus ? (
              <div className="mt-3 rounded-2xl border border-border bg-surface px-4 py-3">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div className="min-w-0">
                    <div className="text-[10.5px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
                      Scan activity
                    </div>
                    <div className="mt-1 text-[14px] font-semibold text-foreground">
                      {scanStatusLabel}
                    </div>
                    <p className="mt-1 truncate text-[12px] text-muted-foreground">
                      {scanJobProgress.message ??
                        (scanJobResult?.selectedReportPath
                          ? `Latest report: ${scanJobResult.selectedReportPath}`
                          : "Open the scan panel to watch the full live log.")}
                    </p>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    {scanProgressPercent !== null ? (
                      <MetaTag>{scanProgressPercent}% complete</MetaTag>
                    ) : null}
                    <MetaTag>{scanJobProgress.filesScanned ?? 0} files scanned</MetaTag>
                    <MetaTag>{scanJobProgress.findings ?? 0} findings</MetaTag>
                    {scanJobError ? (
                      <MetaTag className="border-destructive/25 bg-destructive/8 text-destructive">
                        Error
                      </MetaTag>
                    ) : null}
                  </div>
                </div>
              </div>
            ) : null}
          </div>

          <div>
            <FindingQueue
              findings={filteredFindings}
              total={allFindings.length}
              feedbackStore={reviewStore}
              filters={filters}
              onFiltersChange={setFilters}
              selectedFindingKey={effectiveSelectedFindingKey}
              onSelectFinding={handleSelectFinding}
              languages={languageOptions}
              families={familyOptions}
              statuses={statusOptions}
              severities={severityOptions}
              loading={loadingSelectedReport}
              error={reportError}
            />
          </div>
        </div>
      </div>

      <Sheet open={explorerOpen} onOpenChange={setExplorerOpen}>
        <SheetContent side="left" className="w-[300px] p-0">
          <SheetTitle className="sr-only">Reports</SheetTitle>
          {explorer}
        </SheetContent>
      </Sheet>

      {scanSheetOpen ? (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/45">
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="run-local-scan-title"
            className="flex h-full w-full max-w-[460px] flex-col border-l border-border bg-background shadow-2xl"
          >
            <div className="flex items-start justify-between gap-3 border-b border-border px-5 py-5">
              <div>
                <h2
                  id="run-local-scan-title"
                  className="text-left text-[18px] font-semibold text-foreground"
                >
                  Run local scan
                </h2>
                <p className="mt-2 text-[13px] leading-6 text-muted-foreground">
                  Trigger the Python scan pipeline from the dashboard, export a
                  fresh JSON report, and reopen it here automatically. Large
                  repositories can take several minutes to finish.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setScanSheetOpen(false)}
                className="rounded-sm p-1.5 text-muted-foreground transition-colors hover:bg-surface-muted hover:text-foreground"
                aria-label="Close scan panel"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="flex-1 space-y-5 overflow-y-auto px-5 py-5">
              <div className={`rounded-lg border px-4 py-3 ${scanStatusClassName}`}>
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="text-[11px] font-semibold uppercase tracking-[0.16em]">
                      Scan status
                    </div>
                    <div className="mt-1 text-[15px] font-semibold">
                      {scanStatusLabel}
                    </div>
                  </div>

                  {scanProgressPercent !== null ? (
                    <div className="text-right">
                      <div className="num text-[18px] font-semibold">
                        {scanProgressPercent}%
                      </div>
                      <div className="text-[11px] text-current/80">
                        {scanJobProgress.filesProcessed ?? 0}/
                        {scanJobProgress.totalFiles ?? 0} files
                      </div>
                    </div>
                  ) : null}
                </div>

                <div className="mt-3 h-2 overflow-hidden rounded-full bg-black/8">
                  <div
                    className="h-full rounded-full bg-current transition-[width]"
                    style={{
                      width:
                        scanProgressPercent !== null ? `${scanProgressPercent}%` : "0%",
                    }}
                  />
                </div>

                <div className="mt-3 grid gap-2 text-[12px] sm:grid-cols-2">
                  <div>
                    <span className="text-current/75">Stage:</span>{" "}
                    <span className="font-medium">
                      {scanJobProgress.stage ?? "not started"}
                    </span>
                  </div>
                  <div>
                    <span className="text-current/75">Findings:</span>{" "}
                    <span className="num font-medium">
                      {scanJobProgress.findings ?? 0}
                    </span>
                  </div>
                  <div>
                    <span className="text-current/75">Files scanned:</span>{" "}
                    <span className="num font-medium">
                      {scanJobProgress.filesScanned ?? 0}
                    </span>
                  </div>
                  <div>
                    <span className="text-current/75">Errors:</span>{" "}
                    <span className="num font-medium">
                      {scanJobProgress.errors ?? 0}
                    </span>
                  </div>
                </div>

                {scanJobProgress.message ? (
                  <p className="mt-3 text-[12px] leading-5 text-current/85">
                    {scanJobProgress.message}
                  </p>
                ) : null}

                {scanJobProgress.currentFile ? (
                  <p className="mt-2 truncate font-mono text-[11.5px] text-current/80">
                    {scanJobProgress.currentFile}
                  </p>
                ) : null}

                {scanJobStatus === "completed" && scanJobResult?.selectedReportPath ? (
                  <p className="mt-2 truncate font-mono text-[11.5px] text-current/80">
                    Report: {scanJobResult.selectedReportPath}
                  </p>
                ) : null}

                {scanJobError ? (
                  <p className="mt-2 text-[12px] leading-5 text-current">
                    {scanJobError}
                  </p>
                ) : null}
              </div>

              <div className="space-y-2">
                <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                  Target path
                </div>
                <Input
                  autoFocus
                  value={scanTargetPath}
                  onChange={(event) => setScanTargetPath(event.target.value)}
                  placeholder="C:\\path\\to\\repo or examples/vulnerable_rce.py"
                  className="h-11 rounded-lg border-border bg-surface text-[13px]"
                  disabled={scanRunning}
                />
                <p className="text-[12px] leading-5 text-muted-foreground">
                  Relative paths resolve from the Aegis-SAST repo root.
                </p>
              </div>

              <div className="grid gap-4 sm:grid-cols-[140px_minmax(0,1fr)]">
                <div className="space-y-2">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                    Max depth
                  </div>
                  <Input
                    type="number"
                    min={1}
                    max={20}
                    value={scanMaxDepth}
                    onChange={(event) => setScanMaxDepth(event.target.value)}
                    className="h-11 rounded-lg border-border bg-surface text-[13px]"
                    disabled={scanRunning}
                  />
                </div>

                <div className="rounded-lg border border-border bg-surface px-4 py-3">
                  <label className="flex items-start gap-3">
                    <Checkbox
                      checked={scanEnableAi}
                      onCheckedChange={(checked) => setScanEnableAi(checked === true)}
                      className="mt-0.5"
                      disabled={scanRunning}
                    />
                    <div>
                      <div className="text-[13px] font-medium text-foreground">
                        Enable AI triage overlay
                      </div>
                      <p className="mt-1 text-[12px] leading-5 text-muted-foreground">
                        Keep deterministic detection as the source of truth, then
                        let AI re-review each triage record if Gemini is available.
                      </p>
                    </div>
                  </label>
                </div>
              </div>

              <div className="rounded-lg border border-border bg-surface-muted px-4 py-3">
                <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                  Safe defaults
                </div>
                <p className="mt-2 text-[12.5px] leading-6 text-foreground">
                  Directory scans automatically skip common dependency, cache,
                  and build-output folders such as <code>node_modules</code>,
                  <code>.venv</code>, <code>.next</code>, and <code>dist</code>.
                </p>
                <p className="mt-2 text-[12px] leading-5 text-muted-foreground">
                  For large codebases like PyTorch, start with AI off and a max
                  depth of 3.
                </p>
              </div>

              <div className="rounded-lg border border-border bg-background">
                <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                    Live log
                  </div>
                  <div className="num text-[11.5px] text-muted-foreground">
                    {scanJobLogs.length} line{scanJobLogs.length === 1 ? "" : "s"}
                  </div>
                </div>
                <div className="max-h-[240px] overflow-y-auto px-4 py-3 font-mono text-[11.5px] leading-6 text-foreground">
                  {scanJobLogs.length ? (
                    scanJobLogs.map((line, index) => (
                      <div key={`${line}-${index}`} className="break-words">
                        {line}
                      </div>
                    ))
                  ) : (
                    <div className="text-muted-foreground">
                      Start a scan to see detector progress and exported artifact logs here.
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="flex flex-wrap justify-end gap-2 border-t border-border px-5 py-4">
              <Button
                variant="outline"
                onClick={() => setScanSheetOpen(false)}
              >
                {scanRunning ? "Hide panel" : "Close"}
              </Button>
              <Button
                onClick={() => void handleRunScan()}
                disabled={scanRunning || !scanTargetPath.trim()}
              >
                {scanRunning ? "Running scan..." : "Start scan"}
              </Button>
            </div>
          </div>
        </div>
      ) : null}

      <Sheet open={detailOpen} onOpenChange={setDetailOpen}>
        <SheetContent side="right" className="w-full p-0 sm:max-w-[540px]">
          <SheetTitle className="sr-only">Finding detail</SheetTitle>
          {detail}
        </SheetContent>
      </Sheet>

      <Toaster position="bottom-right" />
    </div>
  );
}

export function DashboardShell() {
  const hydrated = useHydrated();

  return (
    <DashboardShellContent
      key={hydrated ? "dashboard-hydrated" : "dashboard-ssr"}
      hydrated={hydrated}
    />
  );
}
