'use client';

import {
  startTransition,
  useDeferredValue,
  useEffect,
  useRef,
  useState,
} from "react";
import { PanelLeft } from "lucide-react";
import { toast } from "sonner";

import { FindingDetail } from "@/components/finding-detail";
import { FindingQueue, type QueueFilters } from "@/components/finding-queue";
import { ReportSidebar, type ReportEntry } from "@/components/report-sidebar";
import { TopBar } from "@/components/top-bar";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTitle } from "@/components/ui/sheet";
import { Toaster } from "@/components/ui/sonner";
import { severityRank, triageRank } from "@/lib/dashboard-ui";
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
  error?: string;
};

type ReportDetailResponse = {
  report?: NormalizedReport;
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
  const [matches, setMatches] = useState(() =>
    typeof window !== "undefined" ? window.matchMedia(query).matches : false,
  );

  useEffect(() => {
    const mediaQuery = window.matchMedia(query);

    const handler = (event: MediaQueryListEvent) => setMatches(event.matches);

    mediaQuery.addEventListener("change", handler);
    return () => mediaQuery.removeEventListener("change", handler);
  }, [query]);

  return matches;
}

export function DashboardShell() {
  const [workspaceReports, setWorkspaceReports] = useState<ReportSummaryCard[]>([]);
  const [importedReports, setImportedReports] = useState<NormalizedReport[]>([]);
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null);
  const [loadedWorkspaceReport, setLoadedWorkspaceReport] =
    useState<NormalizedReport | null>(null);
  const [selectedFindingKey, setSelectedFindingKey] = useState<string | null>(null);
  const [loadingWorkspaceReports, setLoadingWorkspaceReports] = useState(true);
  const [listError, setListError] = useState<string | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);
  const [reviewStore, setReviewStore] = useState<ReviewerFeedbackStore>(() =>
    readReviewStore(),
  );
  const [filters, setFilters] = useState<QueueFilters>(emptyFilters);
  const [explorerOpen, setExplorerOpen] = useState(false);
  const [detailOpen, setDetailOpen] = useState(false);

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const deferredSearch = useDeferredValue(filters.search);
  const hasSidebar = useMediaQuery("(min-width: 1024px)");
  const isWide = useMediaQuery("(min-width: 1280px)");

  useEffect(() => {
    writeReviewStore(reviewStore);
  }, [reviewStore]);

  async function refreshWorkspaceReports(showToast = false) {
    setLoadingWorkspaceReports(true);

    try {
      const response = await fetch("/api/reports", { cache: "no-store" });
      const data = (await response.json()) as ReportsIndexResponse;

      if (!response.ok) {
        throw new Error(data.error ?? "Unable to load workspace reports.");
      }

      const nextReports = sortByTimestamp(data.reports ?? []);
      setWorkspaceReports(nextReports);
      setListError(null);

      if (showToast) {
        toast.success("Reports refreshed", {
          description: `${nextReports.length} workspace report${
            nextReports.length === 1 ? "" : "s"
          } available.`,
        });
      }
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Unable to load workspace reports.";

      setWorkspaceReports([]);
      setListError(message);

      if (showToast) {
        toast.error("Refresh failed", { description: message });
      }
    } finally {
      setLoadingWorkspaceReports(false);
    }
  }

  useEffect(() => {
    let cancelled = false;

    void (async () => {
      try {
        const response = await fetch("/api/reports", { cache: "no-store" });
        const data = (await response.json()) as ReportsIndexResponse;

        if (!response.ok) {
          throw new Error(data.error ?? "Unable to load workspace reports.");
        }

        if (!cancelled) {
          setWorkspaceReports(sortByTimestamp(data.reports ?? []));
          setListError(null);
        }
      } catch (error) {
        if (!cancelled) {
          setWorkspaceReports([]);
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
  }, []);

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

    if (!isWide) {
      setDetailOpen(true);
    }
  }

  function handleImportRequest() {
    fileInputRef.current?.click();
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
      onClose={isWide ? undefined : () => setDetailOpen(false)}
    />
  );

  return (
    <div className="flex h-screen flex-col overflow-hidden bg-background">
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

      <div className="grid min-h-0 flex-1 grid-cols-1 lg:grid-cols-[296px_minmax(0,1fr)] xl:grid-cols-[296px_minmax(0,1fr)_460px]">
        {hasSidebar ? <div className="border-r border-border">{explorer}</div> : null}

        <div className="min-h-0 min-w-0 border-r border-border">
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

        {isWide ? <div className="min-h-0">{detail}</div> : null}
      </div>

      <Sheet open={explorerOpen} onOpenChange={setExplorerOpen}>
        <SheetContent side="left" className="w-[300px] p-0">
          <SheetTitle className="sr-only">Reports</SheetTitle>
          {explorer}
        </SheetContent>
      </Sheet>

      <Sheet open={!isWide && detailOpen} onOpenChange={setDetailOpen}>
        <SheetContent side="right" className="w-full p-0 sm:max-w-[440px]">
          <SheetTitle className="sr-only">Finding detail</SheetTitle>
          {detail}
        </SheetContent>
      </Sheet>

      <Toaster position="bottom-right" />
    </div>
  );
}
