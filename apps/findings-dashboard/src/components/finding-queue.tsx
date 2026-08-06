import { Search, SlidersHorizontal, VolumeX } from "lucide-react";

import {
  ConfidenceBar,
  MetaTag,
  SeverityTag,
  StatusTag,
  dispositionLabels,
} from "@/components/status-badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  formatConfidence,
  formatLabel,
  shortenPath,
} from "@/lib/dashboard-ui";
import { cn } from "@/lib/utils";
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

function FilterSelect({
  value,
  onChange,
  options,
  placeholder,
  widthClassName = "w-full sm:w-[150px]",
}: {
  value: string;
  onChange: (value: string) => void;
  options: string[];
  placeholder: string;
  widthClassName?: string;
}) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger
        className={cn(
          "h-9 rounded-lg border-border bg-background text-[12.5px]",
          widthClassName,
        )}
      >
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="all">{placeholder}: all</SelectItem>
        {options.map((option) => (
          <SelectItem key={option} value={option}>
            {formatLabel(option)}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

function FindingCard({
  finding,
  feedback,
  selected,
  onSelect,
}: {
  finding: NormalizedFinding;
  feedback: ReviewerFeedbackStore[string] | undefined;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        "w-full rounded-xl border border-border bg-background px-4 py-3 text-left transition-colors hover:bg-surface-muted",
        selected && "border-primary/30 bg-primary/6 shadow-sm",
        feedback?.muted && "opacity-65",
      )}
    >
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <SeverityTag severity={finding.severity} />
            <StatusTag status={finding.status} />
            <MetaTag>{formatLabel(finding.family)}</MetaTag>
            <MetaTag>{formatLabel(finding.language)}</MetaTag>
            {finding.manualReviewRequired ? (
              <MetaTag className="border-sev-medium/25 bg-sev-medium/8 text-sev-medium">
                Manual review
              </MetaTag>
            ) : null}
            {feedback?.muted ? (
              <MetaTag className="border-border text-muted-foreground">
                <VolumeX className="mr-1 h-3 w-3" /> Muted
              </MetaTag>
            ) : null}
          </div>

          <h3 className="mt-2 text-[14px] font-semibold leading-6 text-foreground">
            {finding.message}
          </h3>

          <div className="mt-2 flex flex-wrap items-center gap-2 text-[12px] text-muted-foreground">
            <span className="font-mono">
              {shortenPath(finding.filePath, 5)}
              {finding.line ? `:${finding.line}` : ""}
            </span>
            <span className="text-border">|</span>
            <span className="font-mono">{finding.id}</span>
            {finding.workflowRoute ? (
              <>
                <span className="text-border">|</span>
                <span>{formatLabel(finding.workflowRoute.routeId)}</span>
              </>
            ) : null}
          </div>
        </div>

        <div className="flex min-w-[140px] flex-col gap-1 lg:items-end">
          <div className="w-full max-w-[150px]">
            <ConfidenceBar value={finding.confidence} />
          </div>
          <div className="text-[11.5px] text-muted-foreground lg:text-right">
            {feedback?.disposition ? (
              <span className="font-medium text-primary">
                Override: {dispositionLabels[feedback.disposition]}
              </span>
            ) : (
              `Confidence ${formatConfidence(finding.confidence)}`
            )}
          </div>
        </div>
      </div>
    </button>
  );
}

function QueueHeader({
  findings,
  total,
}: {
  findings: NormalizedFinding[];
  total: number;
}) {
  return (
    <div className="border-b border-border px-4 py-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
            Findings
          </div>
          <h2 className="mt-1 text-[16px] font-semibold tracking-tight text-foreground">
            Review queue
          </h2>
          <p className="mt-1 text-[12px] leading-5 text-muted-foreground">
            Keep the list readable first, then drill into one finding at a time.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <MetaTag>{findings.length} visible</MetaTag>
          <MetaTag>{total} total</MetaTag>
        </div>
      </div>
    </div>
  );
}

interface FindingsQueueProps {
  findings: NormalizedFinding[];
  total: number;
  feedbackStore: ReviewerFeedbackStore;
  filters: QueueFilters;
  onFiltersChange: (filters: QueueFilters) => void;
  selectedFindingKey?: string | null;
  onSelectFinding: (findingKey: string) => void;
  languages: string[];
  families: string[];
  statuses: TriageStatus[];
  severities: Severity[];
  loading?: boolean;
  error?: string | null;
}

export function FindingQueue({
  findings,
  total,
  feedbackStore,
  filters,
  onFiltersChange,
  selectedFindingKey,
  onSelectFinding,
  languages,
  families,
  statuses,
  severities,
  loading = false,
  error,
}: FindingsQueueProps) {
  const setFilters = (patch: Partial<QueueFilters>) =>
    onFiltersChange({ ...filters, ...patch });

  const activeFilterCount = [
    filters.status !== "all",
    filters.severity !== "all",
    filters.language !== "all",
    filters.family !== "all",
    filters.includeMuted,
    filters.search.trim().length > 0,
  ].filter(Boolean).length;

  return (
    <div className="flex min-w-0 flex-col bg-surface">
      <QueueHeader findings={findings} total={total} />

      <div className="border-b border-border px-4 py-4">
        <div className="flex flex-col gap-3">
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={filters.search}
              onChange={(event) => setFilters({ search: event.target.value })}
              placeholder="Search by finding, file path, reason code, or reviewer note"
              className="h-10 rounded-lg border-border bg-background pl-9 text-[12.5px]"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <FilterSelect
              value={filters.status}
              onChange={(value) => setFilters({ status: value })}
              options={statuses}
              placeholder="Status"
            />
            <FilterSelect
              value={filters.severity}
              onChange={(value) => setFilters({ severity: value })}
              options={severities}
              placeholder="Severity"
            />

            <details className="group min-w-[190px] rounded-lg border border-border bg-background">
              <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-3 py-2 text-[12.5px] text-foreground">
                <span className="inline-flex items-center gap-2">
                  <SlidersHorizontal className="h-3.5 w-3.5 text-muted-foreground" />
                  More filters
                </span>
                <MetaTag>{activeFilterCount}</MetaTag>
              </summary>

              <div className="grid gap-2 border-t border-border px-3 py-3 sm:grid-cols-2">
                <FilterSelect
                  value={filters.language}
                  onChange={(value) => setFilters({ language: value })}
                  options={languages}
                  placeholder="Language"
                  widthClassName="w-full"
                />
                <FilterSelect
                  value={filters.family}
                  onChange={(value) => setFilters({ family: value })}
                  options={families}
                  placeholder="Family"
                  widthClassName="w-full"
                />
                <label className="flex items-center gap-2 rounded-lg border border-border px-3 py-2 text-[12px] text-muted-foreground sm:col-span-2">
                  <Checkbox
                    checked={filters.includeMuted}
                    onCheckedChange={(checked) =>
                      setFilters({ includeMuted: checked === true })
                    }
                    className="h-3.5 w-3.5 rounded-[4px]"
                  />
                  Include muted findings
                </label>
              </div>
            </details>
          </div>
        </div>
      </div>

      {error ? (
        <div className="border-b border-border bg-destructive/6 px-4 py-3 text-[12px] text-destructive">
          {error}
        </div>
      ) : null}

      <div className="px-3 py-3">
        {loading ? (
          <div className="rounded-xl border border-dashed border-border bg-background px-4 py-10 text-center text-[12.5px] text-muted-foreground">
            Loading normalized Aegis findings for the selected report...
          </div>
        ) : findings.length === 0 ? (
          <div className="rounded-xl border border-dashed border-border bg-background px-4 py-10 text-center text-[12.5px] text-muted-foreground">
            {total === 0
              ? "This report does not contain any findings."
              : "No findings match the current filters."}
          </div>
        ) : (
          <div className="space-y-2">
            {findings.map((finding) => (
              <FindingCard
                key={finding.key}
                finding={finding}
                feedback={feedbackStore[finding.key]}
                selected={finding.key === selectedFindingKey}
                onSelect={() => onSelectFinding(finding.key)}
              />
            ))}
          </div>
        )}
      </div>

      <div className="border-t border-border bg-surface-muted px-4 py-2 text-[11.5px] text-muted-foreground">
        Showing {findings.length} of {total} findings
      </div>
    </div>
  );
}
