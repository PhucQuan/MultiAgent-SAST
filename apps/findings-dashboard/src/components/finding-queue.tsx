import { Search, VolumeX } from "lucide-react";

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
import { formatConfidence, formatLabel } from "@/lib/dashboard-ui";
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
}: {
  value: string;
  onChange: (value: string) => void;
  options: string[];
  placeholder: string;
}) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger className="h-9 w-full rounded-lg border-border bg-background text-[12.5px]">
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="all">All {placeholder.toLowerCase()}</SelectItem>
        {options.map((option) => (
          <SelectItem key={option} value={option}>
            {formatLabel(option)}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

function FindingRow({
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
        "w-full border-l-2 px-4 py-4 text-left transition-colors hover:bg-surface-muted/80",
        selected
          ? "border-l-primary bg-primary/5"
          : "border-l-transparent bg-background",
        feedback?.muted && "opacity-60",
      )}
    >
      <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_170px] xl:items-start">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-1.5">
            <SeverityTag severity={finding.severity} />
            <StatusTag status={finding.status} />
            <MetaTag>{formatConfidence(finding.confidence)}</MetaTag>
            {feedback?.muted ? (
              <MetaTag className="gap-1.5">
                <VolumeX className="h-3.5 w-3.5" /> Muted
              </MetaTag>
            ) : null}
          </div>

          <div className="mt-2 text-[14px] font-semibold leading-6 text-foreground">
            {finding.message}
          </div>

          <div className="mt-1 font-mono text-[11.5px] text-muted-foreground">
            {finding.filePath}
            <span>{finding.line ? `:${finding.line}` : ""}</span>
          </div>

          <div className="mt-2 flex flex-wrap gap-1.5">
            <MetaTag>{formatLabel(finding.family)}</MetaTag>
            <MetaTag>{formatLabel(finding.language)}</MetaTag>
            {finding.sourceType ? (
              <MetaTag className="font-mono">{formatLabel(finding.sourceType)}</MetaTag>
            ) : null}
            {finding.workflowRoute ? (
              <MetaTag className="font-mono">
                {formatLabel(finding.workflowRoute.routeId)}
              </MetaTag>
            ) : null}
            {finding.knowledgeCards.length ? (
              <MetaTag>{finding.knowledgeCards.length} knowledge cards</MetaTag>
            ) : null}
            {finding.manualReviewRequired ? (
              <MetaTag className="border-sev-medium/30 text-sev-medium">
                Manual review
              </MetaTag>
            ) : null}
          </div>
        </div>

        <div className="flex flex-col gap-2 xl:items-end">
          <div className="w-full xl:w-[160px]">
            <ConfidenceBar value={finding.confidence} />
          </div>
          <div className="text-[11.5px] text-muted-foreground">
            {feedback?.disposition ? (
              <span className="font-medium text-primary">
                Reviewer: {dispositionLabels[feedback.disposition]}
              </span>
            ) : (
              "No local override"
            )}
          </div>
          <div className="num text-[11px] text-muted-foreground">{finding.id}</div>
        </div>
      </div>
    </button>
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

  return (
    <div className="flex h-full min-w-0 flex-col bg-surface">
      <div className="border-b border-border px-4 py-4">
        <div className="flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between">
          <div className="min-w-0">
            <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
              Findings queue
            </div>
            <h2 className="mt-1 text-[18px] font-semibold tracking-tight text-foreground">
              Review queue
            </h2>
            <p className="mt-1 text-[12.5px] leading-6 text-muted-foreground">
              Filter down to the findings that should survive automated triage and
              local review.
            </p>
          </div>
          <div className="flex flex-wrap gap-1.5">
            <MetaTag>{findings.length} visible</MetaTag>
            <MetaTag>{total} total</MetaTag>
          </div>
        </div>

        <div className="mt-4 grid gap-2 xl:grid-cols-[minmax(0,1fr)_repeat(4,minmax(0,132px))]">
          <div className="relative min-w-0">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={filters.search}
              onChange={(event) => setFilters({ search: event.target.value })}
              placeholder="Search by file, family, route, reason code, or note"
              className="h-9 rounded-lg border-border bg-background pl-9 text-[12.5px]"
            />
          </div>
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
          <FilterSelect
            value={filters.language}
            onChange={(value) => setFilters({ language: value })}
            options={languages}
            placeholder="Language"
          />
          <FilterSelect
            value={filters.family}
            onChange={(value) => setFilters({ family: value })}
            options={families}
            placeholder="Family"
          />
        </div>

        <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
          <label className="flex cursor-pointer items-center gap-2 text-[12.5px] text-muted-foreground">
            <Checkbox
              checked={filters.includeMuted}
              onCheckedChange={(checked) =>
                setFilters({ includeMuted: checked === true })
              }
              className="h-4 w-4 rounded-[4px]"
            />
            Include muted findings
          </label>
          <div className="num text-[11.5px] text-muted-foreground">
            Showing {findings.length} of {total}
          </div>
        </div>
      </div>

      {error ? (
        <div className="border-b border-border bg-destructive/6 px-4 py-3 text-[12.5px] text-destructive">
          {error}
        </div>
      ) : null}

      <div className="min-h-0 flex-1 overflow-y-auto bg-background/55">
        {loading ? (
          <div className="px-4 py-10 text-center text-[12.5px] text-muted-foreground">
            Loading normalized Aegis findings for the selected report...
          </div>
        ) : findings.length === 0 ? (
          <div className="px-4 py-10 text-center text-[12.5px] text-muted-foreground">
            {total === 0
              ? "This report does not contain any findings."
              : "No findings match the current filters."}
          </div>
        ) : (
          <div className="divide-y divide-border">
            {findings.map((finding) => (
              <FindingRow
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
    </div>
  );
}
