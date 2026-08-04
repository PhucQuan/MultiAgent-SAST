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
      <SelectTrigger className="h-8 w-[126px] rounded-sm border-border bg-surface text-[12.5px]">
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
    <tr
      role="button"
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onSelect();
        }
      }}
      className={cn(
        "cursor-pointer border-b border-border align-top transition-colors hover:bg-surface-muted",
        selected && "bg-accent/60",
        feedback?.muted && "opacity-60",
      )}
    >
      <td className="relative w-[108px] px-3 py-2.5">
        <span
          className={cn(
            "absolute inset-y-0 left-0 w-[2px]",
            selected ? "bg-primary" : "bg-transparent",
          )}
        />
        <SeverityTag severity={finding.severity} />
      </td>

      <td className="px-3 py-2.5">
        <div className="flex items-start gap-2">
          <span className="min-w-0 text-[13px] font-medium leading-5 text-foreground">
            {finding.message}
          </span>
          {feedback?.muted ? (
            <VolumeX className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" />
          ) : null}
        </div>
        <div className="mt-1 flex flex-wrap items-center gap-1.5">
          <MetaTag>{formatLabel(finding.family)}</MetaTag>
          <MetaTag>{formatLabel(finding.language)}</MetaTag>
          {finding.workflowRoute ? (
            <MetaTag className="font-mono">
              {formatLabel(finding.workflowRoute.routeId)}
            </MetaTag>
          ) : null}
          {finding.manualReviewRequired ? (
            <MetaTag className="border-sev-medium/30 text-sev-medium">
              Manual review
            </MetaTag>
          ) : null}
        </div>
      </td>

      <td className="hidden px-3 py-2.5 lg:table-cell">
        <div className="truncate font-mono text-[12px] text-foreground">
          {finding.filePath}
          <span className="text-muted-foreground">
            {finding.line ? `:${finding.line}` : ""}
          </span>
        </div>
        <div className="num mt-1 text-[11.5px] text-muted-foreground">
          {finding.id}
        </div>
      </td>

      <td className="w-[190px] px-3 py-2.5">
        <StatusTag status={finding.status} />
        <div className="mt-1.5">
          <ConfidenceBar value={finding.confidence} />
        </div>
        <div className="mt-1 text-[11.5px] text-muted-foreground">
          {feedback?.disposition ? (
            <span className="font-medium text-primary">
              Override: {dispositionLabels[feedback.disposition]}
            </span>
          ) : (
            `Confidence ${formatConfidence(finding.confidence)}`
          )}
        </div>
      </td>
    </tr>
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
    <div className="flex items-start justify-between gap-3 border-b border-border px-3 py-2.5">
      <div className="min-w-0">
        <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
          Findings queue
        </div>
        <h2 className="mt-0.5 text-[16px] font-semibold tracking-tight text-foreground">
          Review queue
        </h2>
      </div>
      <div className="flex shrink-0 items-center gap-1.5">
        <MetaTag>{findings.length} visible</MetaTag>
        <MetaTag>{total} total</MetaTag>
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

  return (
    <div className="flex h-full min-w-0 flex-col bg-surface">
      <QueueHeader findings={findings} total={total} />

      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <div className="relative min-w-[220px] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={filters.search}
            onChange={(event) => setFilters({ search: event.target.value })}
            placeholder="Search by file, family, reason code, or note"
            className="h-8 rounded-sm border-border bg-surface pl-8 text-[12.5px]"
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
        <label className="flex cursor-pointer items-center gap-1.5 whitespace-nowrap pl-1 text-[12.5px] text-muted-foreground">
          <Checkbox
            checked={filters.includeMuted}
            onCheckedChange={(checked) =>
              setFilters({ includeMuted: checked === true })
            }
            className="h-3.5 w-3.5 rounded-[3px]"
          />
          Include muted
        </label>
      </div>

      {error ? (
        <div className="border-b border-border bg-destructive/6 px-3 py-2.5 text-[12px] text-destructive">
          {error}
        </div>
      ) : null}

      <div className="min-h-0 flex-1 overflow-auto">
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
          <table className="w-full border-collapse text-left">
            <thead className="sticky top-0 z-10 bg-surface-muted">
              <tr className="border-b border-border text-[11px] uppercase tracking-wider text-muted-foreground">
                <th className="px-3 py-2 font-medium">Risk</th>
                <th className="px-3 py-2 font-medium">Finding</th>
                <th className="hidden px-3 py-2 font-medium lg:table-cell">Location</th>
                <th className="px-3 py-2 font-medium">Review</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((finding) => (
                <FindingRow
                  key={finding.key}
                  finding={finding}
                  feedback={feedbackStore[finding.key]}
                  selected={finding.key === selectedFindingKey}
                  onSelect={() => onSelectFinding(finding.key)}
                />
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="num border-t border-border bg-surface-muted px-3 py-1.5 text-[11.5px] text-muted-foreground">
        Showing {findings.length} of {total} findings
      </div>
    </div>
  );
}
