"use client";

import { useState } from "react";
import {
  AlertTriangle,
  RotateCcw,
  Volume2,
  VolumeX,
  X,
} from "lucide-react";

import {
  CodeBlock,
  DetailSection,
  dispositionLabels,
  KeyValue,
  MetaTag,
  SeverityTag,
  StatusTag,
} from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { formatConfidence, formatDateTime, formatLabel, shortenPath } from "@/lib/dashboard-ui";
import { cn } from "@/lib/utils";
import type {
  NormalizedFinding,
  ReviewerDisposition,
  ReviewerFeedback,
} from "@/lib/report-types";

const dispositions: ReviewerDisposition[] = [
  "confirmed",
  "needs-review",
  "false-positive",
  "suppressed",
];

interface FindingDetailProps {
  finding: NormalizedFinding | null;
  feedback: ReviewerFeedback | undefined;
  loading?: boolean;
  onDisposition: (disposition: ReviewerDisposition) => void;
  onToggleMute: () => void;
  onSaveNote: (note: string) => void;
  onReset: () => void;
  onClose?: () => void;
}

export function FindingDetail({
  finding,
  feedback,
  loading = false,
  onDisposition,
  onToggleMute,
  onSaveNote,
  onReset,
  onClose,
}: FindingDetailProps) {
  const [note, setNote] = useState(feedback?.note ?? "");

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center bg-surface px-6 text-center text-[12.5px] text-muted-foreground">
        Loading report detail and evidence bundle...
      </div>
    );
  }

  if (!finding) {
    return (
      <div className="flex h-full items-center justify-center bg-surface px-6 text-center text-[12.5px] text-muted-foreground">
        Select a finding from the triage queue to inspect evidence and record a
        local review decision.
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col bg-surface">
      <div className="border-b border-border px-4 py-3">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="num text-[11px] uppercase tracking-wider text-muted-foreground">
              {finding.id}
            </div>
            <h2 className="mt-0.5 text-[13.5px] font-semibold leading-5 text-foreground">
              {finding.message}
            </h2>
          </div>
          {onClose ? (
            <button
              type="button"
              onClick={onClose}
              className="rounded-sm p-1 text-muted-foreground hover:bg-surface-muted"
              aria-label="Close detail"
            >
              <X className="h-4 w-4" />
            </button>
          ) : null}
        </div>

        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          <SeverityTag severity={finding.severity} />
          <StatusTag status={finding.status} />
          <MetaTag>{formatConfidence(finding.confidence)}</MetaTag>
          {feedback?.disposition ? (
            <MetaTag className="border-primary/30 text-primary">
              {dispositionLabels[feedback.disposition]}
            </MetaTag>
          ) : null}
        </div>
      </div>

      <Tabs defaultValue="overview" className="flex min-h-0 flex-1 flex-col gap-0">
        <TabsList className="h-9 w-full justify-start rounded-none border-b border-border bg-surface-muted px-2">
          {["overview", "evidence", "review"].map((tab) => (
            <TabsTrigger
              key={tab}
              value={tab}
              className="h-7 rounded-sm text-[12.5px] capitalize data-[state=active]:bg-surface"
            >
              {tab}
            </TabsTrigger>
          ))}
        </TabsList>

        <div className="min-h-0 flex-1 overflow-y-auto">
          <TabsContent value="overview" className="mt-0">
            <DetailSection title="Location">
              <div className="font-mono text-[12px] text-foreground">
                {finding.filePath}
                <span className="text-muted-foreground">
                  {finding.line ? `:${finding.line}` : ""}
                </span>
              </div>
              <div className="mt-2 divide-y divide-border">
                <KeyValue label="Language" value={formatLabel(finding.language)} />
                <KeyValue label="Family" value={formatLabel(finding.family)} />
                <KeyValue
                  label="Source type"
                  value={finding.sourceType ? formatLabel(finding.sourceType) : "n/a"}
                />
                <KeyValue
                  label="Sink function"
                  value={finding.sinkFunction ?? "n/a"}
                />
                <KeyValue
                  label="Analysis engine"
                  value={finding.analysisEngine ?? "n/a"}
                />
                <KeyValue
                  label="Path length"
                  value={finding.pathLength ?? "n/a"}
                />
                <KeyValue
                  label="Intermediates"
                  value={finding.intermediateStepCount ?? "n/a"}
                />
                <KeyValue
                  label="Sanitizers"
                  value={finding.sanitizerCount ?? "n/a"}
                />
                <KeyValue label="Confidence" value={formatConfidence(finding.confidence)} />
                <KeyValue
                  label="Route"
                  value={
                    finding.workflowRoute
                      ? formatLabel(finding.workflowRoute.routeId)
                      : "n/a"
                  }
                />
              </div>
            </DetailSection>

            {finding.manualReviewRequired ? (
              <div className="flex items-start gap-2 border-b border-border bg-sev-medium/8 px-4 py-2.5">
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-sev-medium" />
                <p className="text-[12px] text-foreground">
                  Aegis triage marked this finding as inconclusive. Manual
                  confirmation is still required before it should be closed.
                </p>
              </div>
            ) : null}

            <DetailSection title="Triage summary">
              <p className="text-[12.5px] leading-relaxed text-foreground">
                {finding.explanation || "No triage explanation was attached to this finding."}
              </p>
            </DetailSection>

            <DetailSection title="Remediation guidance">
              <p className="text-[12.5px] leading-relaxed text-foreground">
                {finding.recommendation || "No remediation recommendation was attached."}
              </p>
            </DetailSection>

            <DetailSection title="Knowledge cards">
              {finding.knowledgeCards.length ? (
                <div className="flex flex-wrap gap-1.5">
                  {finding.knowledgeCards.map((card) => (
                    <MetaTag key={card} className="font-mono">
                      {card}
                    </MetaTag>
                  ))}
                </div>
              ) : (
                <p className="text-[12.5px] text-muted-foreground">
                  No knowledge cards were attached to this finding.
                </p>
              )}
            </DetailSection>
          </TabsContent>

          <TabsContent value="evidence" className="mt-0">
            <DetailSection title="Evidence path">
              {finding.evidencePath.length ? (
                <ol className="space-y-1.5">
                  {finding.evidencePath.map((step, index) => (
                    <li
                      key={`${step}-${index}`}
                      className="flex gap-2 font-mono text-[11.5px] text-foreground"
                    >
                      <span className="num w-4 shrink-0 text-muted-foreground">
                        {index + 1}.
                      </span>
                      <span className="min-w-0 break-all">{step}</span>
                    </li>
                  ))}
                </ol>
              ) : (
                <p className="text-[12.5px] text-muted-foreground">
                  No source-to-sink path summary was exported for this finding.
                </p>
              )}
            </DetailSection>

            {finding.workflowRoute ? (
              <DetailSection title="Workflow route">
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <MetaTag className="font-mono">
                      {finding.workflowRoute.routeId}
                    </MetaTag>
                    {finding.workflowRoute.steps.map((step) => (
                      <MetaTag key={step}>{formatLabel(step)}</MetaTag>
                    ))}
                  </div>
                  <p className="text-[12.5px] leading-relaxed text-foreground">
                    {finding.workflowRoute.reason ||
                      "No route rationale was attached to this finding."}
                  </p>
                </div>
              </DetailSection>
            ) : null}

            <DetailSection title="Source context">
              <CodeBlock
                context={finding.sourceContext}
                caption={shortenPath(
                  finding.sourceContext?.filePath || finding.filePath,
                  5,
                )}
              />
            </DetailSection>

            <DetailSection title="Sink context">
              <CodeBlock
                context={finding.sinkContext}
                caption={
                  finding.sinkContext?.filePath
                    ? `${shortenPath(finding.sinkContext.filePath, 5)}${
                        finding.sinkContext.focusLine
                          ? `:${finding.sinkContext.focusLine}`
                          : ""
                      }`
                    : `${shortenPath(finding.filePath, 5)}${
                        finding.line ? `:${finding.line}` : ""
                      }`
                }
              />
            </DetailSection>

            <DetailSection title="Reason codes">
              {finding.reasonCodes.length ? (
                <div className="flex flex-wrap gap-1.5">
                  {finding.reasonCodes.map((code) => (
                    <MetaTag key={code} className="font-mono">
                      {code}
                    </MetaTag>
                  ))}
                </div>
              ) : (
                <p className="text-[12.5px] text-muted-foreground">
                  No reason codes were exported.
                </p>
              )}
            </DetailSection>

            {finding.graphSlice ? (
              <DetailSection title="Graph slice">
                <div className="num grid grid-cols-2 gap-2 text-center xl:grid-cols-5">
                  {[
                    ["Nodes", finding.graphSlice.nodeCount],
                    ["CFG", finding.graphSlice.cfgEdgeCount],
                    ["DFG", finding.graphSlice.dfgEdgeCount],
                    ["Path", finding.graphSlice.pathNodeCount],
                    ["Path edges", finding.graphSlice.pathEdgeCount],
                  ].map(([label, value]) => (
                    <div
                      key={String(label)}
                      className="rounded-sm border border-border py-1.5"
                    >
                      <div className="text-[13px] font-semibold text-foreground">
                        {value ?? "n/a"}
                      </div>
                      <div className="text-[10.5px] uppercase tracking-wide text-muted-foreground">
                        {label}
                      </div>
                    </div>
                  ))}
                </div>
              </DetailSection>
            ) : null}

            <DetailSection title="Reasoning notes">
              {finding.reasoningNotes.length ? (
                <ul className="space-y-1.5">
                  {finding.reasoningNotes.map((note) => (
                    <li
                      key={note}
                      className="font-mono text-[11.5px] text-muted-foreground"
                    >
                      {note}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-[12.5px] text-muted-foreground">
                  No reasoning notes were exported.
                </p>
              )}
            </DetailSection>

            {finding.agentReviews.length ? (
              <DetailSection title="Agent review bundle">
                <ul className="space-y-2">
                  {finding.agentReviews.map((review) => (
                    <li
                      key={review.key}
                      className="rounded-sm border border-border px-2.5 py-2"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[12.5px] font-medium text-foreground">
                          {review.title}
                        </span>
                        <span className="num text-[11.5px] text-muted-foreground">
                          {review.metadata?.verdict
                            ? `${String(review.metadata.verdict)} | `
                            : ""}
                          {review.metadata?.confidence !== undefined
                            ? `${Math.round(Number(review.metadata.confidence) * 100)}%`
                            : "review bundle"}
                        </span>
                      </div>
                      <p className="mt-1 text-[12px] text-muted-foreground">
                        {review.summary}
                      </p>
                      {review.notes.length ? (
                        <div className="mt-2 flex flex-wrap gap-1.5">
                          {review.notes.map((item) => (
                            <MetaTag key={item}>{item}</MetaTag>
                          ))}
                        </div>
                      ) : null}
                    </li>
                  ))}
                </ul>
              </DetailSection>
            ) : null}
          </TabsContent>

          <TabsContent value="review" className="mt-0">
            <DetailSection title="Reviewer disposition">
              <div className="grid grid-cols-2 gap-1.5">
                {dispositions.map((disposition) => {
                  const active = feedback?.disposition === disposition;

                  return (
                    <button
                      key={disposition}
                      type="button"
                      onClick={() => onDisposition(disposition)}
                      className={cn(
                        "rounded-sm border border-border px-2 py-1.5 text-[12.5px] font-medium transition-colors hover:bg-surface-muted",
                        active &&
                          "border-primary bg-primary text-primary-foreground hover:bg-primary",
                      )}
                    >
                      {dispositionLabels[disposition]}
                    </button>
                  );
                })}
              </div>
            </DetailSection>

            <DetailSection title="Visibility in local queue">
              <Button
                variant="outline"
                size="sm"
                className="h-8 w-full justify-start gap-2"
                onClick={onToggleMute}
              >
                {feedback?.muted ? (
                  <>
                    <Volume2 className="h-3.5 w-3.5" /> Unmute finding
                  </>
                ) : (
                  <>
                    <VolumeX className="h-3.5 w-3.5" /> Mute finding
                  </>
                )}
              </Button>
            </DetailSection>

            <DetailSection title="Reviewer note">
              <Textarea
                value={note}
                onChange={(event) => setNote(event.target.value)}
                rows={5}
                placeholder="Record what you verified, who you asked, and what remains open."
                className="resize-none rounded-sm border-border text-[12.5px]"
              />
              <div className="mt-2 flex items-center gap-2">
                <Button size="sm" className="h-8" onClick={() => onSaveNote(note)}>
                  Save note
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-8 gap-1.5 text-muted-foreground"
                  onClick={onReset}
                >
                  <RotateCcw className="h-3.5 w-3.5" /> Reset local review
                </Button>
              </div>
            </DetailSection>

            <DetailSection title="Local memory updated">
              <span className="num text-[12px] text-muted-foreground">
                {feedback?.updatedAt
                  ? formatDateTime(feedback.updatedAt)
                  : "No local review recorded"}
              </span>
            </DetailSection>
          </TabsContent>
        </div>
      </Tabs>
    </div>
  );
}
