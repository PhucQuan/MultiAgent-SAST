"use client";

import { useRef } from "react";
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
import {
  formatConfidence,
  formatDateTime,
  formatLabel,
  shortenPath,
} from "@/lib/dashboard-ui";
import { cn } from "@/lib/utils";
import type {
  AgentReview,
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

function NotePanel({
  eyebrow,
  children,
}: {
  eyebrow: string;
  children: string;
}) {
  return (
    <div className="rounded-xl border border-border bg-background px-4 py-3">
      <div className="mb-2 text-[10.5px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
        {eyebrow}
      </div>
      <p className="text-[12.5px] leading-6 text-foreground">{children}</p>
    </div>
  );
}

function ReviewBundle({ reviews }: { reviews: AgentReview[] }) {
  if (!reviews.length) {
    return (
      <p className="text-[12.5px] text-muted-foreground">
        No agent review bundle was exported.
      </p>
    );
  }

  return (
    <ul className="space-y-3">
      {reviews.map((review) => (
        <li
          key={review.key}
          className="rounded-xl border border-border bg-background px-4 py-3"
        >
          <div className="flex items-center justify-between gap-3">
            <span className="text-[12.5px] font-semibold text-foreground">
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
          <p className="mt-2 text-[12px] leading-6 text-muted-foreground">
            {review.summary}
          </p>
          {review.notes.length ? (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {review.notes.map((item) => (
                <MetaTag key={item}>{item}</MetaTag>
              ))}
            </div>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

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
  const noteRef = useRef<HTMLTextAreaElement | null>(null);

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
        Select a finding from the review queue to inspect evidence and record a
        local reviewer decision.
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col bg-surface">
      <div className="border-b border-border px-5 py-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="num text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
              {finding.id}
            </div>
            <h2 className="mt-1 text-[15px] font-semibold leading-6 text-foreground">
              {finding.message}
            </h2>
            <div className="mt-1 font-mono text-[11.5px] text-muted-foreground">
              {shortenPath(finding.filePath, 5)}
              <span>{finding.line ? `:${finding.line}` : ""}</span>
            </div>
          </div>
          {onClose ? (
            <button
              type="button"
              onClick={onClose}
              className="rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-surface-muted hover:text-foreground"
              aria-label="Close detail"
            >
              <X className="h-4 w-4" />
            </button>
          ) : null}
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-1.5">
          <SeverityTag severity={finding.severity} />
          <StatusTag status={finding.status} />
          <MetaTag>{formatConfidence(finding.confidence)}</MetaTag>
          <MetaTag>{formatLabel(finding.language)}</MetaTag>
          <MetaTag>{formatLabel(finding.family)}</MetaTag>
          {feedback?.disposition ? (
            <MetaTag className="border-primary/25 bg-primary/8 text-primary">
              {dispositionLabels[feedback.disposition]}
            </MetaTag>
          ) : null}
        </div>
      </div>

      <Tabs defaultValue="overview" className="flex min-h-0 flex-1 flex-col gap-0">
        <TabsList className="h-11 w-full justify-start rounded-none border-b border-border bg-surface-muted px-3">
          {["overview", "evidence", "review"].map((tab) => (
            <TabsTrigger
              key={tab}
              value={tab}
              className="h-8 rounded-md px-3 text-[12.5px] capitalize data-[state=active]:bg-background"
            >
              {tab}
            </TabsTrigger>
          ))}
        </TabsList>

        <div className="min-h-0 flex-1 overflow-y-auto">
          <TabsContent value="overview" className="mt-0">
            {finding.manualReviewRequired ? (
              <div className="flex items-start gap-2 border-b border-border bg-sev-medium/8 px-5 py-3">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-sev-medium" />
                <p className="text-[12px] leading-6 text-foreground">
                  Aegis triage still considers this finding inconclusive. Manual
                  confirmation is recommended before it is closed or suppressed.
                </p>
              </div>
            ) : null}

            <DetailSection title="Summary">
              <div className="grid gap-2 sm:grid-cols-2">
                <KeyValue label="Source type" value={finding.sourceType ?? "n/a"} />
                <KeyValue label="Sink function" value={finding.sinkFunction ?? "n/a"} />
                <KeyValue
                  label="Analysis engine"
                  value={finding.analysisEngine ?? "n/a"}
                />
                <KeyValue label="Confidence" value={formatConfidence(finding.confidence)} />
                <KeyValue label="Path length" value={finding.pathLength ?? "n/a"} />
                <KeyValue
                  label="Intermediates"
                  value={finding.intermediateStepCount ?? "n/a"}
                />
                <KeyValue label="Sanitizers" value={finding.sanitizerCount ?? "n/a"} />
                <KeyValue
                  label="Workflow route"
                  value={
                    finding.workflowRoute
                      ? formatLabel(finding.workflowRoute.routeId)
                      : "n/a"
                  }
                />
              </div>
            </DetailSection>

            <DetailSection title="Triage explanation">
              <NotePanel eyebrow="Assessment">
                {finding.explanation ||
                  "No triage explanation was attached to this finding."}
              </NotePanel>
            </DetailSection>

            <DetailSection title="Remediation guidance">
              <NotePanel eyebrow="Recommendation">
                {finding.recommendation ||
                  "No remediation recommendation was attached."}
              </NotePanel>
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
                <ol className="space-y-2">
                  {finding.evidencePath.map((step, index) => (
                    <li
                      key={`${step}-${index}`}
                      className="flex gap-3 rounded-xl border border-border bg-background px-4 py-3 font-mono text-[11.5px] text-foreground"
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

            <DetailSection title="Technical trail">
              <details className="rounded-xl border border-border bg-background">
                <summary className="cursor-pointer list-none px-4 py-3 text-[12.5px] font-medium text-foreground">
                  Open workflow route, reason codes, graph slice, and agent bundle
                </summary>

                <div className="space-y-5 border-t border-border px-4 py-4">
                  {finding.workflowRoute ? (
                    <div>
                      <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                        Workflow route
                      </div>
                      <div className="flex flex-wrap items-center gap-1.5">
                        <MetaTag className="font-mono">
                          {finding.workflowRoute.routeId}
                        </MetaTag>
                        {finding.workflowRoute.steps.map((step) => (
                          <MetaTag key={step}>{formatLabel(step)}</MetaTag>
                        ))}
                      </div>
                      <p className="mt-2 text-[12px] leading-6 text-muted-foreground">
                        {finding.workflowRoute.reason ||
                          "No route rationale was attached to this finding."}
                      </p>
                    </div>
                  ) : null}

                  <div>
                    <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                      Reason codes
                    </div>
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
                  </div>

                  {finding.graphSlice ? (
                    <div>
                      <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                        Graph slice
                      </div>
                      <div className="num grid grid-cols-2 gap-2 text-center sm:grid-cols-3">
                        {[
                          ["Nodes", finding.graphSlice.nodeCount],
                          ["CFG", finding.graphSlice.cfgEdgeCount],
                          ["DFG", finding.graphSlice.dfgEdgeCount],
                          ["Path nodes", finding.graphSlice.pathNodeCount],
                          ["Path edges", finding.graphSlice.pathEdgeCount],
                        ].map(([label, value]) => (
                          <div
                            key={String(label)}
                            className="rounded-xl border border-border px-3 py-3"
                          >
                            <div className="text-[16px] font-semibold text-foreground">
                              {value ?? "n/a"}
                            </div>
                            <div className="text-[10.5px] uppercase tracking-[0.14em] text-muted-foreground">
                              {label}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}

                  <div>
                    <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                      Reasoning notes
                    </div>
                    {finding.reasoningNotes.length ? (
                      <ul className="space-y-2">
                        {finding.reasoningNotes.map((note) => (
                          <li
                            key={note}
                            className="rounded-xl border border-border px-4 py-3 text-[12px] leading-6 text-foreground"
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
                  </div>

                  <div>
                    <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                      Agent review bundle
                    </div>
                    <ReviewBundle reviews={finding.agentReviews} />
                  </div>
                </div>
              </details>
            </DetailSection>
          </TabsContent>

          <TabsContent value="review" className="mt-0">
            <DetailSection title="Reviewer disposition">
              <div className="grid grid-cols-2 gap-2">
                {dispositions.map((disposition) => {
                  const active = feedback?.disposition === disposition;

                  return (
                    <button
                      key={disposition}
                      type="button"
                      onClick={() => onDisposition(disposition)}
                      className={cn(
                        "min-h-[40px] rounded-lg border border-border px-3 py-2 text-[12.5px] font-medium transition-colors hover:bg-surface-muted",
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
                className="h-9 w-full justify-start gap-2 rounded-lg"
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
                ref={noteRef}
                defaultValue={feedback?.note ?? ""}
                rows={6}
                placeholder="Record what you verified, what is still unclear, and why this finding should stay visible or be muted."
                className="min-h-[140px] resize-none rounded-lg border-border bg-background text-[12.5px]"
              />
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <Button
                  size="sm"
                  className="h-9 rounded-lg"
                  onClick={() => onSaveNote(noteRef.current?.value ?? "")}
                >
                  Save note
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-9 gap-1.5 rounded-lg text-muted-foreground"
                  onClick={() => {
                    if (noteRef.current) {
                      noteRef.current.value = "";
                    }
                    onReset();
                  }}
                >
                  <RotateCcw className="h-3.5 w-3.5" /> Reset local review
                </Button>
              </div>
            </DetailSection>

            <DetailSection title="Local memory updated">
              <div className="rounded-xl border border-border bg-background px-4 py-3">
                <span className="num text-[12px] text-muted-foreground">
                  {feedback?.updatedAt
                    ? formatDateTime(feedback.updatedAt)
                    : "No local review recorded"}
                </span>
              </div>
            </DetailSection>
          </TabsContent>
        </div>
      </Tabs>
    </div>
  );
}
