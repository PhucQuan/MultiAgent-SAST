import type {
  AgentReview,
  EvidenceContext,
  GraphSlice,
  NormalizedFinding,
  NormalizedReport,
  ReportKind,
  ReportSummaryCard,
  Severity,
  SeveritySummary,
  TriageStatus,
  TriageSummary,
  WorkflowRoute,
} from "@/lib/report-types";

type JsonRecord = Record<string, unknown>;

const EMPTY_SEVERITY_SUMMARY: SeveritySummary = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
  unknown: 0,
};

const EMPTY_TRIAGE_SUMMARY: TriageSummary = {
  confirmed: 0,
  likely: 0,
  "needs-review": 0,
  suppressed: 0,
  unknown: 0,
};

const AGENT_REVIEW_LABELS: Record<string, string> = {
  auditor_review: "Auditor Review",
  skeptic_review: "Skeptic Review",
  judge_review: "Judge Review",
};

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asRecord(value: unknown): JsonRecord | null {
  return isRecord(value) ? value : null;
}

function asString(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function asBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function firstBoolean(candidates: unknown[]): boolean | null {
  for (const candidate of candidates) {
    const value = asBoolean(candidate);
    if (value !== null) {
      return value;
    }
  }

  return null;
}

function asNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asStringArray(value: unknown): string[] {
  return asArray(value)
    .map((entry) => asString(entry))
    .filter((entry): entry is string => Boolean(entry));
}

function uniqueStrings(values: Array<string | null | undefined>): string[] {
  const seen = new Set<string>();
  const deduped: string[] = [];

  for (const value of values) {
    const normalized = value?.trim();
    if (!normalized || seen.has(normalized)) {
      continue;
    }

    seen.add(normalized);
    deduped.push(normalized);
  }

  return deduped;
}

function getPath(source: unknown, path: string[]): unknown {
  let current: unknown = source;

  for (const segment of path) {
    if (!isRecord(current) || !(segment in current)) {
      return undefined;
    }

    current = current[segment];
  }

  return current;
}

function firstString(candidates: unknown[]): string | null {
  for (const candidate of candidates) {
    const value = asString(candidate);
    if (value) {
      return value;
    }
  }

  return null;
}

function firstNumber(candidates: unknown[]): number | null {
  for (const candidate of candidates) {
    const value = asNumber(candidate);
    if (value !== null) {
      return value;
    }
  }

  return null;
}

function firstRecord(candidates: unknown[]): JsonRecord | null {
  for (const candidate of candidates) {
    const value = asRecord(candidate);
    if (value) {
      return value;
    }
  }

  return null;
}

function firstStringArray(candidates: unknown[]): string[] {
  for (const candidate of candidates) {
    const values = asStringArray(candidate);
    if (values.length) {
      return values;
    }
  }

  return [];
}

function firstCount(candidates: unknown[]): number | null {
  for (const candidate of candidates) {
    if (Array.isArray(candidate)) {
      return candidate.length;
    }

    const value = asNumber(candidate);
    if (value !== null) {
      return value;
    }
  }

  return null;
}

function fileNameFromPath(filePath: string): string {
  const normalized = filePath.replace(/\\/g, "/");
  const segments = normalized.split("/").filter(Boolean);
  return segments.at(-1) ?? filePath;
}

function stripExtension(fileName: string): string {
  return fileName.replace(/\.[^/.]+$/, "");
}

function clampConfidence(value: number | null): number | null {
  if (value === null) {
    return null;
  }

  if (value > 1 && value <= 100) {
    return Math.max(0, Math.min(1, value / 100));
  }

  return Math.max(0, Math.min(1, value));
}

function normalizeSeverity(value: string | null): Severity {
  if (!value) {
    return "unknown";
  }

  const normalized = value.toLowerCase().replace(/[\s_]+/g, "-");

  switch (normalized) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    case "info":
    case "informational":
      return "info";
    default:
      return "unknown";
  }
}

function normalizeTriageStatus(value: string | null): TriageStatus {
  if (!value) {
    return "unknown";
  }

  const normalized = value.toLowerCase().replace(/[\s_]+/g, "-");

  switch (normalized) {
    case "confirmed":
      return "confirmed";
    case "likely":
      return "likely";
    case "needs-review":
    case "manual-review":
    case "review":
      return "needs-review";
    case "suppressed":
    case "muted":
    case "false-positive":
      return "suppressed";
    default:
      return "unknown";
  }
}

function deriveLegacyStatus(rawFinding: JsonRecord): TriageStatus {
  const aiVerification = asRecord(rawFinding.ai_verification);
  const isVulnerable = asBoolean(aiVerification?.is_vulnerable);
  const explanation =
    firstString([
      aiVerification?.explanation,
      rawFinding.explanation,
      rawFinding.message,
    ])?.toLowerCase() ?? "";
  const confidence = clampConfidence(asNumber(aiVerification?.confidence)) ?? 0;

  if (isVulnerable === false) {
    return "suppressed";
  }

  if (explanation.includes("manual review")) {
    return "needs-review";
  }

  if (isVulnerable && confidence >= 0.75) {
    return "likely";
  }

  if (isVulnerable) {
    return "needs-review";
  }

  return "unknown";
}

function deriveLanguage(filePath: string, explicitLanguage: string | null): string {
  if (explicitLanguage) {
    return explicitLanguage.toLowerCase();
  }

  const extension = fileNameFromPath(filePath).split(".").at(-1)?.toLowerCase();

  switch (extension) {
    case "py":
      return "python";
    case "js":
    case "jsx":
      return "javascript";
    case "ts":
    case "tsx":
      return "typescript";
    case "php":
      return "php";
    case "java":
      return "java";
    case "go":
      return "go";
    default:
      return "unknown";
  }
}

function normalizeContext(rawContext: JsonRecord | null): EvidenceContext | null {
  if (!rawContext) {
    return null;
  }

  const filePath =
    firstString([rawContext.file_path, rawContext.file, rawContext.path]) ?? "";
  const focusLine = firstNumber([rawContext.focus_line, rawContext.line]);
  const startLine = firstNumber([rawContext.start_line, rawContext.line]);
  const endLine = firstNumber([rawContext.end_line, rawContext.line]);
  const lines = asStringArray(rawContext.lines);
  const snippet = asString(rawContext.snippet);

  if (!filePath && !lines.length && !snippet) {
    return null;
  }

  return {
    filePath,
    focusLine,
    startLine,
    endLine,
    lines: lines.length ? lines : snippet ? [snippet] : [],
    ...(snippet ? { snippet } : {}),
  };
}

function normalizeSnippetContext(rawContext: JsonRecord | null): EvidenceContext | null {
  if (!rawContext) {
    return null;
  }

  const filePath = firstString([rawContext.file, rawContext.file_path]) ?? "";
  const line = firstNumber([rawContext.line]);
  const snippet = asString(rawContext.snippet);

  if (!filePath && !snippet) {
    return null;
  }

  return {
    filePath,
    focusLine: line,
    startLine: line,
    endLine: line,
    lines: snippet ? [`${line ?? "?"}: ${snippet}`] : [],
    ...(snippet ? { snippet } : {}),
  };
}

function normalizeGraphSlice(rawGraph: JsonRecord | null): GraphSlice | null {
  if (!rawGraph) {
    return null;
  }

  const graph: GraphSlice = {
    nodeCount: firstNumber([rawGraph.node_count]),
    cfgEdgeCount: firstNumber([rawGraph.cfg_edge_count]),
    dfgEdgeCount: firstNumber([rawGraph.dfg_edge_count]),
    pathNodeCount: firstNumber([rawGraph.path_node_count]),
    pathEdgeCount: firstNumber([rawGraph.path_edge_count]),
  };

  return Object.values(graph).some((value) => value !== null) ? graph : null;
}

function normalizeWorkflowRoute(rawRoute: JsonRecord | null): WorkflowRoute | null {
  if (!rawRoute) {
    return null;
  }

  const routeId = firstString([rawRoute.route_id, rawRoute.route]) ?? "";
  const reason = firstString([rawRoute.reason]) ?? "";
  const steps = asStringArray(rawRoute.steps);
  const metadata = asRecord(rawRoute.metadata) ?? {};

  if (!routeId && !reason && !steps.length) {
    return null;
  }

  return {
    routeId: routeId || "workflow-route",
    reason,
    steps,
    metadata,
  };
}

function normalizeAgentReview(key: string, rawReview: JsonRecord | null): AgentReview | null {
  if (!rawReview) {
    return null;
  }

  const summary =
    firstString([rawReview.summary, rawReview.explanation, rawReview.reason]) ?? "";
  const notes = uniqueStrings([
    ...asStringArray(rawReview.notes),
    ...asStringArray(rawReview.objections),
    ...asStringArray(rawReview.mitigation_signals),
    ...asStringArray(getPath(rawReview, ["metadata", "risk_signals"])),
  ]);

  if (!summary && !notes.length) {
    return null;
  }

  return {
    key,
    title: AGENT_REVIEW_LABELS[key] ?? key,
    summary,
    notes,
    metadata: asRecord(rawReview.metadata) ?? {},
  };
}

function collectAgentReviews(rawFinding: JsonRecord): AgentReview[] {
  const reviewKeys = ["auditor_review", "skeptic_review", "judge_review"];
  const reviews: AgentReview[] = [];

  for (const reviewKey of reviewKeys) {
    const rawReview = firstRecord([
      getPath(rawFinding, ["agent_reviews", reviewKey]),
      getPath(rawFinding, ["metadata", "triage", "agent_reviews", reviewKey]),
      getPath(rawFinding, ["triage_decision", "metadata", reviewKey]),
      getPath(rawFinding, ["metadata", reviewKey]),
    ]);

    const review = normalizeAgentReview(reviewKey, rawReview);
    if (review) {
      reviews.push(review);
    }
  }

  return reviews;
}

function collectKnowledgeCards(rawFinding: JsonRecord): string[] {
  return uniqueStrings([
    ...firstStringArray([
      getPath(rawFinding, ["triage_decision", "metadata", "knowledge_card_ids"]),
      getPath(rawFinding, ["metadata", "triage", "knowledge_card_ids"]),
      getPath(rawFinding, ["metadata", "knowledge_card_ids"]),
    ]),
    ...firstStringArray([
      getPath(rawFinding, ["agent_reviews", "auditor_review", "matched_card_ids"]),
      getPath(rawFinding, ["metadata", "auditor_review", "matched_card_ids"]),
      getPath(rawFinding, ["metadata", "triage", "agent_reviews", "auditor_review", "matched_card_ids"]),
    ]),
  ]);
}

function collectReasonCodes(rawFinding: JsonRecord): string[] {
  const evidenceNotes = asStringArray(getPath(rawFinding, ["triage_decision", "evidence_notes"]));
  const noteCodes = evidenceNotes.flatMap((note) => {
    if (note.startsWith("risk_signal=")) {
      return [note.slice("risk_signal=".length)];
    }

    if (note.startsWith("framework_hint=")) {
      return [note.slice("framework_hint=".length)];
    }

    return [];
  });

  return uniqueStrings([
    ...firstStringArray([
      getPath(rawFinding, ["triage_decision", "reason_codes"]),
      getPath(rawFinding, ["metadata", "reason_codes"]),
      getPath(rawFinding, ["metadata", "triage", "reason_codes"]),
      getPath(rawFinding, ["agent_reviews", "judge_review", "metadata", "risk_signals"]),
      getPath(rawFinding, ["metadata", "judge_review", "metadata", "risk_signals"]),
    ]),
    ...noteCodes,
  ]);
}

function collectReasoningNotes(rawFinding: JsonRecord, agentReviews: AgentReview[]): string[] {
  return uniqueStrings([
    ...asStringArray(getPath(rawFinding, ["triage_decision", "evidence_notes"])),
    ...agentReviews.flatMap((review) => review.notes),
  ]);
}

function normalizeSeveritySummary(
  rawSummary: JsonRecord | null,
  findings: NormalizedFinding[],
): SeveritySummary {
  const summary: SeveritySummary = { ...EMPTY_SEVERITY_SUMMARY };

  if (rawSummary) {
    summary.critical = firstNumber([rawSummary.critical]) ?? 0;
    summary.high = firstNumber([rawSummary.high]) ?? 0;
    summary.medium = firstNumber([rawSummary.medium]) ?? 0;
    summary.low = firstNumber([rawSummary.low]) ?? 0;
    summary.info = firstNumber([rawSummary.info, rawSummary.informational]) ?? 0;
    summary.unknown = firstNumber([rawSummary.unknown]) ?? 0;
  }

  const hasCounts = Object.values(summary).some((count) => count > 0);
  if (hasCounts) {
    return summary;
  }

  for (const finding of findings) {
    summary[finding.severity] += 1;
  }

  return summary;
}

function normalizeTriageSummary(
  rawSummary: JsonRecord | null,
  findings: NormalizedFinding[],
): TriageSummary {
  const summary: TriageSummary = { ...EMPTY_TRIAGE_SUMMARY };

  if (rawSummary) {
    summary.confirmed = firstNumber([rawSummary.confirmed]) ?? 0;
    summary.likely = firstNumber([rawSummary.likely]) ?? 0;
    summary["needs-review"] = firstNumber([
      rawSummary["needs-review"],
      rawSummary.needs_review,
      rawSummary.review,
    ]) ?? 0;
    summary.suppressed = firstNumber([
      rawSummary.suppressed,
      rawSummary["false-positive"],
      rawSummary.false_positive,
      rawSummary.muted,
    ]) ?? 0;
    summary.unknown = firstNumber([rawSummary.unknown]) ?? 0;
  }

  const hasCounts = Object.values(summary).some((count) => count > 0);
  if (hasCounts) {
    return summary;
  }

  for (const finding of findings) {
    summary[finding.status] += 1;
  }

  return summary;
}

function detectReportKind(rawReport: JsonRecord, findings: NormalizedFinding[]): ReportKind {
  if (asRecord(rawReport.workflow_summary)) {
    return "workflow";
  }

  if (
    findings.some(
      (finding) =>
        finding.agentReviews.length > 0 ||
        finding.workflowRoute !== null ||
        finding.reasoningNotes.length > 0,
    )
  ) {
    return "rich";
  }

  if (asRecord(rawReport.triage_summary)) {
    return "triage";
  }

  if (asArray(rawReport.findings).some((finding) => isRecord(finding) && asRecord(finding.ai_verification))) {
    return "legacy";
  }

  return "standard";
}

function normalizeFinding(rawFinding: JsonRecord, reportId: string, reportTarget: string): NormalizedFinding {
  const filePath =
    firstString([
      rawFinding.file,
      getPath(rawFinding, ["evidence", "sink", "file"]),
      getPath(rawFinding, ["evidence", "source", "file"]),
      reportTarget,
    ]) ?? "unknown";
  const line = firstNumber([
    rawFinding.line,
    getPath(rawFinding, ["evidence", "sink", "line"]),
    getPath(rawFinding, ["evidence", "source", "line"]),
  ]);
  const fileName = fileNameFromPath(filePath);
  const id =
    firstString([rawFinding.id]) ??
    `${reportId}:${fileName}:${line ?? "?"}:${firstString([rawFinding.type, rawFinding.rule_id]) ?? "finding"}`;
  const family =
    firstString([rawFinding.type, rawFinding.vulnerability_type, rawFinding.rule_id]) ??
    "UNKNOWN";
  const severity = normalizeSeverity(firstString([rawFinding.severity]));
  const status = normalizeTriageStatus(
    firstString([
      getPath(rawFinding, ["triage_decision", "status"]),
      rawFinding.triage_status,
      getPath(rawFinding, ["metadata", "triage", "final_status"]),
      getPath(rawFinding, ["metadata", "judge_review", "final_status"]),
    ]),
  );
  const finalStatus = status === "unknown" ? deriveLegacyStatus(rawFinding) : status;
  const confidence = clampConfidence(
    firstNumber([
      getPath(rawFinding, ["triage_decision", "confidence"]),
      rawFinding.confidence,
      getPath(rawFinding, ["metadata", "triage", "final_confidence"]),
      getPath(rawFinding, ["ai_verification", "confidence"]),
    ]),
  );
  const language = deriveLanguage(
    filePath,
    firstString([rawFinding.language, getPath(rawFinding, ["metadata", "language"])]),
  );
  const sourceType = firstString([
    rawFinding.source_type,
    getPath(rawFinding, ["metadata", "source_type"]),
    getPath(rawFinding, ["evidence", "metadata", "detection", "source_type"]),
    getPath(rawFinding, ["metadata", "detection", "source_type"]),
  ]);
  const sinkFunction = firstString([
    rawFinding.sink_function,
    getPath(rawFinding, ["metadata", "sink_function"]),
    getPath(rawFinding, ["evidence", "metadata", "detection", "sink_function"]),
    getPath(rawFinding, ["metadata", "detection", "sink_function"]),
  ]);
  const analysisEngine = firstString([
    getPath(rawFinding, ["evidence", "metadata", "analysis_engine"]),
    getPath(rawFinding, ["metadata", "dataflow_metadata", "analysis_engine"]),
    getPath(rawFinding, ["metadata", "detection", "analysis_engine"]),
  ]);
  const pathLength = firstCount([
    getPath(rawFinding, ["evidence", "summary", "path_length"]),
    getPath(rawFinding, ["metadata", "evidence_summary", "path_length"]),
    getPath(rawFinding, ["metadata", "detection", "evidence_summary", "path_length"]),
    getPath(rawFinding, ["evidence", "metadata", "path_summary"]),
    rawFinding.dataflow,
  ]);
  const intermediateStepCount = firstCount([
    getPath(rawFinding, ["evidence", "summary", "intermediate_step_count"]),
    getPath(rawFinding, ["metadata", "evidence_summary", "intermediate_step_count"]),
    getPath(rawFinding, ["metadata", "detection", "evidence_summary", "intermediate_step_count"]),
    getPath(rawFinding, ["evidence", "intermediate_steps"]),
  ]);
  const sanitizerCount = firstCount([
    getPath(rawFinding, ["evidence", "summary", "sanitizer_count"]),
    getPath(rawFinding, ["metadata", "evidence_summary", "sanitizer_count"]),
    getPath(rawFinding, ["metadata", "detection", "evidence_summary", "sanitizer_count"]),
    getPath(rawFinding, ["evidence", "sanitizers"]),
  ]);
  const message =
    firstString([rawFinding.message]) ??
    `${family} at ${fileName}${line ? `:${line}` : ""}`;
  const explanation =
    firstString([
      getPath(rawFinding, ["triage_decision", "explanation"]),
      rawFinding.explanation,
      getPath(rawFinding, ["ai_verification", "explanation"]),
    ]) ?? "";
  const recommendation =
    firstString([
      getPath(rawFinding, ["triage_decision", "recommendation"]),
      rawFinding.recommendation,
      getPath(rawFinding, ["ai_verification", "recommendation"]),
    ]) ?? "";
  const evidencePath = firstStringArray([
    getPath(rawFinding, ["evidence", "summary", "path_summary"]),
    getPath(rawFinding, ["evidence", "metadata", "path_summary"]),
    getPath(rawFinding, ["metadata", "evidence_summary", "path_summary"]),
    rawFinding.dataflow,
  ]);
  const sourceContext =
    normalizeContext(
      firstRecord([
        getPath(rawFinding, ["agent_reviews", "auditor_review", "context", "source_window"]),
        getPath(rawFinding, ["metadata", "triage", "agent_reviews", "auditor_review", "context", "source_window"]),
        getPath(rawFinding, ["triage_decision", "metadata", "auditor_review", "context", "source_window"]),
        getPath(rawFinding, ["metadata", "auditor_review", "context", "source_window"]),
      ]),
    ) ?? normalizeSnippetContext(asRecord(getPath(rawFinding, ["evidence", "source"])));
  const sinkContext =
    normalizeContext(
      firstRecord([
        getPath(rawFinding, ["agent_reviews", "auditor_review", "context", "sink_window"]),
        getPath(rawFinding, ["metadata", "triage", "agent_reviews", "auditor_review", "context", "sink_window"]),
        getPath(rawFinding, ["triage_decision", "metadata", "auditor_review", "context", "sink_window"]),
        getPath(rawFinding, ["metadata", "auditor_review", "context", "sink_window"]),
      ]),
    ) ?? normalizeSnippetContext(asRecord(getPath(rawFinding, ["evidence", "sink"])));
  const graphSlice = normalizeGraphSlice(
    firstRecord([
      getPath(rawFinding, ["evidence", "summary", "graph_slice"]),
      getPath(rawFinding, ["metadata", "evidence_summary", "graph_slice"]),
      getPath(rawFinding, ["metadata", "detection", "evidence_summary", "graph_slice"]),
    ]),
  );
  const workflowRoute = normalizeWorkflowRoute(
    firstRecord([
      getPath(rawFinding, ["triage_decision", "metadata", "workflow_route"]),
      getPath(rawFinding, ["metadata", "triage", "workflow_route"]),
      getPath(rawFinding, ["metadata", "workflow_route"]),
    ]),
  );
  const agentReviews = collectAgentReviews(rawFinding);
  const knowledgeCards = collectKnowledgeCards(rawFinding);
  const reasonCodes = collectReasonCodes(rawFinding);
  const reasoningNotes = collectReasoningNotes(rawFinding, agentReviews);
  const manualReviewRequired =
    firstBoolean([
      getPath(rawFinding, ["triage_decision", "manual_review_required"]),
      getPath(rawFinding, ["metadata", "manual_review_required"]),
      getPath(rawFinding, ["metadata", "triage", "manual_review_required"]),
    ]) ??
    (
      finalStatus === "needs-review" ||
      explanation.toLowerCase().includes("manual review") ||
      recommendation.toLowerCase().includes("manual review")
    );

  return {
    id,
    key: `${reportId}:${id}:${filePath}:${line ?? "?"}`,
    family,
    severity,
    status: finalStatus,
    confidence,
    language,
    filePath,
    fileName,
    line,
    sourceType,
    sinkFunction,
    analysisEngine,
    pathLength,
    intermediateStepCount,
    sanitizerCount,
    message,
    explanation,
    recommendation,
    evidencePath,
    sourceContext,
    sinkContext,
    graphSlice,
    knowledgeCards,
    reasonCodes,
    workflowRoute,
    agentReviews,
    reasoningNotes,
    manualReviewRequired,
  };
}

function collectFrameworkHints(findings: JsonRecord[], rawReport: JsonRecord): string[] {
  const hints = uniqueStrings([
    ...asStringArray(getPath(rawReport, ["workflow_summary", "framework_hints"])),
    ...findings.flatMap((finding) =>
      asStringArray(
        firstRecord([
          getPath(finding, ["agent_reviews", "auditor_review", "metadata"]),
          getPath(finding, ["metadata", "triage", "agent_reviews", "auditor_review", "metadata"]),
          getPath(finding, ["triage_decision", "metadata", "auditor_review", "metadata"]),
          getPath(finding, ["metadata", "auditor_review", "metadata"]),
        ])?.framework_hints,
      ),
    ),
  ]);

  return hints;
}

function detectScanProfile(findings: JsonRecord[], rawReport: JsonRecord): string {
  return (
    firstString([
      getPath(rawReport, ["workflow_summary", "scan_profile"]),
      ...findings.map((finding) =>
        firstString([
          getPath(finding, ["agent_reviews", "auditor_review", "metadata", "scan_profile"]),
          getPath(finding, ["metadata", "triage", "agent_reviews", "auditor_review", "metadata", "scan_profile"]),
          getPath(finding, ["triage_decision", "metadata", "auditor_review", "metadata", "scan_profile"]),
          getPath(finding, ["metadata", "auditor_review", "metadata", "scan_profile"]),
        ]),
      ),
    ]) ?? "scan-default"
  );
}

function collectErrors(rawReport: JsonRecord): string[] {
  return asArray(rawReport.errors)
    .map((errorValue) => {
      if (typeof errorValue === "string") {
        return errorValue.trim();
      }

      if (isRecord(errorValue)) {
        return (
          firstString([errorValue.message, errorValue.error, errorValue.code]) ??
          JSON.stringify(errorValue)
        );
      }

      return null;
    })
    .filter((value): value is string => Boolean(value));
}

export function normalizeReport(rawReport: unknown, sourcePath: string): NormalizedReport | null {
  if (!isRecord(rawReport)) {
    return null;
  }

  const rawFindings = asArray(rawReport.findings).filter(isRecord);
  if (!rawFindings.length) {
    return null;
  }

  const target =
    firstString([
      getPath(rawReport, ["summary", "target"]),
      getPath(rawReport, ["scan_metadata", "target"]),
      sourcePath,
    ]) ?? sourcePath;
  const reportId = sourcePath;
  const findings = rawFindings.map((rawFinding) =>
    normalizeFinding(rawFinding, reportId, target),
  );
  const severitySummary = normalizeSeveritySummary(
    asRecord(getPath(rawReport, ["summary", "by_severity"])),
    findings,
  );
  const triageSummary = normalizeTriageSummary(
    firstRecord([
      getPath(rawReport, ["triage_summary"]),
      getPath(rawReport, ["workflow_summary", "triage_summary"]),
    ]),
    findings,
  );
  const shortName =
    stripExtension(fileNameFromPath(target)) ||
    stripExtension(fileNameFromPath(sourcePath)) ||
    "aegis-report";
  const timestamp =
    firstString([
      getPath(rawReport, ["scan_metadata", "timestamp"]),
      getPath(rawReport, ["metadata", "timestamp"]),
    ]) ?? null;
  const reportKind = detectReportKind(rawReport, findings);

  return {
    id: reportId,
    sourcePath,
    shortName,
    target,
    timestamp,
    scanProfile: detectScanProfile(rawFindings, rawReport),
    frameworkHints: collectFrameworkHints(rawFindings, rawReport),
    reportKind,
    totalFindings: findings.length,
    severitySummary,
    triageSummary,
    errors: collectErrors(rawReport),
    findings,
  };
}

export function summarizeReport(report: NormalizedReport): ReportSummaryCard {
  return {
    id: report.id,
    sourcePath: report.sourcePath,
    shortName: report.shortName,
    target: report.target,
    timestamp: report.timestamp,
    scanProfile: report.scanProfile,
    frameworkHints: report.frameworkHints,
    reportKind: report.reportKind,
    totalFindings: report.totalFindings,
    severitySummary: report.severitySummary,
    triageSummary: report.triageSummary,
  };
}
