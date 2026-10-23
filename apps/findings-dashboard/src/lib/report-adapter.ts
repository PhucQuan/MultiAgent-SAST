import { readInvestigationGraph } from "@/lib/investigation-evidence";
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
  TaintFlowStep,
  DiffLine,
  RemediationPatch,
  MultiAgentLedger,
  ReportMetrics,
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

const EMPTY_REPORT_METRICS: ReportMetrics = {
  precision: null,
  owaspScore: null,
  filesScanned: null,
  aiEnabled: null,
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

function deriveCweId(family: string): string {
  const upper = family.toUpperCase();
  if (upper.includes("PATH_TRAVERSAL") || upper.includes("CWE-22") || upper.includes("FILE_ACCESS")) return "CWE-22";
  if (upper.includes("COMMAND_INJECTION") || upper.includes("CWE-78") || upper.includes("RCE") || upper.includes("OS_COMMAND")) return "CWE-78";
  if (upper.includes("INSECURE_DESERIALIZATION") || upper.includes("DESERIALIZATION") || upper.includes("CWE-502")) return "CWE-502";
  if (upper.includes("SQL_INJECTION") || upper.includes("SQLI") || upper.includes("CWE-89")) return "CWE-89";
  if (upper.includes("CODE_INJECTION") || upper.includes("CWE-94")) return "CWE-94";
  if (upper.includes("SSRF") || upper.includes("CWE-918")) return "CWE-918";
  if (upper.includes("OPEN_REDIRECT") || upper.includes("CWE-601")) return "CWE-601";
  if (upper.includes("XSS") || upper.includes("CWE-79")) return "CWE-79";
  if (upper.includes("CSRF") || upper.includes("CWE-352")) return "CWE-352";
  if (upper.includes("RESOURCE") || upper.includes("CWE-400")) return "CWE-400";
  if (upper.includes("DISCLOSURE") || upper.includes("CWE-200")) return "CWE-200";
  return "CWE-Generic";
}

function deriveCvssScore(severity: Severity, confidence: number | null): number {
  const conf = confidence ?? 0.8;
  switch (severity) {
    case "critical": return Number((9.0 + conf * 0.8).toFixed(1));
    case "high": return Number((7.2 + conf * 1.5).toFixed(1));
    case "medium": return Number((4.5 + conf * 2.0).toFixed(1));
    case "low": return Number((2.0 + conf * 1.5).toFixed(1));
    case "info": return 1.0;
    default: return 5.0;
  }
}

function deriveOwaspCategory(family: string): string {
  const upper = family.toUpperCase();
  if (upper.includes("PATH_TRAVERSAL") || upper.includes("OPEN_REDIRECT") || upper.includes("CSRF")) return "A01:2021-Broken Access Control";
  if (upper.includes("SQL") || upper.includes("COMMAND") || upper.includes("CODE") || upper.includes("XSS")) return "A03:2021-Injection";
  if (upper.includes("DESERIALIZATION")) return "A08:2021-Software and Data Integrity Failures";
  if (upper.includes("SSRF")) return "A10:2021-Server-Side Request Forgery";
  if (upper.includes("RESOURCE")) return "A05:2021-Security Misconfiguration";
  return "A04:2021-Insecure Design";
}

function formatOperation(value: string): string { return value.replaceAll("_", " "); }

function buildTaintFlowSteps(
  rawFinding: JsonRecord
): TaintFlowStep[] {
  const evidence = asRecord(rawFinding.evidence);
  const steps: TaintFlowStep[] = [];

  const rawSource = asRecord(evidence?.source);
  const rawSink = asRecord(evidence?.sink);
  const rawIntermediates = asArray(evidence?.intermediate_steps);

  const addEvidenceLocation = (
    location: JsonRecord | null,
    role: TaintFlowStep["role"],
    label: string,
  ): void => {
    if (!location) {
      return;
    }
    const snippet = firstString([location.snippet]);
    const locationFile = firstString([location.file, location.path]);
    const locationLine = firstNumber([location.line]);
    if (!snippet || !locationFile || locationLine === null) {
      return;
    }
    steps.push({
      stepNumber: steps.length + 1,
      role,
      label,
      subLabel: role === "source" ? "Verified source location" : "Verified code location",
      file: locationFile,
      line: locationLine,
      column: firstNumber([location.column]),
      codeSnippet: snippet,
      description: "Loaded from backend evidence; no synthetic step was added.",
    });
  };

  if (getPath(evidence, ["metadata", "source_verified"]) === true) {
    addEvidenceLocation(rawSource, "source", "Source");
  }
  rawIntermediates.forEach((rawIntermediate) => {
    const location = asRecord(rawIntermediate);
    const operation = firstString([location?.operation, location?.operation_type, location?.kind]);
    addEvidenceLocation(location, operation === "sanitizer" ? "sanitizer" : operation === "assignment" ? "assignment" : "propagation", operation ? formatOperation(operation) : "Data-flow step");
  });
  addEvidenceLocation(rawSink, "sink", "Sink");
  return steps;
}

function buildMultiAgentLedger(
  status: TriageStatus,
  confidence: number | null, reviews: AgentReview[]
): MultiAgentLedger | null {
  if (!reviews.length || confidence === null) return null;
  const auditor = reviews.find(r=>r.key === "auditor_review");
  const skeptic = reviews.find(r=>r.key === "skeptic_review");
  const judge = reviews.find(r=>r.key === "judge_review");
  return {
    auditorChecks: auditor?.notes ?? [], skepticChecks: skeptic?.notes ?? [],
    finalVerdictTitle: "Recorded review", finalVerdictStatus: status,
    confidence, confidenceText: `${Math.round(confidence*100)}% confidence`,
    summary: judge?.summary || auditor?.summary || "No review summary recorded.",
    recommendations: [],
  };
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
  const ruleId =
    firstString([
      rawFinding.rule_id,
      rawFinding.ruleId,
      getPath(rawFinding, ["rule", "id"]),
    ]) ?? family;
  const title =
    firstString([
      rawFinding.rule_title,
      rawFinding.title,
      getPath(rawFinding, ["rule", "title"]),
      rawFinding.message,
    ]) ?? family;
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
  const evidenceGraph = readInvestigationGraph(getPath(rawFinding, ["evidence", "graph"]));
  const sinkFunction = firstString([
    evidenceGraph?.sink_function,
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

  const cweId =
    firstString([
      rawFinding.cwe,
      rawFinding.cwe_id,
      getPath(rawFinding, ["metadata", "cwe"]),
      getPath(rawFinding, ["metadata", "cwe_id"]),
    ]) ?? deriveCweId(family);
  const cvssScore = deriveCvssScore(severity, confidence);
  const owaspCategory = deriveOwaspCategory(family);
  const taintFlowSteps = buildTaintFlowSteps(rawFinding);
  const rawPatch = (
    rawFinding.remediation_patch ||
    getPath(rawFinding, ["metadata", "remediation_patch"]) ||
    getPath(rawFinding, ["metadata", "triage", "remediation_patch"]) ||
    getPath(rawFinding, ["agent_reviews", "judge_review", "remediation_patch"]) ||
    getPath(rawFinding, ["metadata", "judge_review", "remediation_patch"])
  ) as JsonRecord | undefined;

  let remediationPatch: RemediationPatch | null = null;
  const rawDiffLines = asArray(rawPatch?.diff_lines ?? rawPatch?.diffLines);
  if (rawPatch && rawDiffLines.length > 0) {
    remediationPatch = {
      filePath: asString(rawPatch.file_path ?? rawPatch.filePath) || filePath,
      vulnerableSnippet: asString(rawPatch.vulnerable_snippet ?? rawPatch.vulnerableSnippet) || undefined,
      secureSnippet: asString(rawPatch.secure_snippet ?? rawPatch.secureSnippet) || undefined,
      hunkHeader: asString(rawPatch.hunk_header ?? rawPatch.hunkHeader) || undefined,
      diffLines: rawDiffLines.map((dl) => {
        const item = asRecord(dl) ?? {};
        const rawType = asString(item.type) || "context";
        const type: "context" | "remove" | "add" =
          rawType === "remove" ? "remove" : rawType === "add" ? "add" : "context";
        return {
          type,
          lineNum: firstNumber([item.line_num, item.lineNum, item.line]) ?? undefined,
          text: asString(item.text) || "",
        };
      }),
      explanation: asString(rawPatch.explanation) || "AI-generated remediation patch.",
    };
  }
  const multiAgentLedger = buildMultiAgentLedger(finalStatus, confidence, agentReviews);

  return {
    id,
    key: `${reportId}:${id}:${filePath}:${line ?? "?"}`,
    ruleId,
    title,
    family,
    cweId,
    cvssScore,
    owaspCategory,
    severity,
    status: finalStatus,
    confidence,
    language,
    filePath,
    fileName,
    line,
    sourceType,
    sinkFunction,
    evidenceGraph,
    evidenceDiagnostic: evidenceGraph ? evidenceGraph.sink_missing_reason ?? null : "No valid structured graph is available in this report.",
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
    traceCompleteness:
      evidenceGraph?.trace_completeness === "complete" ||
      getPath(rawFinding, ["evidence", "metadata", "trace_completeness"]) === "complete"
        ? "complete"
        : evidenceGraph?.trace_completeness === "partial" || taintFlowSteps.length
          ? "partial"
          : "unavailable",
    taintFlowSteps,
    remediationPatch,
    multiAgentLedger,
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

function normalizeReportMetrics(rawReport: JsonRecord): ReportMetrics {
  const precision = firstNumber([
    getPath(rawReport, ["metrics", "precision"]),
    getPath(rawReport, ["benchmark", "precision"]),
  ]);
  const owaspScore = firstNumber([
    getPath(rawReport, ["metrics", "owasp_score"]),
    getPath(rawReport, ["metrics", "owaspScore"]),
    getPath(rawReport, ["benchmark", "owasp_score"]),
  ]);
  const filesScanned = firstNumber([
    getPath(rawReport, ["metrics", "files_scanned"]),
    getPath(rawReport, ["summary", "files_scanned"]),
  ]);
  const aiEnabled = firstBoolean([
    getPath(rawReport, ["metrics", "ai_enabled"]),
    getPath(rawReport, ["ai", "enabled"]),
    getPath(rawReport, ["summary", "ai", "enabled"]),
  ]);

  return {
    ...EMPTY_REPORT_METRICS,
    precision,
    owaspScore,
    filesScanned,
    aiEnabled,
  };
}

export function normalizeReport(rawReport: unknown, sourcePath: string): NormalizedReport | null {
  if (!isRecord(rawReport)) {
    return null;
  }

  const rawFindings = asArray(rawReport.findings).filter(isRecord);
  if (!Array.isArray(rawReport.findings)) {
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
    metrics: normalizeReportMetrics(rawReport),
  };
}

export function normalizeBackendScanResult(
  result: {
    scan_id: string;
    summary: {
      target: string;
      files_scanned: number;
      total_vulnerabilities: number;
      by_severity: Record<string, number>;
      errors: string[];
      duration_seconds?: number;
    };
    findings: unknown[];
    evidence_bundles?: unknown[];
    triage_records: unknown[];
    repo_profile: Record<string, unknown>;
    workflow_metadata: Record<string, unknown>;
    ai: { enabled: boolean };
  },
): NormalizedReport {
  const findings = result.findings.length
    ? result.findings
    : result.triage_records
        .map((record) => (isRecord(record) ? record.finding : null))
        .filter((finding): finding is JsonRecord => isRecord(finding));
  const rawReport = {
    id: result.scan_id,
    target: result.summary.target,
    summary: result.summary,
    findings,
    errors: result.summary.errors,
    workflow_summary: {
      ...(result.workflow_metadata ?? {}),
      ...(result.repo_profile ?? {}),
    },
    metrics: {
      files_scanned: result.summary.files_scanned,
      duration_seconds: result.summary.duration_seconds,
      ai_enabled: result.ai.enabled,
    },
  };
  return normalizeReport(rawReport, `api:${result.scan_id}`) ?? {
    id: result.scan_id,
    sourcePath: `api:${result.scan_id}`,
    shortName: result.summary.target.split(/[\\/]/).pop() || "API scan",
    target: result.summary.target,
    timestamp: new Date().toISOString(),
    scanProfile: "api",
    frameworkHints: [],
    reportKind: "workflow",
    totalFindings: 0,
    severitySummary: { ...EMPTY_SEVERITY_SUMMARY },
    triageSummary: { ...EMPTY_TRIAGE_SUMMARY },
    errors: result.summary.errors,
    findings: [],
    metrics: {
      ...EMPTY_REPORT_METRICS,
      filesScanned: result.summary.files_scanned,
      aiEnabled: result.ai.enabled,
    },
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
    metrics: report.metrics,
  };
}
