export type Severity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "unknown";

export type TriageStatus =
  | "confirmed"
  | "likely"
  | "needs-review"
  | "suppressed"
  | "unknown";

export type ReviewerDisposition =
  | "confirmed"
  | "needs-review"
  | "false-positive"
  | "suppressed";

export type ReportKind =
  | "workflow"
  | "rich"
  | "triage"
  | "legacy"
  | "standard";

export interface SeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  unknown: number;
}

export interface TriageSummary {
  confirmed: number;
  likely: number;
  "needs-review": number;
  suppressed: number;
  unknown: number;
}

export interface EvidenceContext {
  filePath: string;
  focusLine: number | null;
  startLine: number | null;
  endLine: number | null;
  lines: string[];
  snippet?: string;
}

export interface GraphSlice {
  nodeCount: number | null;
  cfgEdgeCount: number | null;
  dfgEdgeCount: number | null;
  pathNodeCount: number | null;
  pathEdgeCount: number | null;
}

export interface WorkflowRoute {
  routeId: string;
  reason: string;
  steps: string[];
  metadata: Record<string, unknown>;
}

export interface AgentReview {
  key: string;
  title: string;
  summary: string;
  notes: string[];
  metadata: Record<string, unknown>;
}

export interface TaintFlowStep {
  stepNumber: number;
  role: "source" | "assignment" | "propagation" | "sanitizer" | "sink";
  label: string;
  subLabel: string;
  file: string;
  line: number | null;
  column?: number | null;
  codeSnippet: string;
  description: string;
}

export interface DiffLine {
  type: "context" | "remove" | "add";
  lineNum?: number;
  text: string;
}

export interface RemediationPatch {
  filePath: string;
  vulnerableSnippet?: string;
  secureSnippet?: string;
  hunkHeader?: string;
  diffLines: DiffLine[];
  explanation: string;
}

export interface MultiAgentLedger {
  auditorTitle?: string;
  auditorChecks: string[];
  skepticTitle?: string;
  skepticChecks: string[];
  finalVerdictTitle: string;
  finalVerdictStatus: string;
  confidence: number;
  confidenceText: string;
  summary: string;
  recommendations: string[];
}

export interface NormalizedFinding {
  evidenceGraph?: InvestigationGraph | null;
  evidenceDiagnostic?: string | null;
  id: string;
  key: string;
  ruleId: string;
  title: string;
  family: string;
  cweId: string;
  cvssScore: number;
  owaspCategory: string;
  severity: Severity;
  status: TriageStatus;
  confidence: number | null;
  language: string;
  filePath: string;
  fileName: string;
  line: number | null;
  sourceType: string | null;
  sinkFunction: string | null;
  analysisEngine: string | null;
  pathLength: number | null;
  intermediateStepCount: number | null;
  sanitizerCount: number | null;
  message: string;
  explanation: string;
  recommendation: string;
  evidencePath: string[];
  sourceContext: EvidenceContext | null;
  sinkContext: EvidenceContext | null;
  graphSlice: GraphSlice | null;
  knowledgeCards: string[];
  reasonCodes: string[];
  workflowRoute: WorkflowRoute | null;
  agentReviews: AgentReview[];
  reasoningNotes: string[];
  manualReviewRequired: boolean;
  traceCompleteness?: "complete" | "partial" | "unavailable";
  taintFlowSteps: TaintFlowStep[];
  remediationPatch: RemediationPatch | null;
  multiAgentLedger: MultiAgentLedger | null;
}

export interface InvestigationNode {
  id: string;
  kind: string;
  label: string;
  file: string;
  line: number;
  column: number;
  snippet: string;
  context?: string[];
  origin?: string;
}

export interface InvestigationEdge {
  id: string;
  source: string;
  target: string;
  relation: string;
  kind: "data" | "control";
  verified: boolean;
}

export interface InvestigationPath {
  id: string;
  source: string;
  sink: string;
  node_ids: string[];
  edge_ids: string[];
  control_node_ids: string[];
  control_edge_ids: string[];
  sanitizers: string[];
  trace_completeness: "complete" | "partial" | "unavailable";
  verified: boolean;
  confidence: string;
  analysis_limitations: string[];
}

export interface InvestigationGraph {
  schema_version: string;
  analysis_engine: string;
  evidence_mode: "verified_path" | "partial_path" | "sink_only" | "pattern_only" | "no_evidence";
  nodes: InvestigationNode[];
  edges: InvestigationEdge[];
  paths: InvestigationPath[];
  sources: string[];
  sinks: string[];
  sanitizers: string[];
  trace_completeness: string;
  analysis_limitations: string[];
  truncated?: boolean;
  sink_function?: string;
  sink_missing_reason?: string;
}

export interface BackendEvidenceBundle {
  source: { file: string; line: number; column: number; snippet: string };
  sink: { file: string; line: number; column: number; snippet: string };
  intermediate_steps: Array<{
    file: string;
    line: number;
    column: number;
    snippet: string;
  }>;
  sanitizers: Array<Record<string, unknown>>;
  metadata: Record<string, unknown>;
}

export interface NormalizedReport {
  id: string;
  sourcePath: string;
  shortName: string;
  target: string;
  timestamp: string | null;
  scanProfile: string;
  frameworkHints: string[];
  reportKind: ReportKind;
  totalFindings: number;
  severitySummary: SeveritySummary;
  triageSummary: TriageSummary;
  errors: string[];
  findings: NormalizedFinding[];
  metrics: ReportMetrics;
}

export interface ReportMetrics {
  precision: number | null;
  owaspScore: number | null;
  filesScanned: number | null;
  aiEnabled: boolean | null;
}

export interface ReportSummaryCard {
  id: string;
  sourcePath: string;
  shortName: string;
  target: string;
  timestamp: string | null;
  scanProfile: string;
  frameworkHints: string[];
  reportKind: ReportKind;
  totalFindings: number;
  severitySummary: SeveritySummary;
  triageSummary: TriageSummary;
  metrics: ReportMetrics;
}

export interface ReviewerFeedback {
  disposition?: ReviewerDisposition;
  note?: string;
  muted?: boolean;
  updatedAt: string;
}

export type ReviewerFeedbackStore = Record<string, ReviewerFeedback>;
