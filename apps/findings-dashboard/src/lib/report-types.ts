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
  role: "source" | "propagation" | "sink";
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
  id: string;
  key: string;
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
  taintFlowSteps: TaintFlowStep[];
  remediationPatch: RemediationPatch | null;
  multiAgentLedger: MultiAgentLedger | null;
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
