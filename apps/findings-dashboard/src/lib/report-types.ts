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

export interface NormalizedFinding {
  id: string;
  key: string;
  family: string;
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
}

export interface ReviewerFeedback {
  disposition?: ReviewerDisposition;
  note?: string;
  muted?: boolean;
  updatedAt: string;
}

export type ReviewerFeedbackStore = Record<string, ReviewerFeedback>;
