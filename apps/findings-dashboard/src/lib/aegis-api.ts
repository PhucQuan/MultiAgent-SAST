/**
 * API client for interacting with the Aegis-SAST FastAPI backend (http://localhost:8000).
 */

export interface BackendScanConfig {
  enable_ai_verification?: boolean;
  max_analysis_depth?: number;
  rules_path?: string | null;
  append_rules_paths?: string[];
  exclude_dir_names?: string[];
  exclude_globs?: string[];
  scan_engine?: "deterministic" | "semgrep";
}

export type BackendScanStatus = "queued" | "running" | "completed" | "failed";

export interface StartBackendScanRequest {
  path: string;
  repo_path?: string;
  language?: string;
  config?: BackendScanConfig;
}

export interface BackendScanJob {
  scan_id: string;
  status: BackendScanStatus;
  started_at: string;
  finished_at?: string | null;
  progress: Array<Record<string, unknown>>;
  result?: {
    summary: {
      target: string;
      files_scanned: number;
      total_vulnerabilities: number;
      by_severity: Record<string, number>;
      errors: string[];
      duration_seconds?: number;
    };
    ai: {
      requested?: boolean;
      enabled: boolean;
      error?: string | null;
    };
  } | null;
  error?: string | null;
}

export interface BackendScanResult {
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
  ai: {
    requested?: boolean;
    enabled: boolean;
    error?: string | null;
  };
}

const API_BASE_URL =
  process.env.NEXT_PUBLIC_AEGIS_API_URL || "http://localhost:8000";

/**
 * Start a new scan via the FastAPI backend.
 */
export async function startBackendScan(
  payload: StartBackendScanRequest,
): Promise<BackendScanJob> {
  const response = await fetch(`${API_BASE_URL}/api/v1/scan`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(
      `Failed to start backend scan (${response.status}): ${errorText}`,
    );
  }

  return (await response.json()) as BackendScanJob;
}

/**
 * Poll scan status and live progress events.
 */
export async function getBackendScanStatus(
  scanId: string,
): Promise<BackendScanJob> {
  const response = await fetch(`${API_BASE_URL}/api/v1/scan/${scanId}/status`, {
    cache: "no-store",
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(
      `Failed to fetch scan status (${response.status}): ${errorText}`,
    );
  }

  return (await response.json()) as BackendScanJob;
}

/**
 * Retrieve completed scan findings, triage records, and summary.
 */
export async function getBackendScanResults(
  scanId: string,
): Promise<BackendScanResult> {
  const response = await fetch(
    `${API_BASE_URL}/api/v1/scan/${scanId}/results`,
    {
      cache: "no-store",
    },
  );

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(
      `Failed to fetch scan results (${response.status}): ${errorText}`,
    );
  }

  return (await response.json()) as BackendScanResult;
}
