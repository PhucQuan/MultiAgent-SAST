import { spawn } from "node:child_process";
import path from "node:path";

import type { NextRequest } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 3600;

const REPO_ROOT = path.resolve(/* turbopackIgnore: true */ process.cwd(), "..", "..");
const BRIDGE_SCRIPT = path.join(REPO_ROOT, "scripts", "run_scan_pipeline_json.py");
const PYTHON_BIN = process.env.AEGIS_PYTHON ?? "python";
const DEFAULT_BRIDGE_TIMEOUT_MS = 60 * 60 * 1000;
const DEFAULT_PROGRESS_EVERY = 100;
const MAX_JOB_LOG_LINES = 160;
const JOB_RETENTION_MS = 12 * 60 * 60 * 1000;

const configuredTimeout = Number(process.env.AEGIS_SCAN_TIMEOUT_MS);
const configuredProgressEvery = Number(process.env.AEGIS_SCAN_PROGRESS_EVERY);
const BRIDGE_TIMEOUT_MS =
  Number.isFinite(configuredTimeout) && configuredTimeout > 0
    ? configuredTimeout
    : DEFAULT_BRIDGE_TIMEOUT_MS;
const BRIDGE_PROGRESS_EVERY =
  Number.isFinite(configuredProgressEvery) && configuredProgressEvery > 0
    ? Math.max(1, Math.trunc(configuredProgressEvery))
    : DEFAULT_PROGRESS_EVERY;

type ScanBridgePayload = {
  targetPath: string;
  enableAi?: boolean;
  maxDepth?: number;
};

type ScanApiPayload = {
  targetPath?: string;
  enableAi?: boolean;
  maxDepth?: number;
};

type ScanResultPayload = {
  selectedReportPath?: string | null;
  summary?: {
    files_scanned?: number;
    total_vulnerabilities?: number;
  };
  ai?: {
    requested?: boolean;
    enabled?: boolean;
    error?: string | null;
  };
  reports?: Record<
    string,
    {
      path: string;
      sourcePath: string | null;
    }
  >;
  request?: Record<string, unknown>;
  repoProfile?: Record<string, unknown>;
  workflowSummary?: Record<string, unknown>;
  supportedLanguages?: string[];
  importFailures?: Record<string, string>;
  exitCode?: number;
};

type ProgressPayload = {
  event?: string;
  stage?: string;
  message?: string;
  total_files?: number;
  files_scanned?: number;
  files_processed?: number;
  findings?: number;
  errors?: number;
  current_file?: string;
  indexed_functions?: number;
  duration_seconds?: number;
  scan_profile?: string;
  detected_languages?: string[];
  framework_hints?: string[];
  supported_file_count?: number;
  format?: string;
  path?: string;
};

type ScanJobStatus = "queued" | "running" | "completed" | "failed";

type ScanJobProgress = {
  stage: string | null;
  message: string | null;
  totalFiles: number | null;
  filesScanned: number | null;
  filesProcessed: number | null;
  findings: number | null;
  errors: number | null;
  currentFile: string | null;
  indexedFunctions: number | null;
  durationSeconds: number | null;
};

type ScanJobState = {
  id: string;
  status: ScanJobStatus;
  targetPath: string;
  enableAi: boolean;
  maxDepth: number;
  progressEvery: number;
  startedAt: string;
  updatedAt: string;
  finishedAt: string | null;
  progress: ScanJobProgress;
  logs: string[];
  result: ScanResultPayload | null;
  error: string | null;
};

const globalForScanJobs = globalThis as typeof globalThis & {
  __aegisScanJobs?: Map<string, ScanJobState>;
};

const scanJobs =
  globalForScanJobs.__aegisScanJobs ?? new Map<string, ScanJobState>();

if (!globalForScanJobs.__aegisScanJobs) {
  globalForScanJobs.__aegisScanJobs = scanJobs;
}

function emptyProgress(): ScanJobProgress {
  return {
    stage: null,
    message: null,
    totalFiles: null,
    filesScanned: null,
    filesProcessed: null,
    findings: null,
    errors: null,
    currentFile: null,
    indexedFunctions: null,
    durationSeconds: null,
  };
}

function touchJob(job: ScanJobState): void {
  job.updatedAt = new Date().toISOString();
}

function appendLog(job: ScanJobState, message: string): void {
  const trimmed = message.trim();
  if (!trimmed) {
    return;
  }

  const entry = `[${new Date().toLocaleTimeString("vi-VN", {
    hour12: false,
  })}] ${trimmed}`;

  if (job.logs.at(-1) === entry) {
    touchJob(job);
    return;
  }

  job.logs = [...job.logs, entry].slice(-MAX_JOB_LOG_LINES);
  touchJob(job);
}

function coerceNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function pruneOldJobs(): void {
  const now = Date.now();

  for (const [jobId, job] of scanJobs.entries()) {
    const updatedAt = Date.parse(job.updatedAt);
    if (Number.isNaN(updatedAt) || now - updatedAt <= JOB_RETENTION_MS) {
      continue;
    }

    scanJobs.delete(jobId);
  }
}

function describeProgressEvent(payload: ProgressPayload): string | null {
  const event = payload.event;

  if (event === "stage") {
    return payload.message ?? null;
  }

  if (event === "repo-profile") {
    const languages = payload.detected_languages?.join(", ") || "unknown";
    const supportedFiles =
      coerceNumber(payload.supported_file_count) ?? 0;
    return `Repo intake: ${payload.scan_profile ?? "scan-default"}, languages ${languages}, supported files ${supportedFiles}.`;
  }

  if (event === "index-start") {
    return `Building Python index for ${coerceNumber(payload.total_files) ?? 0} candidate files.`;
  }

  if (event === "index-complete") {
    return `Python index ready: ${coerceNumber(payload.indexed_functions) ?? 0} indexed functions.`;
  }

  if (event === "scan-start") {
    return `Scanning ${coerceNumber(payload.total_files) ?? 0} candidate files.`;
  }

  if (event === "progress") {
    const processed = coerceNumber(payload.files_processed) ?? 0;
    const total = coerceNumber(payload.total_files) ?? 0;
    const findings = coerceNumber(payload.findings) ?? 0;
    const errors = coerceNumber(payload.errors) ?? 0;
    const currentFile = payload.current_file
      ? ` (${path.basename(payload.current_file)})`
      : "";
    return `Processed ${processed}/${total} files, findings ${findings}, errors ${errors}${currentFile}.`;
  }

  if (event === "complete") {
    const durationSeconds = coerceNumber(payload.duration_seconds);
    return durationSeconds === null
      ? "Detector complete."
      : `Detector complete in ${durationSeconds.toFixed(1)}s.`;
  }

  if (event === "scan-summary") {
    return `Scan summary: ${coerceNumber(payload.files_scanned) ?? 0} files scanned, ${coerceNumber(payload.findings) ?? 0} findings.`;
  }

  if (event === "ai-unavailable") {
    return `AI unavailable: ${payload.message ?? "unknown reason"}`;
  }

  if (event === "report-exported") {
    return `Exported ${payload.format ?? "report"} artifact.`;
  }

  return null;
}

function applyProgressEvent(job: ScanJobState, payload: ProgressPayload): void {
  const nextStage =
    payload.stage ??
    (payload.event === "index-start" || payload.event === "index-complete"
      ? "indexing"
      : payload.event === "scan-start" ||
          payload.event === "progress" ||
          payload.event === "complete"
        ? "scanning"
        : payload.event === "repo-profile"
          ? "repo-intake"
          : null);

  if (nextStage) {
    job.progress.stage = nextStage;
  }

  if (typeof payload.message === "string" && payload.message.trim()) {
    job.progress.message = payload.message.trim();
  }

  const totalFiles = coerceNumber(payload.total_files);
  if (totalFiles !== null) {
    job.progress.totalFiles = totalFiles;
  }

  const filesScanned = coerceNumber(payload.files_scanned);
  if (filesScanned !== null) {
    job.progress.filesScanned = filesScanned;
  }

  const filesProcessed = coerceNumber(payload.files_processed);
  if (filesProcessed !== null) {
    job.progress.filesProcessed = filesProcessed;
  }

  const findings = coerceNumber(payload.findings);
  if (findings !== null) {
    job.progress.findings = findings;
  }

  const errors = coerceNumber(payload.errors);
  if (errors !== null) {
    job.progress.errors = errors;
  }

  const indexedFunctions = coerceNumber(payload.indexed_functions);
  if (indexedFunctions !== null) {
    job.progress.indexedFunctions = indexedFunctions;
  }

  const durationSeconds = coerceNumber(payload.duration_seconds);
  if (durationSeconds !== null) {
    job.progress.durationSeconds = durationSeconds;
  }

  if (typeof payload.current_file === "string" && payload.current_file.trim()) {
    job.progress.currentFile = payload.current_file;
  }

  const logLine = describeProgressEvent(payload);
  if (logLine) {
    appendLog(job, logLine);
  } else {
    touchJob(job);
  }
}

function completeJob(job: ScanJobState, result: ScanResultPayload): void {
  job.status = "completed";
  job.result = result;
  job.error = null;
  job.finishedAt = new Date().toISOString();
  job.progress.stage = "completed";
  job.progress.message = "Local scan completed.";

  const filesScanned = result.summary?.files_scanned ?? 0;
  const findings = result.summary?.total_vulnerabilities ?? 0;
  job.progress.filesScanned = filesScanned;
  job.progress.filesProcessed = job.progress.totalFiles ?? filesScanned;
  job.progress.findings = findings;

  appendLog(
    job,
    `Local scan complete: ${filesScanned} files scanned, ${findings} findings.`,
  );

  if (result.ai?.requested && !result.ai?.enabled && result.ai.error) {
    appendLog(job, `AI unavailable: ${result.ai.error}`);
  }
}

function failJob(job: ScanJobState, message: string): void {
  job.status = "failed";
  job.error = message;
  job.finishedAt = new Date().toISOString();
  job.progress.stage = "failed";
  job.progress.message = message;
  appendLog(job, `Scan failed: ${message}`);
}

function handleStdoutLine(job: ScanJobState, line: string): void {
  let parsed: unknown;

  try {
    parsed = JSON.parse(line) as unknown;
  } catch {
    appendLog(job, line);
    return;
  }

  if (typeof parsed !== "object" || parsed === null) {
    appendLog(job, line);
    return;
  }

  const record = parsed as Record<string, unknown>;
  const type = typeof record.type === "string" ? record.type : null;

  if (type === "progress") {
    const payload = record.payload;
    if (typeof payload === "object" && payload !== null) {
      applyProgressEvent(job, payload as ProgressPayload);
      return;
    }
  }

  if (type === "result") {
    if (record.ok === true && record.scan && typeof record.scan === "object") {
      completeJob(job, record.scan as ScanResultPayload);
      return;
    }

    failJob(
      job,
      typeof record.error === "string"
        ? record.error
        : "Local scan failed without a detailed error.",
    );
    return;
  }

  appendLog(job, line);
}

function attachLineReader(
  readable: NodeJS.ReadableStream,
  onLine: (line: string) => void,
): void {
  let buffer = "";

  readable.setEncoding("utf8");
  readable.on("data", (chunk: string) => {
    buffer += chunk;

    while (buffer.includes("\n")) {
      const newlineIndex = buffer.indexOf("\n");
      const line = buffer.slice(0, newlineIndex).trim();
      buffer = buffer.slice(newlineIndex + 1);

      if (line) {
        onLine(line);
      }
    }
  });

  readable.on("end", () => {
    const line = buffer.trim();
    if (line) {
      onLine(line);
    }
  });
}

function startScanJob(payload: ScanBridgePayload): ScanJobState {
  pruneOldJobs();

  const jobId = crypto.randomUUID();
  const now = new Date().toISOString();
  const job: ScanJobState = {
    id: jobId,
    status: "queued",
    targetPath: payload.targetPath,
    enableAi: Boolean(payload.enableAi),
    maxDepth: Math.max(1, Math.min(Number(payload.maxDepth ?? 5), 20)),
    progressEvery: BRIDGE_PROGRESS_EVERY,
    startedAt: now,
    updatedAt: now,
    finishedAt: null,
    progress: emptyProgress(),
    logs: [],
    result: null,
    error: null,
  };

  scanJobs.set(job.id, job);
  appendLog(job, `Queued local scan for ${payload.targetPath}.`);

  const child = spawn(
    PYTHON_BIN,
    [
      BRIDGE_SCRIPT,
      "--stdin",
      "--stream-progress",
      "--progress-every",
      String(BRIDGE_PROGRESS_EVERY),
    ],
    {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        PYTHONIOENCODING: "utf-8",
      },
      stdio: ["pipe", "pipe", "pipe"],
    },
  );

  job.status = "running";
  job.progress.stage = "queued";
  job.progress.message = "Launching Python scan pipeline.";
  appendLog(job, `Python scan process started (progress every ${BRIDGE_PROGRESS_EVERY} files).`);

  const timeout =
    BRIDGE_TIMEOUT_MS > 0
      ? setTimeout(() => {
          if (job.status === "completed" || job.status === "failed") {
            return;
          }

          child.kill();
          failJob(
            job,
            `Local scan timed out after ${Math.round(
              BRIDGE_TIMEOUT_MS / 60000,
            )} minute${BRIDGE_TIMEOUT_MS >= 120000 ? "s" : ""}. Increase AEGIS_SCAN_TIMEOUT_MS for very large repositories.`,
          );
        }, BRIDGE_TIMEOUT_MS)
      : null;

  attachLineReader(child.stdout, (line) => handleStdoutLine(job, line));
  attachLineReader(child.stderr, (line) => appendLog(job, line));

  child.on("error", (error) => {
    if (timeout) {
      clearTimeout(timeout);
    }

    if (job.status === "completed" || job.status === "failed") {
      return;
    }

    failJob(job, error.message);
  });

  child.on("close", (code) => {
    if (timeout) {
      clearTimeout(timeout);
    }

    if (job.status === "completed" || job.status === "failed") {
      return;
    }

    if (code === 0) {
      failJob(job, "Local scan exited without a final result payload.");
      return;
    }

    failJob(job, `Local scan bridge exited with code ${code ?? "unknown"}.`);
  });

  child.stdin.write(JSON.stringify(payload));
  child.stdin.end();

  return job;
}

export async function GET(request: NextRequest) {
  pruneOldJobs();

  const jobId = request.nextUrl.searchParams.get("jobId")?.trim();
  if (!jobId) {
    return Response.json({ error: "jobId is required." }, { status: 400 });
  }

  const job = scanJobs.get(jobId);
  if (!job) {
    return Response.json({ error: "Scan job not found." }, { status: 404 });
  }

  return Response.json({ job });
}

export async function POST(request: NextRequest) {
  let body: ScanApiPayload | null = null;

  try {
    body = (await request.json()) as ScanApiPayload;
  } catch {
    return Response.json({ error: "Invalid JSON request body." }, { status: 400 });
  }

  const targetPath = body?.targetPath?.trim();
  if (!targetPath) {
    return Response.json({ error: "targetPath is required." }, { status: 400 });
  }

  const maxDepth = Number.isFinite(Number(body?.maxDepth))
    ? Math.max(1, Math.min(Number(body?.maxDepth), 20))
    : 5;

  const job = startScanJob({
    targetPath,
    enableAi: Boolean(body?.enableAi),
    maxDepth,
  });

  return Response.json({ job }, { status: 202 });
}
