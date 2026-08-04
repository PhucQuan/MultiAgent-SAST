import { spawn } from "node:child_process";
import path from "node:path";

import type { NextRequest } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const REPO_ROOT = path.resolve(/* turbopackIgnore: true */ process.cwd(), "..", "..");
const BRIDGE_SCRIPT = path.join(REPO_ROOT, "scripts", "run_scan_pipeline_json.py");
const PYTHON_BIN = process.env.AEGIS_PYTHON ?? "python";
const BRIDGE_TIMEOUT_MS = 10 * 60 * 1000;

type ScanBridgePayload = {
  targetPath: string;
  enableAi?: boolean;
  maxDepth?: number;
};

type ScanBridgeResponse = {
  ok?: boolean;
  error?: string;
  scan?: {
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
  };
};

function runBridge(payload: ScanBridgePayload): Promise<ScanBridgeResponse> {
  return new Promise((resolve, reject) => {
    const child = spawn(PYTHON_BIN, [BRIDGE_SCRIPT, "--stdin"], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        PYTHONIOENCODING: "utf-8",
      },
      stdio: ["pipe", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let settled = false;

    const timeout = setTimeout(() => {
      if (settled) {
        return;
      }

      settled = true;
      child.kill();
      reject(new Error("Local scan timed out after 10 minutes."));
    }, BRIDGE_TIMEOUT_MS);

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });

    child.on("error", (error) => {
      if (settled) {
        return;
      }

      settled = true;
      clearTimeout(timeout);
      reject(error);
    });

    child.on("close", (code) => {
      if (settled) {
        return;
      }

      settled = true;
      clearTimeout(timeout);

      const rawOutput = stdout.trim() || stderr.trim();
      let parsed: ScanBridgeResponse | null = null;

      if (rawOutput) {
        try {
          parsed = JSON.parse(rawOutput) as ScanBridgeResponse;
        } catch {
          parsed = null;
        }
      }

      if (code === 0 && parsed?.ok && parsed.scan) {
        resolve(parsed);
        return;
      }

      reject(
        new Error(
          parsed?.error ||
            stderr.trim() ||
            stdout.trim() ||
            "Local scan bridge failed.",
        ),
      );
    });

    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
  });
}

export async function POST(request: NextRequest) {
  let body: ScanBridgePayload | null = null;

  try {
    body = (await request.json()) as ScanBridgePayload;
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

  try {
    const result = await runBridge({
      targetPath,
      enableAi: Boolean(body?.enableAi),
      maxDepth,
    });

    return Response.json({ scan: result.scan });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Unable to run a local scan.";

    return Response.json({ error: message }, { status: 500 });
  }
}
