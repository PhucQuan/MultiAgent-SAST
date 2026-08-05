import "server-only";

import { promises as fs } from "node:fs";
import path from "node:path";

import { normalizeReport, summarizeReport } from "@/lib/report-adapter";
import type { NormalizedReport, ReportSummaryCard } from "@/lib/report-types";

const REPO_ROOT = path.resolve(process.cwd(), "..", "..");
const REPORTS_ROOT = path.join(REPO_ROOT, "reports");
const RECENT_REPORT_LIMIT = 12;

export interface WorkspaceReportIndexMeta {
  totalReports: number;
  activeReports: number;
  archiveReports: number;
  includeArchive: boolean;
  recentLimit: number;
}

export interface WorkspaceReportIndex {
  reports: ReportSummaryCard[];
  meta: WorkspaceReportIndexMeta;
}

function toPosixPath(filePath: string): string {
  return filePath.split(path.sep).join("/");
}

function ensureReportPath(relativeSourcePath: string): string {
  const sanitized = relativeSourcePath.replace(/\\/g, "/").replace(/^\/+/, "");
  const resolved = path.resolve(REPORTS_ROOT, sanitized);
  const relative = path.relative(REPORTS_ROOT, resolved);

  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("Invalid report path.");
  }

  return resolved;
}

async function walkReportFiles(currentDirectory: string): Promise<string[]> {
  const entries = await fs.readdir(currentDirectory, { withFileTypes: true });
  const files: string[] = [];

  for (const entry of entries) {
    const fullPath = path.join(currentDirectory, entry.name);

    if (entry.isDirectory()) {
      files.push(...(await walkReportFiles(fullPath)));
      continue;
    }

    if (entry.isFile() && entry.name.toLowerCase().endsWith(".json")) {
      files.push(fullPath);
    }
  }

  return files;
}

async function readJson(filePath: string): Promise<unknown | null> {
  try {
    const content = await fs.readFile(filePath, "utf8");
    return JSON.parse(content) as unknown;
  } catch {
    return null;
  }
}

function sortReports<T extends { timestamp: string | null; totalFindings: number; sourcePath: string }>(
  reports: T[],
): T[] {
  return reports.sort((left, right) => {
    const leftTime = left.timestamp ? Date.parse(left.timestamp) : 0;
    const rightTime = right.timestamp ? Date.parse(right.timestamp) : 0;

    if (leftTime !== rightTime) {
      return rightTime - leftTime;
    }

    if (left.totalFindings !== right.totalFindings) {
      return right.totalFindings - left.totalFindings;
    }

    return left.sourcePath.localeCompare(right.sourcePath);
  });
}

function isActiveWorkspaceReport(sourcePath: string): boolean {
  return sourcePath.toLowerCase().startsWith("dashboard_runs/");
}

function selectVisibleReports(
  reports: ReportSummaryCard[],
  includeArchive: boolean,
): ReportSummaryCard[] {
  if (includeArchive) {
    return reports;
  }

  const activeReports = reports.filter((report) =>
    isActiveWorkspaceReport(report.sourcePath),
  );
  const base = activeReports.length > 0 ? activeReports : reports;
  return base.slice(0, RECENT_REPORT_LIMIT);
}

export async function loadWorkspaceReportIndex(options?: {
  includeArchive?: boolean;
}): Promise<WorkspaceReportIndex> {
  const includeArchive = options?.includeArchive === true;
  const filePaths = await walkReportFiles(REPORTS_ROOT).catch(() => []);
  const reports: ReportSummaryCard[] = [];

  for (const filePath of filePaths) {
    const rawReport = await readJson(filePath);
    if (!rawReport) {
      continue;
    }

    const sourcePath = toPosixPath(path.relative(REPORTS_ROOT, filePath));
    const report = normalizeReport(rawReport, sourcePath);
    if (!report) {
      continue;
    }

    reports.push(summarizeReport(report));
  }

  const sortedReports = sortReports(reports);
  const activeReports = sortedReports.filter((report) =>
    isActiveWorkspaceReport(report.sourcePath),
  ).length;
  const visibleReports = selectVisibleReports(sortedReports, includeArchive);

  return {
    reports: visibleReports,
    meta: {
      totalReports: sortedReports.length,
      activeReports,
      archiveReports: Math.max(sortedReports.length - activeReports, 0),
      includeArchive,
      recentLimit: RECENT_REPORT_LIMIT,
    },
  };
}

export async function loadWorkspaceReport(
  relativeSourcePath: string,
): Promise<NormalizedReport | null> {
  const filePath = ensureReportPath(relativeSourcePath);
  const rawReport = await readJson(filePath);
  if (!rawReport) {
    return null;
  }

  const sourcePath = toPosixPath(path.relative(REPORTS_ROOT, filePath));
  return normalizeReport(rawReport, sourcePath);
}
