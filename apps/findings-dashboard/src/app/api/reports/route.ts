import type { NextRequest } from "next/server";

import {
  loadWorkspaceReport,
  loadWorkspaceReportIndex,
} from "@/lib/report-loader";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const reportPath = request.nextUrl.searchParams.get("path");

  try {
    if (reportPath) {
      const report = await loadWorkspaceReport(reportPath);

      if (!report) {
        return Response.json({ error: "Report not found." }, { status: 404 });
      }

      return Response.json({ report });
    }

    const reports = await loadWorkspaceReportIndex();
    return Response.json({ reports });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Unable to load reports.";

    return Response.json({ error: message }, { status: 500 });
  }
}
