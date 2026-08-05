import type { NextRequest } from "next/server";

import {
  loadWorkspaceReport,
  loadWorkspaceReportIndex,
} from "@/lib/report-loader";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const reportPath = request.nextUrl.searchParams.get("path");
  const includeArchive =
    request.nextUrl.searchParams.get("includeArchive") === "1";

  try {
    if (reportPath) {
      const report = await loadWorkspaceReport(reportPath);

      if (!report) {
        return Response.json({ error: "Report not found." }, { status: 404 });
      }

      return Response.json({ report });
    }

    const index = await loadWorkspaceReportIndex({ includeArchive });
    return Response.json(index);
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Unable to load reports.";

    return Response.json({ error: message }, { status: 500 });
  }
}
