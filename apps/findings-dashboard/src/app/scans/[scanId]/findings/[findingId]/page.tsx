"use client";

import { useEffect, useMemo, useState } from "react";
import { useParams, useRouter, useSearchParams } from "next/navigation";
import { ArrowLeft, Loader2 } from "lucide-react";

import { FindingDetail } from "@/components/finding-detail";
import { Button } from "@/components/ui/button";
import { getBackendScanResults } from "@/lib/aegis-api";
import { normalizeBackendScanResult } from "@/lib/report-adapter";
import type { NormalizedFinding } from "@/lib/report-types";

function asRouteValue(value: string | string[] | undefined): string {
  return Array.isArray(value) ? value[0] ?? "" : value ?? "";
}

export default function VulnerabilityInvestigationRoute() {
  const params = useParams<{ scanId: string; findingId: string }>();
  const router = useRouter();
  const searchParams = useSearchParams();
  const scanId = asRouteValue(params.scanId);
  const findingId = decodeURIComponent(asRouteValue(params.findingId));
  const returnHref =
    searchParams.get("return") ||
    `/scans/${encodeURIComponent(scanId)}/findings`;
  const [finding, setFinding] = useState<NormalizedFinding | null>(null);
  const [totalFindings, setTotalFindings] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const routeError =
    !scanId || !findingId
      ? "The scan or finding identifier is missing."
      : null;

  useEffect(() => {
    let cancelled = false;

    if (routeError) {
      return () => {
        cancelled = true;
      };
    }

    void getBackendScanResults(scanId)
      .then((result) => {
        if (cancelled) {
          return;
        }

        const report = normalizeBackendScanResult(result);
        const selected =
          report.findings.find(
            (candidate) =>
              candidate.key === findingId ||
              candidate.id === findingId,
          ) ?? null;
        setTotalFindings(report.findings.length);
        if (!selected) {
          setError(`Finding "${findingId}" was not found in scan ${scanId}.`);
          return;
        }
        setFinding(selected);
      })
      .catch((cause: unknown) => {
        if (!cancelled) {
          setError(cause instanceof Error ? cause.message : "Unable to load finding evidence.");
        }
      });

    return () => {
      cancelled = true;
    };
  }, [findingId, routeError, scanId]);

  const heading = useMemo(
    () => finding ? `${finding.cweId} - ${finding.family}` : "Vulnerability Investigation",
    [finding],
  );

  return (
    <main className="flex min-h-screen flex-col bg-background">
      <header className="flex flex-wrap items-center gap-3 border-b border-border bg-surface px-5 py-3">
        <Button
          variant="outline"
          size="sm"
          className="gap-2"
          onClick={() => router.push(returnHref)}
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Findings
        </Button>
        <span className="text-sm text-muted-foreground">AEGIS-SAST /</span>
        <h1 className="font-semibold">{heading}</h1>
        <span className="ml-auto max-w-full truncate font-mono text-xs text-muted-foreground">
          Scan {scanId}
        </span>
      </header>

      {routeError || error ? (
        <section className="m-auto max-w-xl rounded-lg border border-destructive/40 bg-surface p-6 text-center">
          <h2 className="font-semibold">Unable to load vulnerability evidence</h2>
          <p className="mt-2 text-sm text-muted-foreground">{routeError || error}</p>
          <Button className="mt-4" onClick={() => router.push(returnHref)}>
            Return to Findings
          </Button>
        </section>
      ) : finding ? (
        <div className="min-h-0 flex-1 overflow-hidden">
          <FindingDetail
            finding={finding}
            initialTab="taint"
            currentIndex={1}
            totalCount={totalFindings}
            onExpand={() => undefined}
          />
        </div>
      ) : (
        <div className="m-auto flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading verified source-to-sink evidence...
        </div>
      )}
    </main>
  );
}
