"use client";

import { CheckCircle2, ExternalLink, GitBranch, Layers, Plus, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";

export function IntegrationsPage() {
  const integrations = [
    {
      id: "github",
      name: "GitHub Actions & Code Scanning",
      description: "Automate AST taint scans on Pull Requests and upload SARIF reports to GitHub Security Advisories.",
      status: "Connected",
      badgeColor: "bg-emerald-50 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-400",
    },
    {
      id: "gitlab",
      name: "GitLab CI/CD",
      description: "Run Aegis-SAST as a security analyzer step in .gitlab-ci.yml pipeline.",
      status: "Available",
      badgeColor: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
    },
    {
      id: "jira",
      name: "Jira Issue Tracker",
      description: "Automatically create security tickets for verified Critical and High vulnerability exploits.",
      status: "Available",
      badgeColor: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
    },
    {
      id: "slack",
      name: "Slack Security Alerts",
      description: "Send instant notifications to the security operations channel when new actionable findings are flagged.",
      status: "Connected",
      badgeColor: "bg-emerald-50 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-400",
    },
    {
      id: "defectdojo",
      name: "DefectDojo Vulnerability Management",
      description: "Synchronize triage dispositions and suppressed false positive records into centralized AppSec portal.",
      status: "Available",
      badgeColor: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
    },
  ];

  return (
    <div className="flex flex-1 flex-col overflow-y-auto bg-slate-50/50 p-8 dark:bg-[#0b0f19]">
      <div className="mx-auto w-full max-w-[1200px] space-y-7">
        <div>
          <div className="flex items-center gap-2">
            <Layers className="h-6 w-6 text-blue-600" />
            <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
              CI/CD & DevOps Integrations
            </h1>
          </div>
          <p className="mt-1 text-[13.5px] text-slate-500">
            Connect Aegis-SAST to your version control, CI/CD runners, alert webhooks, and issue tracking platforms.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {integrations.map((item) => (
            <div
              key={item.id}
              className="rounded-2xl border border-slate-200 bg-white p-6 shadow-xs flex flex-col justify-between dark:border-slate-800 dark:bg-slate-900"
            >
              <div>
                <div className="flex items-center justify-between pb-3">
                  <h3 className="font-bold text-[15px] text-slate-900 dark:text-slate-100">
                    {item.name}
                  </h3>
                  <span className={`rounded-full px-2.5 py-0.5 text-[11px] font-semibold ${item.badgeColor}`}>
                    {item.status}
                  </span>
                </div>
                <p className="text-[12.5px] leading-relaxed text-slate-600 dark:text-slate-400">
                  {item.description}
                </p>
              </div>

              <div className="mt-6 flex items-center justify-between pt-4 border-t border-border">
                <span className="text-[11.5px] text-slate-400">v1.2 Protocol</span>
                <Button
                  size="sm"
                  variant="outline"
                  disabled
                  title="Feature in preview"
                  className="h-8 rounded-lg text-[12px]"
                >
                  Preview
                </Button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
