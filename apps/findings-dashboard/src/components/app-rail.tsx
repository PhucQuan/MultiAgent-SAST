"use client";

import { useState } from "react";
import {
  AlertTriangle,
  Bot,
  ChevronLeft,
  ChevronRight,
  Code2,
  FileText,
  HelpCircle,
  LayoutDashboard,
  Layers,
  MessageSquare,
  Settings,
  Shield,
  ShieldCheck,
} from "lucide-react";

interface AppRailProps {
  activeTab?: string;
  onTabChange?: (tab: string) => void;
  findingsCount?: number;
  activeProjectName?: string;
  lastScanDuration?: string;
}

export function AppRail({
  activeTab = "scans",
  onTabChange,
  findingsCount = 30,
  activeProjectName = "vulnerable-python-suite",
  lastScanDuration = "4.2s",
}: AppRailProps) {
  const [collapsed, setCollapsed] = useState(false);

  const navItems = [
    { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
    { id: "scans", label: "Scans", icon: Shield, badge: "Live", badgeColor: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400" },
    {
      id: "vulnerabilities",
      label: "Vulnerabilities",
      icon: AlertTriangle,
      badge: String(findingsCount || 30),
      badgeColor: "bg-rose-500/15 text-rose-600 dark:text-rose-400 font-bold",
    },
    { id: "code", label: "Code Browser", icon: Code2 },
    { id: "ai", label: "AI Triage", icon: Bot },
    { id: "reports", label: "Reports", icon: FileText },
    { id: "integrations", label: "Integrations", icon: Layers },
    { id: "settings", label: "Settings", icon: Settings },
  ];

  return (
    <aside
      className={`relative flex flex-col justify-between border-r border-border bg-slate-50/90 transition-all duration-200 select-none dark:bg-[#0c121e] ${
        collapsed ? "w-[68px] px-2 py-4" : "w-[230px] px-3.5 py-4"
      }`}
    >
      {/* Collapse / Expand Toggle Button */}
      <button
        type="button"
        onClick={() => setCollapsed(!collapsed)}
        title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        className="absolute -right-3 top-6 z-20 flex h-6 w-6 items-center justify-center rounded-full border border-border bg-white text-slate-500 shadow-sm hover:bg-slate-100 hover:text-slate-800 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700"
      >
        {collapsed ? (
          <ChevronRight className="h-3.5 w-3.5" />
        ) : (
          <ChevronLeft className="h-3.5 w-3.5" />
        )}
      </button>

      {/* Top: Brand Logo & Title */}
      <div className="flex flex-col gap-5">
        <div
          onClick={() => onTabChange?.("dashboard")}
          className="flex cursor-pointer items-center gap-3 px-1 transition-opacity hover:opacity-90"
        >
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-blue-600 text-white shadow-md shadow-blue-500/25">
            <ShieldCheck className="h-5 w-5" />
          </div>
          {!collapsed && (
            <div className="flex flex-col overflow-hidden">
              <span className="truncate text-[14.5px] font-bold tracking-tight text-slate-900 dark:text-slate-100">
                Aegis-SAST
              </span>
              <span className="truncate text-[10.5px] font-medium text-slate-400">
                Code Security Workbench
              </span>
            </div>
          )}
        </div>

        {/* Navigation List */}
        <nav className="flex flex-col gap-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => onTabChange?.(item.id)}
                title={item.label}
                className={`group relative flex items-center gap-3 rounded-xl px-2.5 py-2 text-[12.5px] font-medium transition-all ${
                  isActive
                    ? "bg-blue-600/10 font-semibold text-blue-600 shadow-xs dark:bg-blue-500/15 dark:text-blue-400"
                    : "text-slate-600 hover:bg-slate-200/50 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800/60 dark:hover:text-slate-200"
                } ${collapsed ? "justify-center px-0 py-2.5" : "justify-start"}`}
              >
                <Icon
                  className={`h-4.5 w-4.5 shrink-0 transition-colors ${
                    isActive
                      ? "text-blue-600 dark:text-blue-400"
                      : "text-slate-500 group-hover:text-slate-800 dark:text-slate-400 dark:group-hover:text-slate-200"
                  }`}
                />

                {!collapsed && (
                  <>
                    <span className="truncate flex-1 text-left">{item.label}</span>
                    {item.badge && (
                      <span
                        className={`rounded-full px-2 py-0.5 text-[10.5px] ${item.badgeColor}`}
                      >
                        {item.badge}
                      </span>
                    )}
                  </>
                )}

                {isActive && (
                  <span className="absolute -left-3.5 top-2 h-5 w-1 rounded-r-full bg-blue-600 dark:bg-blue-500" />
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom: Project Status & Version Info */}
      <div className="flex flex-col gap-3 pt-3 border-t border-border/80">
        {!collapsed ? (
          <>
            {/* Scan Status Card */}
            <div className="rounded-xl border border-border/70 bg-white/60 p-2.5 text-[11px] shadow-2xs dark:bg-slate-900/40">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                Scan Status
              </div>
              <div className="mt-1 flex items-center gap-1.5 font-medium text-slate-800 dark:text-slate-200">
                <span className="h-2 w-2 rounded-full bg-emerald-500 shrink-0 animate-pulse" />
                <span className="truncate">Last scan completed</span>
              </div>
              <div className="mt-0.5 text-[10px] text-slate-400">
                {lastScanDuration} · {findingsCount} findings
              </div>
            </div>

            {/* Active Project Card */}
            <div className="rounded-xl border border-border/70 bg-white/60 p-2.5 text-[11px] shadow-2xs dark:bg-slate-900/40">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                Active Project
              </div>
              <div className="mt-1 flex items-center gap-1.5 font-medium text-slate-800 dark:text-slate-200">
                <span className="truncate font-mono text-[11px]">
                  {activeProjectName}
                </span>
              </div>
              <div className="mt-0.5 text-[10px] text-slate-400">Language from report</div>
            </div>

            {/* Footer Links & Badge */}
            <div className="flex items-center justify-between px-1 text-[11px] text-slate-400">
              <button
                type="button"
                onClick={() => onTabChange?.("settings")}
                className="hover:text-slate-700 dark:hover:text-slate-200"
              >
                Docs
              </button>
              <span>·</span>
              <button
                type="button"
                onClick={() => onTabChange?.("settings")}
                className="hover:text-slate-700 dark:hover:text-slate-200"
              >
                Support
              </button>
              <span>·</span>
              <span className="font-semibold text-slate-600 dark:text-slate-300">
                v0.1-beta
              </span>
            </div>
          </>
        ) : (
          <div className="flex flex-col items-center gap-2.5">
            <button
              type="button"
              title="Documentation & Settings"
              onClick={() => onTabChange?.("settings")}
              className="text-slate-400 hover:text-slate-700 dark:hover:text-slate-200"
            >
              <HelpCircle className="h-4 w-4" />
            </button>
            <div
              title="Aegis-SAST v0.1.0-beta"
              className="flex h-6 w-6 items-center justify-center rounded-lg bg-blue-50 text-[9.5px] font-bold text-blue-700 dark:bg-blue-950 dark:text-blue-300"
            >
              v0.1
            </div>
          </div>
        )}
      </div>
    </aside>
  );
}
