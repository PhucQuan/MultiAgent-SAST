"use client";

import { useState } from "react";
import { Bot, Check, Key, Save, Settings, ShieldCheck, Sliders, Sparkles } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";

export function SettingsPage() {
  const [maxDepth, setMaxDepth] = useState("5");
  const [enableAi, setEnableAi] = useState(true);
  const [aiModel, setAiModel] = useState("gemini-2.5-pro");
  const [confidenceThreshold, setConfidenceThreshold] = useState("0.85");
  const [crossFileTracking, setCrossFileTracking] = useState(true);

  const handleSave = () => {
    toast.success("Settings saved successfully");
  };

  return (
    <div className="flex flex-1 flex-col overflow-y-auto bg-slate-50/50 p-8 dark:bg-[#0b0f19]">
      <div className="mx-auto w-full max-w-[960px] space-y-7">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <Settings className="h-6 w-6 text-blue-600" />
              <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
                Scanner & AI Engine Settings
              </h1>
            </div>
            <p className="mt-1 text-[13.5px] text-slate-500">
              Tune static analysis precision, taint flow limits, and multi-agent AI verification parameters.
            </p>
          </div>

          <Button
            onClick={handleSave}
            className="h-9.5 gap-2 rounded-xl bg-blue-600 px-4 text-[13px] font-semibold text-white shadow-md shadow-blue-500/20 hover:bg-blue-700"
          >
            <Save className="h-4 w-4" />
            <span>Save Changes</span>
          </Button>
        </div>

        {/* 1. SAST Analysis Engine */}
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-xs dark:border-slate-800 dark:bg-slate-900 space-y-5">
          <div className="flex items-center gap-2 pb-3 border-b border-border">
            <Sliders className="h-4.5 w-4.5 text-blue-600" />
            <h2 className="font-bold text-[15px] text-slate-900 dark:text-slate-100">
              Static Analysis & Taint Flow Parameters
            </h2>
          </div>

          <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
            <div className="space-y-2">
              <label className="text-[12.5px] font-semibold text-slate-700 dark:text-slate-300">
                Max Call Graph Traversal Depth
              </label>
              <input
                type="number"
                min="1"
                max="20"
                value={maxDepth}
                onChange={(e) => setMaxDepth(e.target.value)}
                className="h-10 w-full rounded-xl border border-border bg-slate-50/80 px-3 font-mono text-[13px] text-slate-800 focus:outline-hidden dark:bg-slate-800 dark:text-slate-200"
              />
              <p className="text-[11.5px] text-slate-500">
                Depth limit for inter-procedural propagation along function calls.
              </p>
            </div>

            <div className="space-y-2">
              <label className="text-[12.5px] font-semibold text-slate-700 dark:text-slate-300">
                Python Cross-File Taint Tracking
              </label>
              <div className="flex items-center gap-3 pt-2">
                <input
                  type="checkbox"
                  id="crossFile"
                  checked={crossFileTracking}
                  onChange={(e) => setCrossFileTracking(e.target.checked)}
                  className="h-4 w-4 rounded border-border text-blue-600 focus:ring-blue-500"
                />
                <label htmlFor="crossFile" className="text-[13px] text-slate-700 dark:text-slate-300">
                  Enable module import graph resolution
                </label>
              </div>
              <p className="text-[11.5px] text-slate-500">
                Tracks data flowing across module boundaries (e.g. storage.py → views.py).
              </p>
            </div>
          </div>
        </div>

        {/* 2. AI Multi-Agent Verification */}
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-xs dark:border-slate-800 dark:bg-slate-900 space-y-5">
          <div className="flex items-center gap-2 pb-3 border-b border-border">
            <Bot className="h-4.5 w-4.5 text-indigo-600" />
            <h2 className="font-bold text-[15px] text-slate-900 dark:text-slate-100">
              AI Multi-Agent Verification Engine
            </h2>
          </div>

          <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
            <div className="space-y-2">
              <label className="text-[12.5px] font-semibold text-slate-700 dark:text-slate-300">
                Primary Agent Model
              </label>
              <select
                value={aiModel}
                onChange={(e) => setAiModel(e.target.value)}
                className="h-10 w-full rounded-xl border border-border bg-slate-50/80 px-3 text-[13px] text-slate-800 focus:outline-hidden dark:bg-slate-800 dark:text-slate-200"
              >
                <option value="gemini-2.5-pro">Gemini 2.5 Pro (Recommended)</option>
                <option value="gemini-2.5-flash">Gemini 2.5 Flash (Fast)</option>
                <option value="claude-3-7-sonnet">Claude 3.7 Sonnet</option>
                <option value="gpt-4o">GPT-4o</option>
              </select>
              <p className="text-[11.5px] text-slate-500">
                Used for Auditor exploit validation and Skeptic false-positive reduction.
              </p>
            </div>

            <div className="space-y-2">
              <label className="text-[12.5px] font-semibold text-slate-700 dark:text-slate-300">
                Confidence Auto-Triage Threshold ({confidenceThreshold})
              </label>
              <input
                type="range"
                min="0.5"
                max="0.99"
                step="0.05"
                value={confidenceThreshold}
                onChange={(e) => setConfidenceThreshold(e.target.value)}
                className="w-full accent-blue-600 pt-2"
              />
              <div className="flex justify-between text-[11px] text-slate-400">
                <span>0.50 (Permissive)</span>
                <span>0.85 (Balanced)</span>
                <span>0.99 (Strict)</span>
              </div>
            </div>
          </div>

          {/* API Key Status */}
          <div className="rounded-xl border border-border bg-slate-50/60 p-4 dark:bg-slate-950/40 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Key className="h-5 w-5 text-amber-500" />
              <div>
                <div className="text-[13px] font-semibold text-slate-800 dark:text-slate-200">
                  Google Gemini API Key
                </div>
                <div className="text-[11.5px] text-slate-500">
                  Configured via environment variable <code className="font-mono text-blue-600 dark:text-blue-400">GEMINI_API_KEY</code>
                </div>
              </div>
            </div>

            <span className="rounded-full bg-emerald-50 px-3 py-1 text-[11px] font-bold text-emerald-700 dark:bg-emerald-950 dark:text-emerald-400">
              Active & Valid
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
