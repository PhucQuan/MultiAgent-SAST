"use client";
import { useState, type ReactNode } from "react";

export function ReviewWorkspace({ explorer, findings, details }: { explorer: ReactNode; findings: ReactNode; details: (expand:()=>void)=>ReactNode }) {
  const [left, setLeft] = useState(true);
  const [right, setRight] = useState(true);
  const [full, setFull] = useState(false);
  const [tab, setTab] = useState("findings");
  const [sizes, setSizes] = useState(() => {
    try { const saved = JSON.parse(localStorage.getItem("aegis-panel-sizes") || "[250,480]"); return Array.isArray(saved) && saved.length === 2 && saved.every(v=>typeof v === "number" && Number.isFinite(v)) ? [Math.max(200,Math.min(420,saved[0])),Math.max(320,Math.min(680,saved[1]))] : [250,480]; } catch { return [250,480]; }
  });
  function resize(index: number, delta: number) {
    setSizes(previous => { const next = [...previous]; next[index] = Math.max(index ? 320 : 200, Math.min(index ? 680 : 420, next[index] + delta)); localStorage.setItem("aegis-panel-sizes", JSON.stringify(next)); return next; });
  }
  function splitter(index: number) { return <div role="separator" aria-label={index ? "Resize details" : "Resize explorer"} aria-orientation="vertical" tabIndex={0} className="hidden xl:block w-2 shrink-0 cursor-col-resize bg-border hover:bg-primary" onKeyDown={e => { if (e.key === "ArrowLeft" || e.key === "ArrowRight") resize(index, (e.key === "ArrowRight" ? 20 : -20) * (index ? -1 : 1)); }} onPointerDown={e => { e.currentTarget.setPointerCapture(e.pointerId); }} onPointerMove={e => { if(e.currentTarget.hasPointerCapture(e.pointerId)) resize(index, e.movementX * (index ? -1 : 1)); }} onPointerUp={e => e.currentTarget.releasePointerCapture(e.pointerId)} />; }
  return <div className="flex flex-1 min-h-0 flex-col overflow-hidden">
    <div className="flex flex-wrap gap-3 border-b p-2 text-xs">
      <button onClick={() => {setFull(false);setLeft(!left);setTab("explorer");}}>Explorer {left ? "−" : "+"}</button>
      <button onClick={() => {setFull(false);setTab("findings");}}>Findings</button>
      <button onClick={() => {setRight(!right);setTab("details");}}>Details {right ? "−" : "+"}</button>
      <button onClick={() => {setFull(!full);setRight(true);setTab("details");}}>{full ? "Restore panels" : "Expand details"}</button>
    </div>
    <div className="flex flex-1 min-h-0 overflow-hidden">
      {!full && <aside style={{width:sizes[0]}} className={`${tab === "explorer" ? "flex" : "hidden"} ${left ? "xl:flex" : "xl:hidden"} xl:max-w-[30%] shrink-0 min-h-0 overflow-auto flex-col`}>{explorer}</aside>}
      {!full && left && splitter(0)}
      {!full && <div className={`${tab === "findings" ? "flex" : "hidden"} xl:flex flex-1 min-w-0 overflow-auto flex-col`}>{findings}</div>}
      {!full && right && splitter(1)}
      <div style={{width:full ? "100%" : sizes[1]}} className={`${tab === "details" ? "flex" : "hidden"} ${right ? "xl:flex" : "xl:hidden"} ${full ? "max-w-full" : "max-w-full xl:max-w-[45%]"} min-w-0 shrink-0 overflow-auto flex-col`}>{details(()=>{setFull(true);setRight(true);setTab("details");})}</div>
    </div>
  </div>;
}
