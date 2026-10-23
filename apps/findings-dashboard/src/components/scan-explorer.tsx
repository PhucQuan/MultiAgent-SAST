"use client";
import { useState } from "react";
import type { BackendScanJob } from "@/lib/aegis-api";
import type { NormalizedFinding } from "@/lib/report-types";
export function ScanExplorer({jobs, activeId, files, findings, selectedPath, onScan, onPath, error}: {jobs: BackendScanJob[];activeId:string|null;files:string[]|undefined;findings:NormalizedFinding[];selectedPath:string|null;onScan:(job:BackendScanJob)=>void;onPath:(path:string|null)=>void;error:string|null}) {
 const [query,setQuery]=useState("");
 const normalize=(p:string)=>p.replaceAll("\\","/");
 const counts=(p:string)=>findings.filter(f=>normalize(f.filePath)===p || normalize(f.filePath).startsWith(p+"/")).length;
 const job=jobs.find(j=>j.scan_id===activeId);
 const target=normalize(job?.target_path || job?.result?.summary.target || "");
 const root=job?.target_type === "file" ? target.slice(0,target.lastIndexOf("/")+1) : target.replace(/\/$/, "")+"/";
 const paths=(files || []).map(normalize).filter(p=>p.toLowerCase().includes(query.toLowerCase()));
 function tree(paths:string[], prefix=""): React.ReactNode {
  const groups=new Map<string,string[]>();
  for(const path of paths){const part=path.slice(prefix.length).split("/")[0];const key=prefix+part;groups.set(key,[...(groups.get(key)||[]),path]);}
  return [...groups].sort(([a],[b])=>a.localeCompare(b)).map(([path,children])=>children.length===1 && children[0]===path ? <div key={path} className="flex min-w-0 items-center"><button title={path} aria-pressed={selectedPath===path} className={`min-w-0 flex-1 break-all text-left p-1 ${selectedPath===path ? "bg-primary/20" : ""}`} onClick={()=>onPath(path)}>{path.slice(prefix.length)} <span className="text-muted-foreground">{counts(path)}</span></button><button title="Copy full path" onClick={()=>void navigator.clipboard.writeText(path)}>⧉</button></div> : <details key={path} open={query ? true : undefined} className="pl-2"><summary title={path}><button className={selectedPath===path ? "bg-primary/20" : ""} onClick={()=>onPath(path)}>{path.slice(prefix.length)||"/"} ({counts(path)})</button></summary>{tree(children,path+"/")}</details>);
 }
 return <div className="w-full min-w-0 p-3 space-y-4 text-xs">
  <h2 className="font-bold">Scan History</h2>{error && <p role="alert">{error}</p>}{!jobs.length && <p>No saved scans.</p>}
  <div className="max-h-72 overflow-auto space-y-2">{jobs.map(job=><button key={job.scan_id} onClick={()=>onScan(job)} className={`w-full rounded border p-2 text-left break-all ${activeId===job.scan_id ? "border-primary bg-primary/10" : ""}`}><strong>{job.target_path || job.result?.summary.target || "Legacy scan"}</strong><div>{job.target_type || "Unknown target type"} · {job.status}</div><div>{new Date(job.started_at).toLocaleString()}</div><div>{job.config?.scan_engine || "Unknown engine"} · {job.config?.rule_profile || "Unknown profile"}</div><div>{job.result?.summary.files_scanned ?? "—"} files · {job.result?.summary.total_vulnerabilities ?? "—"} findings</div><div>{job.result?.finding_counts?.actionable ?? "Unavailable"} actionable / {job.result?.finding_counts?.suppressed ?? "Unavailable"} suppressed</div><small>{job.scan_id}</small>{job.error && <div>{job.error}</div>}</button>)}</div>
  <h2 className="font-bold">Scanned files</h2><input aria-label="Search scanned files" placeholder="Search filename or path" value={query} onChange={e=>setQuery(e.target.value)} className="w-full border rounded p-2"/><button onClick={()=>onPath(null)}>Clear file filter</button>
  {files===undefined ? <p>Manifest unavailable for this scan. Run a new scan to record its inventory.</p> : paths.length ? <div><div title={target} className="break-all font-semibold">{target.split("/").pop()}</div>{tree(paths, paths.every(p=>p.startsWith(root)) ? root : "")}</div> : <p>No scanned files match.</p>}
  <p className="text-muted-foreground">Counts use primary finding locations. Trace-only references do not add findings to a file.</p>
 </div>;
}
