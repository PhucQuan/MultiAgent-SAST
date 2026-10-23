"use client";

import { useState } from "react";
import { Background, Controls, MiniMap, ReactFlow, MarkerType, Position, type Node, type Edge } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { InvestigationGraph, InvestigationPath, NormalizedFinding } from "@/lib/report-types";

const modeLabels = {
  verified_path: "Verified static source-to-sink evidence",
  partial_path: "Partial dependency evidence",
  sink_only: "Sink-only evidence",
  pattern_only: "Pattern-only evidence",
  no_evidence: "No usable evidence",
};
const colors: Record<string, string> = { source: "#0369a1", sink: "#be123c", sanitizer: "#047857", branch: "#a16207", pattern: "#475569" };
const basename = (path: string) => path.replaceAll("\\", "/").split("/").pop();

export function TaintInvestigation({ finding }: { finding: NormalizedFinding }) {
  const graph = finding.evidenceGraph;
  if (!graph) return <div className="rounded border p-4 space-y-3">
    <h3 className="font-semibold">Structured graph unavailable</h3>
    <p>{finding.evidenceDiagnostic || "This report predates structured path evidence. Run a new scan to collect it."}</p>
    <p>Matched function: {finding.sinkFunction || "Not available"}</p>
    {finding.sinkContext && <pre className="overflow-x-auto whitespace-pre">{finding.sinkContext.lines.join("\n")}</pre>}
  </div>;
  return <GraphWorkspace key={finding.key} graph={graph} finding={finding} />;
}

function GraphWorkspace({ graph, finding }: { graph: InvestigationGraph; finding: NormalizedFinding }) {
  const [pathId, setPathId] = useState(graph.paths[0]?.id ?? "");
  const [compareId, setCompareId] = useState("");
  const [selection, setSelection] = useState<{ kind: "node" | "edge"; id: string } | null>(null);
  const [showControl, setShowControl] = useState(false);
  const [onlyPath, setOnlyPath] = useState(graph.nodes.length > 250);
  const [collapsedFiles, setCollapsedFiles] = useState<string[]>([]);
  const active = graph.paths.find(path => path.id === pathId);
  const compared = graph.paths.find(path => path.id === compareId);
  const files = [...new Set(graph.nodes.map(node => node.file))].sort();
  const nodeMap = new Map(graph.nodes.map(node => [node.id, node]));
  const activeNodes = new Set(active ? [...active.node_ids, ...active.control_node_ids] : []);
  const activeEdges = new Set(active ? [...active.edge_ids, ...active.control_edge_ids] : []);
  const compareNodes = new Set(compared?.node_ids ?? []);

  const { nodes, edges } = (() => {
    const ranks = new Map<string, number>();
    for (const path of graph.paths) path.node_ids.forEach((id, index) => ranks.set(id, Math.max(ranks.get(id) ?? 0, index)));
    const counts = new Map<number, number>();
    const selectedNodes = new Set(active ? [...active.node_ids, ...active.control_node_ids] : []);
    const selectedEdges = new Set(active ? [...active.edge_ids, ...active.control_edge_ids] : []);
    const comparisonNodes = new Set(compared?.node_ids ?? []);
    const visible = graph.nodes.filter(node =>
      (showControl || node.kind !== "branch") &&
      (!onlyPath || !active || selectedNodes.has(node.id) || comparisonNodes.has(node.id)) &&
      (!collapsedFiles.includes(node.file) || ["source", "sink"].includes(node.kind)));
    const visibleIds = new Set(visible.map(node => node.id));
    const nodes: Node[] = visible.map(node => {
      const rank = ranks.get(node.id) ?? 0;
      const row = counts.get(rank) ?? 0;
      counts.set(rank, row + 1);
      return { id: node.id, position: { x: rank * 240, y: row * 115 },
        sourcePosition: Position.Right, targetPosition: Position.Left,
        data: { label: <div title={node.label}><strong>{node.label.length > 27 ? node.label.slice(0, 27) + "…" : node.label}</strong><div className="text-[10px] mt-1">{node.kind.replaceAll("_", " ")} · {basename(node.file)}:{node.line}</div></div> },
        style: { width: 205, background: colors[node.kind] ?? "#1e293b", color: "white", border: selectedNodes.has(node.id) ? "3px solid #38bdf8" : comparisonNodes.has(node.id) ? "3px solid #c084fc" : "1px solid #64748b", opacity: active && !selectedNodes.has(node.id) && !comparisonNodes.has(node.id) ? 0.5 : 1 },
      };
    });
    const edges: Edge[] = graph.edges.filter(edge => visibleIds.has(edge.source) && visibleIds.has(edge.target) && (showControl || edge.kind !== "control")).map(edge => ({
      id: edge.id, source: edge.source, target: edge.target, label: edge.relation.replaceAll("_", " "),
      markerEnd: { type: MarkerType.ArrowClosed }, interactionWidth: 24,
      style: { stroke: selectedEdges.has(edge.id) ? "#38bdf8" : "#94a3b8", strokeWidth: selectedEdges.has(edge.id) ? 3 : 1, strokeDasharray: edge.kind === "control" || !edge.verified ? "6 4" : undefined },
      labelStyle: { fill: "#0f172a", fontSize: 10 },
    }));
    return { nodes, edges };
  })();

  const selectedNode = selection?.kind === "node" ? nodeMap.get(selection.id) : undefined;
  const selectedEdge = selection?.kind === "edge" ? graph.edges.find(edge => edge.id === selection.id) : undefined;
  function orderedPath(path: InvestigationPath, title: string) {
    return <section className="min-w-0"><h4 className="font-semibold">{title}</h4><p className="text-xs">{path.trace_completeness} · {path.verified ? "Static relationships verified" : "Unresolved relationship present"}</p>
      <ol className="mt-2 space-y-2">{path.node_ids.map((id, index) => { const node = nodeMap.get(id)!; return <li key={`${id}-${index}`}><button className={`w-full rounded border p-2 text-left text-xs ${compared && compareNodes.has(id) && activeNodes.has(id) ? "border-purple-400" : "border-border"}`} onClick={() => setSelection({ kind: "node", id })}>
        <strong>{index + 1}. {node.label}</strong><div className="break-all">{node.file}:{node.line}:{node.column}</div>{node.kind === "sanitizer" && <span>Sanitizer call observed; effectiveness requires sink-specific review.</span>}
      </button></li>; })}</ol>
      {path.analysis_limitations.map(note => <p key={note} className="mt-2 text-xs text-amber-600">{note}</p>)}
    </section>;
  }

  return <div className="investigation-root space-y-4">
    <div className="rounded border p-3 space-y-2" data-testid="evidence-mode">
      <h3 className="font-semibold">{modeLabels[graph.evidence_mode]}</h3>
      <p className="text-xs">Sources: {graph.sources.length} · Sinks: {graph.sinks.length} · Verified static paths: {graph.paths.filter(path => path.verified).length} · Partial paths: {graph.paths.filter(path => !path.verified).length}</p>
      <p className="text-xs">A verified dependency is not proof of an exploitable vulnerability.</p>
      {graph.sink_missing_reason && <p className="text-xs">Sink unavailable: {graph.sink_missing_reason}</p>}
      {finding.status === "suppressed" && <div className="rounded border border-amber-500 p-2 text-xs"><strong>Suppressed — still inspectable</strong><p>{finding.explanation || "No suppression explanation was recorded."}</p><p>{finding.reasonCodes.join(" · ")}</p><p>Suppression is a triage decision, not proof of a false positive.</p></div>}
      {graph.truncated && <p role="status" className="text-amber-600">Analysis limits were reached. These paths are not exhaustive.</p>}
    </div>
    <div className="investigation-grid">
      <aside className="min-w-0 space-y-3 overflow-auto max-h-[650px] border rounded p-3">
        <h3 className="font-semibold">Paths</h3>
        {!graph.paths.length && <p className="text-xs">No source-to-sink path was established. Inspect the matched operation and rule explanation.</p>}
        {graph.paths.map((path, index) => <button key={path.id} data-testid="path-choice" aria-pressed={pathId === path.id} onClick={() => { setPathId(path.id); setSelection({ kind: "node", id: path.source }); }} className={`block w-full text-left rounded border p-2 text-xs ${pathId === path.id ? "border-sky-400 bg-sky-500/10" : ""}`}>
          <strong>Path {index + 1} · {path.trace_completeness}</strong><div>{nodeMap.get(path.source)?.label} → {nodeMap.get(path.sink)?.label}</div><div>{path.sanitizers.length} sanitizer calls</div><small title={path.id}>{path.id.slice(0, 10)}</small>
        </button>)}
        {graph.paths.length > 1 && <label className="block text-xs">Compare with<select aria-label="Compare path" className="w-full border rounded p-1 mt-1" value={compareId} onChange={event => setCompareId(event.target.value)}><option value="">None</option>{graph.paths.filter(path => path.id !== pathId).map(path => <option key={path.id} value={path.id}>Path {graph.paths.indexOf(path) + 1}</option>)}</select></label>}
        <details><summary className="cursor-pointer text-xs">File groups ({files.length})</summary>{files.map(file => <label key={file} className="block break-all text-xs mt-2"><input type="checkbox" checked={!collapsedFiles.includes(file)} onChange={() => setCollapsedFiles(previous => previous.includes(file) ? previous.filter(item => item !== file) : [...previous, file])} /> {file}</label>)}<p className="text-xs mt-2">Collapsed groups hide intermediate nodes and their edges; no replacement edges are invented.</p></details>
      </aside>
      <section className="min-w-0 space-y-2">
        <div className="flex flex-wrap gap-3 text-xs"><label><input type="checkbox" checked={onlyPath} onChange={event => setOnlyPath(event.target.checked)} /> Selected paths only</label><label><input type="checkbox" checked={showControl} onChange={event => setShowControl(event.target.checked)} /> Control conditions</label><span>{nodes.length} / {graph.nodes.length} nodes shown</span></div>
        <div className="h-[540px] min-w-0 border rounded bg-slate-950" data-testid="taint-graph">
          <ReactFlow key={`${onlyPath}-${showControl}-${collapsedFiles.join()}`} nodes={nodes} edges={edges} fitView minZoom={0.08} maxZoom={2} nodesDraggable={false} nodesConnectable={false} onlyRenderVisibleElements onNodeClick={(_, node) => setSelection({ kind: "node", id: node.id })} onEdgeClick={(_, edge) => setSelection({ kind: "edge", id: edge.id })} aria-label="Static taint evidence graph">
            <Background color="#334155" /><Controls showInteractive={false} /><MiniMap nodeColor={node => String(node.style?.background ?? "#64748b")} />
          </ReactFlow>
        </div>
        <p className="text-xs">Legend: blue source · red sink · green sanitizer · amber condition · solid data dependency · dashed control or unresolved relationship. Select an edge for its verification state.</p>
      </section>
      <aside className="min-w-0 border rounded p-3 space-y-3 max-h-[650px] overflow-auto" data-testid="evidence-inspector">
        <h3 className="font-semibold">Evidence Inspector</h3>
        {!selection && <p className="text-xs">Select a node, edge, or ordered path step to inspect exact evidence.</p>}
        {selectedNode && <><h4 className="font-semibold break-words">{selectedNode.label}</h4><p className="text-xs">{selectedNode.kind} · {selectedNode.origin}</p><p className="break-all text-xs">{selectedNode.file}:{selectedNode.line}:{selectedNode.column}</p><button className="text-xs underline" onClick={() => void navigator.clipboard.writeText(`${selectedNode.file}:${selectedNode.line}`)}>Copy location</button><button className="text-xs underline ml-3" onClick={() => void navigator.clipboard.writeText(selectedNode.snippet)}>Copy code</button>
          <div className="overflow-x-auto rounded bg-slate-950 p-2 text-slate-100"><pre className="text-xs">{selectedNode.snippet.split("\n").map((line, index) => <div key={index}><span className="text-slate-500 select-none mr-3">{selectedNode.line + index}</span>{line}</div>)}</pre></div>
          {selectedNode.kind === "sanitizer" && <p className="text-xs">This call was encountered on the selected dependency path. Its effectiveness is not assumed.</p>}
        </>}
        {selectedEdge && <><h4>{selectedEdge.relation.replaceAll("_", " ")}</h4><p className="text-xs">{selectedEdge.kind === "control" ? "Control-flow condition, not a data dependency" : "Data dependency"} · {selectedEdge.verified ? "Verified static relationship" : "Unresolved relationship"}</p>{[selectedEdge.source, selectedEdge.target].map(id => <button key={id} className="block text-left text-xs underline break-all" onClick={() => setSelection({ kind: "node", id })}>{nodeMap.get(id)?.file}:{nodeMap.get(id)?.line} — {nodeMap.get(id)?.label}</button>)}</>}
        {!graph.paths.length && graph.nodes.map(node => <button key={node.id} className="block text-left text-xs border rounded p-2" onClick={() => setSelection({ kind: "node", id: node.id })}>Inspect {node.label} at line {node.line}</button>)}
      </aside>
    </div>
    {active && <div className={`grid gap-4 ${compared ? "md:grid-cols-2" : ""}`} data-testid="ordered-path">{orderedPath(active, "Selected path")}{compared && orderedPath(compared, "Comparison path — shared nodes outlined in purple")}</div>}
    <details className="rounded border p-3 text-xs"><summary className="cursor-pointer font-semibold">Analysis limitations ({graph.analysis_limitations.length})</summary><ul className="list-disc pl-4 mt-2 space-y-1">{graph.analysis_limitations.map(note => <li key={note}>{note}</li>)}</ul></details>
    <span className="sr-only">{activeEdges.size} selected path edges</span>
  </div>;
}
