import type { InvestigationGraph } from "./report-types";

/** Do not draw fabricated connections when an imported graph has broken references. */
export function readInvestigationGraph(value: unknown): InvestigationGraph | null {
  if (!value || typeof value !== "object") return null;
  const graph = value as InvestigationGraph;
  if (graph.schema_version !== "1.0" || !Array.isArray(graph.nodes) || !Array.isArray(graph.edges) || !Array.isArray(graph.paths)) return null;
  if (!["verified_path", "partial_path", "sink_only", "pattern_only", "no_evidence"].includes(graph.evidence_mode)) return null;
  const nodes = new Set(graph.nodes.map(node => node.id));
  if (nodes.size !== graph.nodes.length || graph.nodes.some(node => typeof node.id !== "string" || typeof node.file !== "string" || typeof node.snippet !== "string" || typeof node.kind !== "string" || typeof node.label !== "string" || !Number.isInteger(node.line))) return null;
  const edges = new Map(graph.edges.map(edge => [edge.id, edge]));
  if (edges.size !== graph.edges.length || graph.edges.some(edge => !nodes.has(edge.source) || !nodes.has(edge.target) || !["data", "control"].includes(edge.kind))) return null;
  for (const path of graph.paths) {
    if (!Array.isArray(path.node_ids) || !Array.isArray(path.edge_ids) || !Array.isArray(path.control_node_ids) || !Array.isArray(path.control_edge_ids) || !Array.isArray(path.analysis_limitations) || !Array.isArray(path.sanitizers)) return null;
    if (path.node_ids[0] !== path.source || path.node_ids.at(-1) !== path.sink || path.edge_ids.length !== path.node_ids.length - 1) return null;
    if ([...path.node_ids, ...path.control_node_ids, ...path.sanitizers].some(id => !nodes.has(id))) return null;
    if (path.control_edge_ids.some(id => edges.get(id)?.kind !== "control")) return null;
    if (path.edge_ids.some((id, index) => {
      const edge = edges.get(id);
      return !edge || edge.kind !== "data" || edge.source !== path.node_ids[index] || edge.target !== path.node_ids[index + 1] || (path.verified && !edge.verified);
    })) return null;
  }
  if (![graph.sources, graph.sinks, graph.sanitizers, graph.analysis_limitations].every(Array.isArray)) return null;
  if ([...graph.sources, ...graph.sinks, ...graph.sanitizers].some(id => !nodes.has(id))) return null;
  return graph;
}
