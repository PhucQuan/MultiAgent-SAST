"""Bounded, context-sensitive Python provenance for investigation evidence.

This is static dependency evidence, not an exploit or branch-feasibility proof.
Paths are retained during interpretation; they are never reconstructed by sorting
locations or by walking a union of unrelated call contexts.
"""
from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


SINKS = {
    "os.system": "COMMAND_INJECTION", "os.popen": "COMMAND_INJECTION",
    "eval": "CODE_INJECTION", "exec": "CODE_INJECTION",
    "pickle.loads": "INSECURE_DESERIALIZATION", "pickle.load": "INSECURE_DESERIALIZATION",
    "yaml.load": "INSECURE_DESERIALIZATION", "yaml.unsafe_load": "INSECURE_DESERIALIZATION",
    "requests.get": "SSRF", "requests.post": "SSRF", "urllib.request.urlopen": "SSRF",
    "redirect": "OPEN_REDIRECT", "flask.redirect": "OPEN_REDIRECT",
    "open": "PATH_TRAVERSAL", "send_file": "PATH_TRAVERSAL", "flask.send_file": "PATH_TRAVERSAL",
}
SANITIZERS = {"shlex.quote", "html.escape", "int", "float", "yaml.safe_load", "os.path.basename"}
TRANSFORMS = {"str", "bytes", "repr", "str.format"}
BASE_LIMITATIONS = [
    "Static dependencies only; branch satisfiability and exploitability are not proven.",
    "No heap-alias, dynamic-dispatch, exception, concurrency or loop fixed-point analysis.",
]


def stable_id(*parts: object) -> str:
    return hashlib.sha256("\0".join(map(str, parts)).encode()).hexdigest()[:24]


@dataclass(frozen=True)
class Trace:
    nodes: tuple[str, ...]
    edges: tuple[str, ...] = ()
    controls: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass
class State:
    env: dict[str, list[Trace]] = field(default_factory=dict)
    controls: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    def clone(self) -> State:
        return State(dict(self.env), self.controls, self.limitations)


class InvestigationAnalyzer:
    """Retain bounded alternative paths across explicit assignments and calls."""

    def __init__(self, files: list[Path], max_paths: int = 64, max_depth: int = 5,
                 max_states: int = 64, max_steps: int = 50000):
        self.max_paths, self.max_depth, self.max_states = max_paths, max_depth, max_states
        self.max_steps, self.steps = max_steps, 0
        self.trees: dict[str, ast.Module] = {}
        self.text: dict[str, str] = {}
        self.functions: dict[tuple[str, str], ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.aliases: dict[str, dict[str, str]] = {}
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}
        self.paths: dict[str, dict[str, Any]] = {}
        self.limitations: set[str] = set()
        self.sinks: dict[str, str] = {}
        for path in sorted(set(Path(p).resolve() for p in files)):
            if path.suffix not in {".py", ".pyw"}:
                continue
            key = str(path)
            try:
                self.text[key] = path.read_text(encoding="utf-8")
                self.trees[key] = ast.parse(self.text[key], filename=key)
            except (OSError, UnicodeError, SyntaxError) as exc:
                self.limitations.add(f"Could not parse {key}: {exc}")
                continue
            self.aliases[key] = {}
            for node in self.trees[key].body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.functions[key, node.name] = node
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        self.aliases[key][alias.asname or alias.name] = alias.name
                elif isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        self.aliases[key][alias.asname or alias.name] = "." * node.level + (node.module or "") + "." + alias.name

    def tick(self) -> None:
        self.steps += 1
        if self.steps > self.max_steps:
            raise RuntimeError("Investigation work budget reached; evidence is truncated.")

    def node(self, file: str, expr: ast.AST, kind: str, label: str,
             context: tuple[str, ...] = ()) -> str:
        key = stable_id(file, getattr(expr, "lineno", 0), getattr(expr, "col_offset", 0), kind, label, context)
        self.nodes.setdefault(key, {
            "id": key, "kind": kind, "label": label, "file": file,
            "line": getattr(expr, "lineno", 0), "column": getattr(expr, "col_offset", 0) + 1,
            "end_line": getattr(expr, "end_lineno", getattr(expr, "lineno", 0)),
            "snippet": ast.get_source_segment(self.text[file], expr) or ast.unparse(expr),
            "context": list(context), "origin": "python_ast",
        })
        return key

    def edge(self, source: str, target: str, relation: str, kind: str = "data", verified: bool = True) -> str:
        key = stable_id(source, target, relation, kind, verified)
        self.edges[key] = {"id": key, "source": source, "target": target,
                           "relation": relation, "kind": kind, "verified": verified}
        return key

    def extend(self, traces: list[Trace], node: str, relation: str, state: State,
               limitation: str | None = None) -> list[Trace]:
        result = []
        for trace in traces:
            controls = tuple(dict.fromkeys((*trace.controls, *state.controls)))
            notes = tuple(dict.fromkeys((*trace.limitations, *state.limitations, *((limitation,) if limitation else ()))))
            edge = self.edge(trace.nodes[-1], node, relation, verified=limitation is None)
            result.append(Trace((*trace.nodes, node), (*trace.edges, edge), controls, notes))
        unique = list(dict.fromkeys(result))
        if len(unique) > self.max_paths:
            self.limitations.add("Per-value path cap reached; additional paths omitted.")
        return unique[:self.max_paths]

    def callee(self, file: str, expr: ast.AST) -> str:
        name = ast.unparse(expr)
        first, _, tail = name.partition(".")
        alias = self.aliases.get(file, {}).get(first, first)
        return alias + ("." + tail if tail else "")

    def resolve(self, file: str, name: str) -> tuple[str, ast.FunctionDef | ast.AsyncFunctionDef] | None:
        local = self.functions.get((file, name))
        if local:
            return file, local
        module, _, function = name.rpartition(".")
        if not module:
            return None
        # Only resolve an unambiguous import to one of the actual scanned files.
        parts = module.lstrip(".").split(".")
        base = Path(file).parent
        relative = base.joinpath(*parts).with_suffix(".py")
        candidates = [p for p in self.trees if Path(p) == relative]
        if not candidates:
            suffix = "/".join(parts) + ".py"
            candidates = [p for p in self.trees if Path(p).as_posix().endswith("/" + suffix)]
        if len(candidates) == 1 and (candidates[0], function) in self.functions:
            return candidates[0], self.functions[candidates[0], function]
        return None

    @staticmethod
    def source(name: str) -> bool:
        return name == "input" or name in {"sys.argv", "os.environ", "os.environ.get"} or name.startswith((
            "request.args", "request.form", "request.values", "request.GET", "request.POST",
            "request.json", "request.data", "request.get_json", "request.cookies", "request.headers",
            "flask.request.args", "flask.request.form",
        ))

    def expression(self, file: str, expr: ast.AST | None, state: State, context: tuple[str, ...]) -> list[Trace]:
        self.tick()
        if expr is None or isinstance(expr, ast.Constant):
            return []
        if isinstance(expr, ast.Name):
            return state.env.get(expr.id, [])
        if isinstance(expr, (ast.Attribute, ast.Subscript)):
            name = self.callee(file, expr)
            if self.source(name):
                return [Trace((self.node(file, expr, "source", name, context),), controls=state.controls)]
            key = ast.unparse(expr)
            if key in state.env:
                values = state.env[key]
            elif isinstance(expr, ast.Subscript):
                if isinstance(expr.slice, ast.Constant):
                    # Literal collections retain member provenance, not the union of all members.
                    values = state.env.get(key, [])
                    if not any(k.startswith(ast.unparse(expr.value) + "[") for k in state.env):
                        values = self.expression(file, expr.value, state, context)
                        state = state.clone()
                        state.limitations += ("Collection membership or alias is unresolved.",)
                else:
                    values = self.expression(file, expr.value, state, context)
                    state = state.clone()
                    state.limitations += ("Dynamic collection index is unresolved.",)
            else:
                values = []  # Do not infer arbitrary object-field dependencies.
            node = self.node(file, expr, "collection_access" if isinstance(expr, ast.Subscript) else "field_access", key, context)
            return self.extend(values, node, self.nodes[node]["kind"], state)
        if isinstance(expr, ast.Call):
            name = self.callee(file, expr.func)
            if self.source(name):
                return [Trace((self.node(file, expr, "source", name, context),), controls=state.controls)]
            args = [self.expression(file, arg, state, context) for arg in expr.args]
            keywords = {k.arg: self.expression(file, k.value, state, context) for k in expr.keywords}
            values = [v for group in [*args, *keywords.values()] for v in group]
            family = SINKS.get(name)
            if name.endswith((".execute", ".executemany")):
                family = "SQL_INJECTION"
            if family:
                node = self.node(file, expr, "sink", name, context)
                self.sinks[node] = family
                # SQL parameters are not SQL query syntax; only query argument is a sink.
                values = args[0] if args else keywords.get("query", keywords.get("url", keywords.get("command", [])))
                for trace in self.extend(values, node, "argument_passing", state):
                    self.record(trace)
                return []
            resolved = self.resolve(file, name)
            if resolved and len(context) < self.max_depth:
                callee_file, function = resolved
                call_id = self.node(file, expr, "call", name, context)
                call_context = (*context, call_id)
                local = State(controls=state.controls, limitations=state.limitations)
                for index, parameter in enumerate([*function.args.posonlyargs, *function.args.args]):
                    value = args[index] if index < len(args) else keywords.get(parameter.arg, [])
                    passed = self.extend(value, call_id, "argument_passing", state)
                    param_id = self.node(callee_file, parameter, "parameter", parameter.arg, call_context)
                    local.env[parameter.arg] = self.extend(passed, param_id, "parameter_binding", state)
                _, returned = self.block(callee_file, function.body, [local], call_context)
                result_id = self.node(file, expr, "call_result", name, context)
                return self.extend(returned, result_id, "return_value", state)
            node = self.node(file, expr, "sanitizer" if name in SANITIZERS else "call", name, context)
            if name in SANITIZERS:
                return self.extend(values, node, "sanitizer_call", state)
            if name in TRANSFORMS or name.endswith((".format", ".join", ".strip", ".lower", ".upper", ".encode", ".decode")):
                if isinstance(expr.func, ast.Attribute):
                    values += self.expression(file, expr.func.value, state, context)
                return self.extend(values, node, "data_transformation", state)
            reason = "Call depth limit reached." if resolved else f"Return dependency of external/dynamic call {name} is unverified."
            return self.extend(values, node, "unresolved_return", state, reason)
        if isinstance(expr, ast.IfExp):
            # Separate alternatives; condition reads are control dependencies, never data sources.
            result = []
            for branch, label in [(expr.body, "true"), (expr.orelse, "false")]:
                local = state.clone()
                local.controls += (self.node(file, expr.test, "branch", label, context),)
                result += self.expression(file, branch, local, context)
            return result
        if isinstance(expr, (ast.BinOp, ast.UnaryOp, ast.JoinedStr, ast.FormattedValue, ast.List, ast.Tuple, ast.Set, ast.Dict)):
            values = [trace for child in ast.iter_child_nodes(expr) if isinstance(child, ast.expr)
                      for trace in self.expression(file, child, state, context)]
            return self.extend(values, self.node(file, expr, "transformation", type(expr).__name__, context), "data_transformation", state)
        self.limitations.add(f"Unsupported expression {type(expr).__name__} at {file}:{getattr(expr, 'lineno', '?')}.")
        return []

    def assign(self, file: str, target: ast.AST, value: ast.AST | None, traces: list[Trace], state: State, context: tuple[str, ...]) -> None:
        key = ast.unparse(target)
        if isinstance(target, (ast.Tuple, ast.List)):
            self.limitations.add("Destructuring assignments are not modeled.")
            for item in target.elts:
                state.env[ast.unparse(item)] = []
            return
        # Strong updates kill both the old value and its known members.
        for old in list(state.env):
            if old == key or old.startswith(key + "[") or old.startswith(key + "."):
                del state.env[old]
        node = self.node(file, target, "assignment", key, context)
        state.env[key] = self.extend(traces, node, "assignment", state)
        if isinstance(value, (ast.List, ast.Tuple, ast.Dict)):
            pairs = zip(value.keys, value.values) if isinstance(value, ast.Dict) else enumerate(value.elts)
            for member, item in pairs:
                member_key = member.value if isinstance(member, ast.Constant) else member
                if not isinstance(member_key, (str, int)):
                    continue
                member_traces = self.expression(file, item, state, context)
                state.env[f"{key}[{member_key!r}]"] = self.extend(member_traces, node, "collection_store", state)

    def block(self, file: str, body: list[ast.stmt], states: list[State], context: tuple[str, ...]) -> tuple[list[State], list[Trace]]:
        returned: list[Trace] = []
        for statement in body:
            self.tick()
            next_states: list[State] = []
            for state in states:
                if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    value = statement.value
                    traces = self.expression(file, value, state, context)
                    targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                    if isinstance(statement, ast.AugAssign):
                        traces += self.expression(file, statement.target, state, context)
                    for target in targets:
                        self.assign(file, target, value, traces, state, context)
                elif isinstance(statement, ast.Expr):
                    self.expression(file, statement.value, state, context)
                elif isinstance(statement, ast.Return):
                    traces = self.expression(file, statement.value, state, context)
                    returned += self.extend(traces, self.node(file, statement, "return", "return", context), "return_value", state)
                    continue
                elif isinstance(statement, ast.If):
                    # Evaluate calls in predicates for sink evidence, but never taint the branch body.
                    self.expression(file, statement.test, state, context)
                    for branch, label in [(statement.body, "true"), (statement.orelse, "false")]:
                        if isinstance(statement.test, ast.Constant) and bool(statement.test.value) != (label == "true"):
                            continue
                        local = state.clone()
                        local.controls += (self.node(file, statement.test, "branch", label, context),)
                        survivors, returns = self.block(file, branch, [local], context)
                        next_states.extend(survivors)
                        returned.extend(returns)
                    continue
                elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Import, ast.ImportFrom, ast.Pass)):
                    pass
                elif isinstance(statement, ast.Raise):
                    continue
                else:
                    self.limitations.add(f"Unsupported statement {type(statement).__name__} at {file}:{statement.lineno}; state after it is uncertain.")
                    state.limitations += (f"Unmodeled {type(statement).__name__} before sink.",)
                next_states.append(state)
            if len(next_states) > self.max_states:
                self.limitations.add("Branch-state cap reached; additional alternatives omitted.")
            states = next_states[:self.max_states]
            if not states:
                break
        return states, returned[:self.max_paths]

    def record(self, trace: Trace) -> None:
        sink = trace.nodes[-1]
        if sum(p["sink"] == sink for p in self.paths.values()) >= self.max_paths:
            self.limitations.add("Per-sink path cap reached; additional paths omitted.")
            return
        controls = [self.edge(control, sink, "branch_condition", "control") for control in trace.controls]
        key = stable_id(trace.nodes, trace.edges, trace.controls)
        self.paths[key] = {
            "id": key, "source": trace.nodes[0], "sink": sink,
            "node_ids": list(trace.nodes), "edge_ids": list(trace.edges),
            "control_node_ids": list(trace.controls), "control_edge_ids": controls,
            "sanitizers": [n for n in trace.nodes if self.nodes[n]["kind"] == "sanitizer"],
            "trace_completeness": "partial" if trace.limitations else "complete",
            "verified": not trace.limitations, "confidence": "static_dependency",
            "analysis_limitations": list(trace.limitations),
        }

    def analyze(self) -> InvestigationAnalyzer:
        try:
            called = set()
            for file, tree in self.trees.items():
                for expr in ast.walk(tree):
                    if isinstance(expr, ast.Call):
                        resolved = self.resolve(file, self.callee(file, expr.func))
                        if resolved:
                            called.add((resolved[0], resolved[1].name))
            for file, tree in self.trees.items():
                self.block(file, tree.body, [State()], ())
                # Entry parameters are unknown, never synthetic untrusted sources.
                for (function_file, _), function in self.functions.items():
                    if function_file == file and (function_file, function.name) not in called:
                        self.block(file, function.body, [State()], ())
        except (RuntimeError, RecursionError) as exc:
            self.limitations.add(str(exc))
        return self

    def graph_for(self, file: str, line: int, end_line: int | None = None) -> dict[str, Any]:
        file = str(Path(file).resolve())
        end_line = end_line or line
        # Sink identity does not require a supported control-flow construct.
        for expr in ast.walk(self.trees.get(file, ast.Module(body=[], type_ignores=[]))):
            if isinstance(expr, ast.Call) and expr.lineno <= end_line and expr.end_lineno >= line:
                name = self.callee(file, expr.func)
                family = SINKS.get(name) or ("SQL_INJECTION" if name.endswith((".execute", ".executemany")) else None)
                if family and not any(n["file"] == file and n["line"] == expr.lineno and n["column"] == expr.col_offset + 1 and n["kind"] == "sink" for n in self.nodes.values()):
                    self.sinks[self.node(file, expr, "sink", name)] = family
        sink_ids = [key for key in self.sinks if self.nodes[key]["file"] == file
                    and self.nodes[key]["line"] <= end_line and self.nodes[key]["end_line"] >= line]
        paths = [p for p in self.paths.values() if p["sink"] in sink_ids]
        node_ids = set(sink_ids)
        edge_ids: set[str] = set()
        for path in paths:
            node_ids.update(path["node_ids"] + path["control_node_ids"])
            edge_ids.update(path["edge_ids"] + path["control_edge_ids"])
        nodes = [self.nodes[n] for n in sorted(node_ids)]
        mode = "verified_path" if any(p["verified"] for p in paths) else "partial_path" if paths else "sink_only" if sink_ids else "no_evidence"
        limitations = [*BASE_LIMITATIONS, *sorted(self.limitations)]
        if not paths:
            limitations.append("No source-to-sink dependency was established for this match.")
        return {
            "schema_version": "1.0", "analysis_engine": "python-bounded-provenance",
            "evidence_mode": mode, "nodes": nodes,
            "edges": [self.edges[e] for e in sorted(edge_ids)], "paths": sorted(paths, key=lambda p: p["id"]),
            "sources": sorted({p["source"] for p in paths}), "sinks": sink_ids,
            "sanitizers": sorted({n for p in paths for n in p["sanitizers"]}),
            "trace_completeness": "complete" if paths and all(p["verified"] for p in paths) else "partial" if paths else "unavailable",
            "analysis_limitations": limitations,
            "truncated": any("cap reached" in s or "budget reached" in s for s in self.limitations),
        }

    def enrich(self, finding: Any) -> None:
        """Attach new evidence without rewriting legacy traces or triage decisions."""
        graph = self.graph_for(finding.file_path, finding.line_number,
                               finding.evidence.metadata.get("semgrep_end", {}).get("line"))
        if not graph["nodes"]:
            file = str(Path(finding.file_path).resolve())
            lines = self.text.get(file, "").splitlines()
            snippet = lines[finding.line_number - 1] if 0 < finding.line_number <= len(lines) else finding.evidence.sink.code_snippet
            if snippet:
                key = stable_id(file, finding.line_number, finding.rule_id, "pattern")
                graph["nodes"] = [{"id": key, "kind": "pattern", "label": finding.rule_id,
                                   "file": file, "line": finding.line_number, "column": 1,
                                   "snippet": snippet, "origin": "rule_match"}]
                graph["evidence_mode"] = "pattern_only"
            graph["sink_missing_reason"] = "No recognized matched call was established at the rule location."
        else:
            labels = sorted({self.nodes[n]["label"] for n in graph["sinks"]})
            graph["sink_function"] = ", ".join(labels)
        finding.evidence.graph = graph


def validate_graph(graph: dict[str, Any]) -> None:
    """Reject dangling or reordered path references at serialization boundaries."""
    nodes = {node["id"] for node in graph["nodes"]}
    edges = {edge["id"]: edge for edge in graph["edges"]}
    assert len(nodes) == len(graph["nodes"]), "Duplicate node IDs"
    for edge in edges.values():
        assert edge["source"] in nodes and edge["target"] in nodes, "Dangling edge"
    for path in graph["paths"]:
        assert path["source"] == path["node_ids"][0] and path["sink"] == path["node_ids"][-1]
        assert len(path["edge_ids"]) == len(path["node_ids"]) - 1
        for index, edge_id in enumerate(path["edge_ids"]):
            edge = edges[edge_id]
            assert edge["source"] == path["node_ids"][index] and edge["target"] == path["node_ids"][index + 1]
            assert edge["kind"] == "data", "Control edge presented as data flow"


def enrich_scan(scan_result: Any, max_depth: int = 5) -> InvestigationAnalyzer:
    """Enrich every finding and retain newly established dependencies as review items.

    Native findings retain their types, classifications, triage and legacy paths.
    Newly discovered sinks have a distinct detector rule and NEEDS_REVIEW status.
    """
    from aegis_sast.core.models import CodeLocation, EvidenceBundle, NormalizedFinding, Severity, TriageStatus
    from aegis_sast.integrations.semgrep_adapter import ImportedNormalizedVulnerability

    analyzer = InvestigationAnalyzer([Path(p) for p in scan_result.scanned_files], max_depth=max_depth).analyze()
    existing = set()
    for vulnerability in scan_result.vulnerabilities:
        finding = vulnerability.to_normalized_finding()
        analyzer.enrich(finding)
        existing.add((str(Path(finding.file_path).resolve()), finding.line_number))
        if hasattr(vulnerability, "finding"):
            vulnerability.finding.evidence.graph = finding.evidence.graph
        else:
            vulnerability.dataflow.metadata["investigation_graph"] = finding.evidence.graph

    for path in list(analyzer.paths.values()):
        if not path["verified"]:
            continue
        sink = analyzer.nodes[path["sink"]]
        key = (sink["file"], sink["line"])
        if key in existing:
            continue
        existing.add(key)
        graph = analyzer.graph_for(*key)
        source = analyzer.nodes[path["source"]]
        def location(node: dict[str, Any]) -> CodeLocation:
            return CodeLocation(node["file"], node["line"], node["column"], node["snippet"])
        family = analyzer.sinks[path["sink"]]
        finding = NormalizedFinding(
            id=stable_id("bounded-provenance", *key, sink["label"]), tool="aegis-python-provenance", language="python",
            rule_id=f"aegis.python.verified-flow.{family.lower()}", vulnerability_type=family,
            severity=Severity.HIGH, triage_status=TriageStatus.NEEDS_REVIEW, confidence=0.7,
            file_path=sink["file"], line_number=sink["line"],
            message=f"Static input dependency reaches {sink['label']}; review sink context and sanitizers.",
            explanation="A bounded static analysis established the recorded dependencies. This is not an exploitability verdict.",
            evidence=EvidenceBundle(source=location(source), sink=location(sink),
                intermediate_steps=[location(analyzer.nodes[n]) for n in path["node_ids"][1:-1]],
                metadata={"source_verified": True, "sink_verified": True, "trace_completeness": graph["trace_completeness"],
                          "detection": {"sink_function": sink["label"]}}, graph=graph),
            metadata={"sink_function": sink["label"], "analysis_engine": "python-bounded-provenance"},
        )
        scan_result.vulnerabilities.append(ImportedNormalizedVulnerability(finding))
    return analyzer
