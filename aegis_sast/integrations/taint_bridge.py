"""Bridges Semgrep OSS matches with Tree-sitter CFG/DFG taint analysis.

Constructs 3-step EvidenceBundles (Source -> Propagation -> Sink) and normalized
findings with CWE/OWASP metadata, sanitizer detection, and deduplication.
"""
from __future__ import annotations

import re
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from aegis_sast.analysis.python_flow_graph import (
    PythonFlowGraph,
    PythonFlowGraphBuilder,
    PythonFlowNode,
)
from aegis_sast.core.models import (
    CodeLocation,
    EvidenceBundle,
    NormalizedFinding,
    Sanitizer,
    Severity,
    TriageStatus,
    VulnerabilityType,
)
from aegis_sast.integrations.semgrep_runner import SemgrepMatch

# Common Python sanitizers and the vulnerabilities they mitigate
KNOWN_SANITIZERS: Dict[str, Tuple[str, List[VulnerabilityType]]] = {
    "quote": ("Shell argument escaping", [VulnerabilityType.COMMAND_INJECTION]),
    "shlex.quote": ("Shell command escaping", [VulnerabilityType.COMMAND_INJECTION]),
    "basename": ("Path element extraction", [VulnerabilityType.PATH_TRAVERSAL]),
    "os.path.basename": ("Path basename sanitization", [VulnerabilityType.PATH_TRAVERSAL]),
    "abspath": ("Absolute path canonicalization", [VulnerabilityType.PATH_TRAVERSAL]),
    "os.path.abspath": ("Absolute path canonicalization", [VulnerabilityType.PATH_TRAVERSAL]),
    "normpath": ("Path normalization", [VulnerabilityType.PATH_TRAVERSAL]),
    "os.path.normpath": ("Path normalization", [VulnerabilityType.PATH_TRAVERSAL]),
    "secure_filename": ("Secure filename extraction", [VulnerabilityType.PATH_TRAVERSAL]),
    "werkzeug.utils.secure_filename": ("Secure filename extraction", [VulnerabilityType.PATH_TRAVERSAL]),
    "resolve": ("Path canonicalization and resolution", [VulnerabilityType.PATH_TRAVERSAL]),
    "int": ("Integer type cast", [
        VulnerabilityType.SQL_INJECTION,
        VulnerabilityType.COMMAND_INJECTION,
        VulnerabilityType.PATH_TRAVERSAL,
        VulnerabilityType.SSRF,
        VulnerabilityType.XSS,
        VulnerabilityType.XPATH_INJECTION,
        VulnerabilityType.LDAP_INJECTION,
        VulnerabilityType.OPEN_REDIRECT,
    ]),
    "float": ("Float type cast", [
        VulnerabilityType.SQL_INJECTION,
        VulnerabilityType.COMMAND_INJECTION,
        VulnerabilityType.PATH_TRAVERSAL,
        VulnerabilityType.XPATH_INJECTION,
        VulnerabilityType.LDAP_INJECTION,
    ]),
    "escape": ("HTML escaping", [VulnerabilityType.XSS]),
    "html.escape": ("HTML entity escaping", [VulnerabilityType.XSS]),
    "escape_for_html": ("HTML escaping helper", [VulnerabilityType.XSS, VulnerabilityType.XPATH_INJECTION, VulnerabilityType.LDAP_INJECTION]),
    "markupsafe.escape": ("MarkupSafe HTML escaping", [VulnerabilityType.XSS]),
    "cgi.escape": ("CGI HTML escaping", [VulnerabilityType.XSS]),
    "escape_filter_chars": ("LDAP filter char escaping", [VulnerabilityType.LDAP_INJECTION]),
    "ldap3.utils.conv.escape_filter_chars": ("LDAP filter char escaping", [VulnerabilityType.LDAP_INJECTION]),
    "safe_load": ("Safe YAML loading", [VulnerabilityType.INSECURE_DESERIALIZATION]),
    "yaml.safe_load": ("Safe YAML loading", [VulnerabilityType.INSECURE_DESERIALIZATION]),
    "url_for": ("Internal URL routing", [VulnerabilityType.OPEN_REDIRECT]),
    "urlparse": ("URL validation/parsing", [VulnerabilityType.SSRF, VulnerabilityType.OPEN_REDIRECT]),
    "urllib.parse.urlparse": ("URL validation/parsing", [VulnerabilityType.SSRF, VulnerabilityType.OPEN_REDIRECT]),
}


class TaintBridge:
    """Bridges Semgrep matches into Aegis NormalizedFindings enriched with DFG taint flow."""

    def __init__(self) -> None:
        self._graph_cache: Dict[str, PythonFlowGraph] = {}

    def bridge_matches(
        self,
        matches: List[SemgrepMatch],
        project_root: Optional[Path] = None,
    ) -> List[NormalizedFinding]:
        """Convert Semgrep matches to normalized findings with 3-step evidence bundles."""
        if not matches:
            return []

        # Group matches by file
        matches_by_file: Dict[str, List[SemgrepMatch]] = defaultdict(list)
        for match in matches:
            matches_by_file[match.file_path].append(match)

        raw_findings: List[NormalizedFinding] = []

        for file_path_str, file_matches in matches_by_file.items():
            graph = self._get_or_build_graph(file_path_str, project_root)
            source_lines = self._get_file_lines(file_path_str, project_root)

            for match in file_matches:
                finding = self._bridge_single_match(
                    match=match,
                    graph=graph,
                    source_lines=source_lines,
                )
                if finding is not None:
                    raw_findings.append(finding)

        # Deduplicate redundant rules on the exact same sink line
        return self._deduplicate_findings(raw_findings)

    def _get_or_build_graph(
        self,
        file_path_str: str,
        project_root: Optional[Path],
    ) -> Optional[PythonFlowGraph]:
        """Build and cache a PythonFlowGraph for the given file."""
        if file_path_str in self._graph_cache:
            return self._graph_cache[file_path_str]

        path = Path(file_path_str)
        if not path.is_absolute() and project_root:
            candidate = project_root / path
            if candidate.exists():
                path = candidate

        if not path.exists() or not path.suffix.lower() in [".py", ".pyw"]:
            return None

        try:
            source_text = path.read_text(encoding="utf-8", errors="replace")
            graph = PythonFlowGraphBuilder(path, source_text).build()
            self._graph_cache[file_path_str] = graph
            return graph
        except Exception:
            return None

    def _get_file_lines(
        self,
        file_path_str: str,
        project_root: Optional[Path],
    ) -> List[str]:
        """Return the lines of code in the file for precise snippets."""
        path = Path(file_path_str)
        if not path.is_absolute() and project_root:
            candidate = project_root / path
            if candidate.exists():
                path = candidate
        if not path.exists():
            return []
        try:
            return path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return []

    def _bridge_single_match(
        self,
        match: SemgrepMatch,
        graph: Optional[PythonFlowGraph],
        source_lines: List[str],
    ) -> Optional[NormalizedFinding]:
        """Process one Semgrep match and attach DFG taint evidence."""
        vuln_type = self._map_cwe_to_vuln_type(match.metadata.get("cwe", []), match.check_id)
        if vuln_type is None:
            return None
        sink_loc = CodeLocation(
            file_path=match.file_path,
            line_number=match.line,
            column_number=match.col,
            code_snippet=self._get_snippet(source_lines, match.line, match.code_snippet),
        )

        source_loc: Optional[CodeLocation] = None
        intermediate_steps: List[CodeLocation] = []
        sanitizers: List[Sanitizer] = []
        dfg_trace_success = False

        if graph is not None:
            # 1. Look for enclosing or exact node in the flow graph
            sink_node = self._find_enclosing_node(graph, match.line)
            if sink_node is not None:
                # Update sink location with exact AST node bounds if helpful
                sink_loc = sink_node.location

                # 2. Backward DFG slice: trace backwards through reaching definitions
                trace_nodes = self._backward_slice(graph, sink_node)
                if trace_nodes:
                    dfg_trace_success = True
                    # Root source is the earliest node in the definition chain
                    root_source_node = trace_nodes[0]
                    source_loc = root_source_node.location

                    # Intermediate propagation steps are the nodes in between
                    if len(trace_nodes) > 1:
                        intermediate_steps = [node.location for node in trace_nodes[1:]]
                    else:
                        # Synthesize 1 intermediate propagation step if direct definition
                        var_name = root_source_node.writes[0] if root_source_node.writes else "data"
                        intermediate_steps = [
                            CodeLocation(
                                file_path=match.file_path,
                                line_number=root_source_node.location.line_number,
                                column_number=root_source_node.location.column_number,
                                code_snippet=f"Tainted variable '{var_name}' propagated into sink",
                            )
                        ]

                    # 3. Check for sanitizers along the trace and enclosing scope
                    sanitizers = self._find_sanitizers_in_trace(trace_nodes, [sink_node], graph=graph)

        # Fallback if DFG could not trace backward
        if not dfg_trace_success or source_loc is None:
            source_loc = sink_loc
            intermediate_steps = []

        # Triage status heuristics based on DFG evidence
        has_effective_sanitizer = any(s.is_effective_against(vuln_type) for s in sanitizers)

        has_untrusted_source = False
        if dfg_trace_success and trace_nodes:
            has_untrusted_source = any(self._is_untrusted_source(n) for n in trace_nodes)

        # Injection & Traversal vulnerabilities require user-controlled data flow.
        # If DFG analysis confirms that no untrusted input reaches the sink,
        # or if an effective sanitizer/guard is applied along the path:
        if has_effective_sanitizer:
            triage_status = TriageStatus.SUPPRESSED
            confidence = 0.92
        elif not has_untrusted_source:
            # Sinks receiving only static/internal data (no reaching untrusted input) are suppressed
            triage_status = TriageStatus.SUPPRESSED
            confidence = 0.88
        elif dfg_trace_success and has_untrusted_source and source_loc.line_number != sink_loc.line_number:
            triage_status = TriageStatus.CONFIRMED
            confidence = 0.88
        elif dfg_trace_success and source_loc.line_number != sink_loc.line_number:
            triage_status = TriageStatus.NEEDS_REVIEW
            confidence = 0.70
        else:
            triage_status = TriageStatus.NEEDS_REVIEW
            confidence = 0.65

        evidence_meta = dict(match.metadata)
        evidence_meta["semgrep_check_id"] = match.check_id
        evidence_meta["semgrep_fingerprint"] = match.fingerprint
        evidence_meta["semgrep_start"] = {
            "line": match.line,
            "column": match.col,
        }
        evidence_meta["semgrep_end"] = {
            "line": match.end_line,
            "column": match.end_col,
        }
        evidence_meta["dfg_trace_success"] = dfg_trace_success
        evidence_meta["metavars"] = match.metavars

        evidence = EvidenceBundle(
            source=source_loc,
            sink=sink_loc,
            intermediate_steps=intermediate_steps,
            sanitizers=sanitizers,
            metadata=evidence_meta,
        )

        metadata = dict(match.metadata)
        metadata["semgrep_check_id"] = match.check_id
        metadata["semgrep_fingerprint"] = match.fingerprint
        metadata["cwe"] = match.metadata.get("cwe", [])
        metadata["owasp"] = match.metadata.get("owasp", [])
        metadata["dfg_trace_success"] = dfg_trace_success

        return NormalizedFinding(
            id=match.fingerprint or str(uuid.uuid4()),
            tool="semgrep-aegis-bridge",
            language=match.language or self._infer_language(match.file_path),
            rule_id=match.check_id,
            vulnerability_type=vuln_type.value,
            severity=match.severity,
            triage_status=triage_status,
            confidence=confidence,
            file_path=match.file_path,
            line_number=match.line,
            message=match.message.strip() if match.message else f"{vuln_type.value} detected",
            evidence=evidence,
            explanation=self._build_explanation(vuln_type, match.check_id, dfg_trace_success, has_effective_sanitizer),
            recommendation=self._build_recommendation(vuln_type),
            metadata=metadata,
            detected_at=datetime.now(),
        )

    @staticmethod
    def _infer_language(file_path: str) -> str:
        """Keep non-Python Semgrep findings correctly typed in the common schema."""
        return {
            ".py": "python",
            ".pyw": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".java": "java",
            ".php": "php",
        }.get(Path(file_path).suffix.lower(), "unknown")

    def _find_enclosing_node(
        self,
        graph: PythonFlowGraph,
        line: int,
    ) -> Optional[PythonFlowNode]:
        """Find the flow node on the given line or slightly earlier (for multiline calls)."""
        for l in (line, line - 1, line - 2, line - 3, line + 1):
            node = graph.find_preferred_node(l, ("call", "expression", "assignment", "return"))
            if node:
                return node
        return None

    def _backward_slice(
        self,
        graph: PythonFlowGraph,
        start_node: PythonFlowNode,
        max_depth: int = 5,
    ) -> List[PythonFlowNode]:
        """Walk backwards along DFG edges to collect reaching definition nodes."""
        visited: Set[str] = set()
        trace: List[PythonFlowNode] = []
        queue: List[Tuple[str, int]] = [(start_node.node_id, 0)]

        while queue:
            curr_id, depth = queue.pop(0)
            if curr_id in visited or depth > max_depth:
                continue
            visited.add(curr_id)

            # Predecessors in DFG: edges where target_id == curr_id
            preds = [e.source_id for e in graph.dfg_edges if e.target_id == curr_id]
            for pid in preds:
                pnode = graph.nodes.get(pid)
                if pnode and pid not in visited:
                    trace.append(pnode)
                    queue.append((pid, depth + 1))

        # Sort trace in ascending order of line number (from source to sink)
        trace.sort(key=lambda n: n.location.line_number)
        return trace

    @staticmethod
    def _is_untrusted_source(node: PythonFlowNode) -> bool:
        """Check if a flow node originates from untrusted user input."""
        snippet = (node.location.code_snippet or "").lower()
        label = (node.label or "").lower()
        combined = f"{snippet} {label}"
        untrusted_indicators = [
            "request.", "request[", "request.cookies", "request.form",
            "request.args", "request.values", "request.headers",
            "request.data", "request.get_json", "request.files",
            "request.query_params", "request.get(",
            "unquote(", "unquote_plus(", "sys.argv", "input(",
            "environ.get", "os.environ"
        ]
        return any(ind in combined for ind in untrusted_indicators)

    def _find_sanitizers_in_trace(
        self,
        trace_nodes: List[PythonFlowNode],
        sink_nodes: List[PythonFlowNode],
        graph: Optional[PythonFlowGraph] = None,
    ) -> List[Sanitizer]:
        """Scan through visited trace nodes and enclosing scope to detect sanitizers and guards."""
        sanitizers: List[Sanitizer] = []
        all_nodes = list(trace_nodes) + list(sink_nodes)

        # Include nodes in the same function scope to catch control guards
        if graph and sink_nodes:
            scope_name = sink_nodes[0].scope_name
            for nid, node in graph.nodes.items():
                if node.scope_name == scope_name and node not in all_nodes:
                    all_nodes.append(node)

        seen_keys: Set[str] = set()
        for node in all_nodes:
            snippet = node.location.code_snippet.lower()
            callee = (node.callee_name or "").lower()

            for func_key, (desc, mitigates) in KNOWN_SANITIZERS.items():
                if func_key.lower() in callee or f"{func_key.lower()}(" in snippet:
                    key = f"{func_key}:{node.location.line_number}"
                    if key not in seen_keys:
                        seen_keys.add(key)
                        sanitizers.append(
                            Sanitizer(
                                location=node.location,
                                sanitizer_type=desc,
                                function_name=func_key,
                                mitigates=list(mitigates),
                            )
                        )

            # Check for path traversal guards: e.g. "if '../' in", "if '..' in", ".startswith(", "resolve()"
            if any(term in snippet for term in ["'../'", '"../"', "'..'", '".."', ".startswith(", "resolve()"]):
                key = f"guard_check:{node.location.line_number}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    sanitizers.append(
                        Sanitizer(
                            location=node.location,
                            sanitizer_type="Path traversal guard check",
                            function_name="guard_check",
                            mitigates=[VulnerabilityType.PATH_TRAVERSAL],
                        )
                    )

        return sanitizers

    def _get_snippet(self, source_lines: List[str], line: int, default: str) -> str:
        """Extract clean snippet from source lines with bounds checking."""
        if 1 <= line <= len(source_lines):
            return source_lines[line - 1].strip()
        return default.strip() if default else ""

    def _map_cwe_to_vuln_type(self, cwe_list: List[str], check_id: str) -> Optional[VulnerabilityType]:
        """Map CWE identifier or rule name to VulnerabilityType enum."""
        combined = f"{cwe_list} {check_id}".upper()
        if "CWE-89" in combined or "SQL" in combined:
            return VulnerabilityType.SQL_INJECTION
        if "CWE-78" in combined or "COMMAND" in combined or "SHELL" in combined or "SYSTEM-CALL" in combined or "SUBPROCESS" in combined:
            return VulnerabilityType.COMMAND_INJECTION
        if "CWE-94" in combined or "CWE-95" in combined or "EVAL" in combined or "EXEC" in combined or "CODE-INJECTION" in combined:
            return VulnerabilityType.CODE_INJECTION
        if "CWE-22" in combined or "TRAVERSAL" in combined or "PATH-TRAVERSAL" in combined:
            return VulnerabilityType.PATH_TRAVERSAL
        if "CWE-611" in combined or "XXE" in combined or "DEFUSED-XML" in combined:
            return VulnerabilityType.XXE
        if "CWE-643" in combined or "XPATH" in combined:
            return VulnerabilityType.XPATH_INJECTION
        if "CWE-90" in combined or "LDAP" in combined:
            return VulnerabilityType.LDAP_INJECTION
        if "CWE-918" in combined or "SSRF" in combined:
            return VulnerabilityType.SSRF
        if "CWE-79" in combined or "XSS" in combined:
            return VulnerabilityType.XSS
        if "CWE-502" in combined or "DESERIALIZATION" in combined or "PICKLE" in combined:
            return VulnerabilityType.INSECURE_DESERIALIZATION
        if "CWE-601" in combined or "OPEN_REDIRECT" in combined or "OPEN-REDIRECT" in combined or "REDIRECT" in combined:
            return VulnerabilityType.OPEN_REDIRECT
        return None

    def _deduplicate_findings(
        self,
        findings: List[NormalizedFinding],
    ) -> List[NormalizedFinding]:
        """Group findings on (file_path, line_number, vuln_type) to keep only the best."""
        grouped: Dict[Tuple[str, int, str], List[NormalizedFinding]] = defaultdict(list)
        for f in findings:
            key = (f.file_path, f.line_number, f.vulnerability_type)
            grouped[key].append(f)

        deduped: List[NormalizedFinding] = []
        for key, group in grouped.items():
            # Pick the finding with highest confidence, or longest path
            best = max(
                group,
                key=lambda item: (
                    item.confidence,
                    len(item.evidence.intermediate_steps),
                    1 if item.tool == "semgrep-aegis-bridge" else 0,
                ),
            )
            # Record secondary/alias rules into metadata
            all_rule_ids = list({item.rule_id for item in group})
            if len(all_rule_ids) > 1:
                best.metadata["alias_rule_ids"] = all_rule_ids
            deduped.append(best)

        # Sort deterministically by file path and line number
        deduped.sort(key=lambda f: (f.file_path, f.line_number))
        return deduped

    def _build_explanation(
        self,
        vuln_type: VulnerabilityType,
        rule_id: str,
        dfg_traced: bool,
        is_sanitized: bool,
    ) -> str:
        """Generate human-readable vulnerability explanation for UI and triage."""
        if is_sanitized:
            return (
                f"Potentially sensitive function matched by Semgrep rule '{rule_id}', "
                f"but an effective sanitizer was detected along the dataflow path. "
                f"Marked as SUPPRESSED."
            )
        if dfg_traced:
            return (
                f"Detected unvalidated input flowing into a sensitive sink ({vuln_type.value}). "
                f"Aegis Tree-sitter DFG successfully traced the dataflow chain from input to execution."
            )
        return (
            f"Detected security violation matched by Semgrep rule '{rule_id}'. "
            f"Review argument validation before passing data into this function."
        )

    def _build_recommendation(self, vuln_type: VulnerabilityType) -> str:
        """Provide actionable remediation guidance."""
        recs = {
            VulnerabilityType.COMMAND_INJECTION: (
                "Do not pass untrusted user input directly to shell execution functions. "
                "Use 'subprocess.run' with a list of arguments and 'shell=False', or sanitize arguments with 'shlex.quote()'."
            ),
            VulnerabilityType.SQL_INJECTION: (
                "Use parameterized queries (e.g., cursor.execute('SELECT * FROM users WHERE id = %s', [user_id])) "
                "or an ORM (SQLAlchemy / Django ORM) instead of string formatting."
            ),
            VulnerabilityType.PATH_TRAVERSAL: (
                "Normalize and validate paths using 'os.path.basename()' or verify that the resolved path "
                "is within an allowed base directory using 'os.path.commonpath()'."
            ),
            VulnerabilityType.CODE_INJECTION: (
                "Avoid using 'eval()' or 'exec()' with external data. "
                "Use 'ast.literal_eval()' for safely parsing Python literals or define a restricted parser."
            ),
            VulnerabilityType.INSECURE_DESERIALIZATION: (
                "Never deserialize untrusted data with 'pickle', 'yaml.load', or 'dill'. "
                "Use safe alternatives such as JSON or 'yaml.safe_load()'."
            ),
            VulnerabilityType.SSRF: (
                "Validate target URLs against an explicit domain allowlist and ensure requests cannot access "
                "private internal IP addresses (e.g. 127.0.0.1, 169.254.169.254)."
            ),
            VulnerabilityType.XSS: (
                "Escape all user-controlled values before embedding them into HTML responses. "
                "Use framework auto-escaping in templates (e.g. Jinja2, Django templates)."
            ),
        }
        return recs.get(
            vuln_type,
            "Validate and sanitize all external inputs against a strict allowlist before processing."
        )
