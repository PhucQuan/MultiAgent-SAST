"""Inter-procedural Cross-File Taint Engine for Aegis-SAST.

Connects dataflow when Source and Sink reside in different Python files/modules
within a repository. Overcomes the cross-file blindness of intra-file scanners
(such as Semgrep OSS) by performing inter-module call-graph and parameter
propagation analysis.
"""
from __future__ import annotations

import ast
import fnmatch
import os
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from aegis_sast.analysis.call_graph import FunctionIndex, ImportResolver
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

# Standard sources of untrusted external input in Python web apps and scripts
DEFAULT_SOURCE_PATTERNS = [
    "request.args.get",
    "request.args[",
    "request.form.get",
    "request.form[",
    "request.values.get",
    "request.values[",
    "request.GET.get",
    "request.GET[",
    "request.POST.get",
    "request.POST[",
    "request.data",
    "request.json",
    "request.get_json",
    "flask.request.args",
    "flask.request.form",
    "sys.argv",
    "os.environ.get",
    "os.environ[",
    "input(",
]

# Standard sinks categorized by vulnerability type
DEFAULT_SINK_MAPPING = {
    # Command Injection
    "os.system": VulnerabilityType.COMMAND_INJECTION,
    "os.popen": VulnerabilityType.COMMAND_INJECTION,
    "subprocess.run": VulnerabilityType.COMMAND_INJECTION,
    "subprocess.call": VulnerabilityType.COMMAND_INJECTION,
    "subprocess.Popen": VulnerabilityType.COMMAND_INJECTION,
    "os.exec": VulnerabilityType.COMMAND_INJECTION,
    # Code Injection
    "eval": VulnerabilityType.CODE_INJECTION,
    "exec": VulnerabilityType.CODE_INJECTION,
    "compile": VulnerabilityType.CODE_INJECTION,
    # SQL Injection
    "execute": VulnerabilityType.SQL_INJECTION,
    "executemany": VulnerabilityType.SQL_INJECTION,
    "raw": VulnerabilityType.SQL_INJECTION,
    "text": VulnerabilityType.SQL_INJECTION,
    # Path Traversal
    "open": VulnerabilityType.PATH_TRAVERSAL,
    "send_file": VulnerabilityType.PATH_TRAVERSAL,
    "os.remove": VulnerabilityType.PATH_TRAVERSAL,
    # Insecure Deserialization
    "pickle.loads": VulnerabilityType.INSECURE_DESERIALIZATION,
    "pickle.load": VulnerabilityType.INSECURE_DESERIALIZATION,
    "yaml.load": VulnerabilityType.INSECURE_DESERIALIZATION,
    # SSRF
    "requests.get": VulnerabilityType.SSRF,
    "requests.post": VulnerabilityType.SSRF,
    "urllib.request.urlopen": VulnerabilityType.SSRF,
}

# Known sanitizers and the vulnerabilities they neutralize
CROSS_FILE_SANITIZERS = {
    "shlex.quote": (VulnerabilityType.COMMAND_INJECTION, "Shell argument escaping"),
    "quote": (VulnerabilityType.COMMAND_INJECTION, "Shell argument escaping"),
    "os.path.basename": (VulnerabilityType.PATH_TRAVERSAL, "Path element extraction"),
    "basename": (VulnerabilityType.PATH_TRAVERSAL, "Path element extraction"),
    "os.path.abspath": (VulnerabilityType.PATH_TRAVERSAL, "Absolute path normalization"),
    "int": (None, "Integer type casting"),  # Mitigates all numeric conversions
    "float": (None, "Float type casting"),
    "html.escape": (VulnerabilityType.XSS, "HTML entity escaping"),
    "yaml.safe_load": (VulnerabilityType.INSECURE_DESERIALIZATION, "Safe YAML parsing"),
}


@dataclass
class CallSiteInfo:
    """Detailed record of one function call across modules."""

    caller_file: Path
    caller_line: int
    callee_name: str
    arguments: List[str]
    imports: Dict[str, Path]
    raw_node: ast.Call


class CrossFileTaintEngine:
    """Inter-procedural taint propagation engine across multiple Python files."""

    def __init__(
        self,
        project_root: Path,
        max_depth: int = 5,
        exclude_dir_names: Optional[Set[str]] = None,
        exclude_globs: Optional[List[str]] = None,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        self.max_depth = max_depth
        self.exclude_dir_names = {
            value.strip().casefold()
            for value in (exclude_dir_names or set())
            if value and value.strip()
        }
        self.exclude_globs = [
            value.strip() for value in (exclude_globs or []) if value and value.strip()
        ]
        self.function_index = FunctionIndex()
        self.import_resolver = ImportResolver(self.project_root)
        self.call_sites: List[CallSiteInfo] = []
        self._graph_cache: Dict[str, PythonFlowGraph] = {}
        self._initialized = False

    def initialize(self) -> None:
        """Scan project files, index all function definitions and call sites."""
        if self._initialized:
            return

        self.function_index.build(
            self.project_root,
            exclude_dir_names=self.exclude_dir_names,
            exclude_globs=self.exclude_globs,
        )
        py_files = self._get_python_files()

        for file_path in py_files:
            self._index_file_call_sites(file_path)

        self._initialized = True

    def _get_python_files(self) -> List[Path]:
        """Collect all relevant Python files while ignoring hidden and virtualenv directories."""
        skip_dirs = {
            ".git",
            ".next",
            "node_modules",
            "venv",
            ".venv",
            "__pycache__",
            "build",
            "dist",
            *self.exclude_dir_names,
        }
        files: List[Path] = []
        for root, dirnames, filenames in os.walk(self.project_root, topdown=True):
            root_path = Path(root)
            dirnames[:] = sorted(
                dirname
                for dirname in dirnames
                if dirname.casefold() not in skip_dirs
            )
            for filename in sorted(filenames):
                if not filename.endswith(".py"):
                    continue
                path = root_path / filename
                relative = path.relative_to(self.project_root).as_posix()
                if any(fnmatch.fnmatch(relative, pattern) for pattern in self.exclude_globs):
                    continue
                files.append(path)
        return sorted(files)

    def _index_file_call_sites(self, file_path: Path) -> None:
        """Extract all function calls and their arguments in a single file."""
        try:
            source_text = file_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source_text, filename=str(file_path))
            imports = self.import_resolver.resolve_imports(file_path)

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    callee_name = ""
                    if isinstance(node.func, ast.Name):
                        callee_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        callee_name = ast.unparse(node.func)

                    args = [ast.unparse(a) for a in node.args]
                    self.call_sites.append(
                        CallSiteInfo(
                            caller_file=file_path,
                            caller_line=node.lineno,
                            callee_name=callee_name,
                            arguments=args,
                            imports=imports,
                            raw_node=node,
                        )
                    )
        except Exception:
            pass

    def analyze_project(self) -> List[NormalizedFinding]:
        """Perform full forward inter-procedural taint propagation across project files."""
        self.initialize()
        findings: List[NormalizedFinding] = []
        py_files = self._get_python_files()

        for file_path in py_files:
            file_findings = self._analyze_file_sources(file_path)
            findings.extend(file_findings)

        return self._deduplicate_cross_file_findings(findings)

    def _analyze_file_sources(self, file_path: Path) -> List[NormalizedFinding]:
        """Find local taint sources in file_path and trace forward through callers."""
        findings: List[NormalizedFinding] = []
        try:
            source_text = file_path.read_text(encoding="utf-8", errors="replace")
            graph = PythonFlowGraphBuilder(file_path, source_text).build()
            self._graph_cache[str(file_path)] = graph
        except Exception:
            return []

        # Find nodes matching untrusted input sources
        for node in graph.nodes.values():
            snippet = node.location.code_snippet
            if any(pat in snippet for pat in DEFAULT_SOURCE_PATTERNS):
                tainted_var = node.writes[0] if node.writes else None
                if not tainted_var:
                    continue

                source_location = CodeLocation(
                    file_path=str(file_path.relative_to(self.project_root) if file_path.is_relative_to(self.project_root) else file_path),
                    line_number=node.location.line_number,
                    column_number=node.location.column_number,
                    code_snippet=snippet,
                )

                chain = [source_location]
                sanitizers: List[Sanitizer] = []

                # Trace call sites in the same file that pass tainted_var
                for cs in self.call_sites:
                    if cs.caller_file == file_path and any(tainted_var == arg or f" {tainted_var}" in arg for arg in cs.arguments):
                        callee = cs.callee_name
                        step_loc = CodeLocation(
                            file_path=str(file_path.relative_to(self.project_root) if file_path.is_relative_to(self.project_root) else file_path),
                            line_number=cs.caller_line,
                            column_number=1,
                            code_snippet=f"Cross-file call: {callee}({', '.join(cs.arguments)})",
                        )
                        target_file = self._resolve_callee_target(callee, cs.imports)
                        if target_file and target_file.exists() and target_file != file_path:
                            entry = self.function_index.get(callee)
                            # Match argument position to parameter name
                            arg_idx = 0
                            for idx, a in enumerate(cs.arguments):
                                if tainted_var in a:
                                    arg_idx = idx
                                    break
                            param_name = entry.params[arg_idx] if entry and arg_idx < len(entry.params) else "arg"

                            self._trace_into_callee(
                                current_file=target_file,
                                func_name=callee,
                                tainted_param=param_name,
                                current_chain=chain + [step_loc],
                                sanitizers=list(sanitizers),
                                depth=1,
                                results=findings,
                            )

        return findings

    def _trace_into_callee(
        self,
        current_file: Path,
        func_name: str,
        tainted_param: str,
        current_chain: List[CodeLocation],
        sanitizers: List[Sanitizer],
        depth: int,
        results: List[NormalizedFinding],
    ) -> None:
        """Trace tainted parameter through the callee function body and onward."""
        if depth > self.max_depth:
            return

        try:
            source_text = current_file.read_text(encoding="utf-8", errors="replace")
            graph = PythonFlowGraphBuilder(current_file, source_text).build()
            self._graph_cache[str(current_file)] = graph
        except Exception:
            return

        rel_path = str(current_file.relative_to(self.project_root) if current_file.is_relative_to(self.project_root) else current_file)
        tainted_vars: Set[str] = {tainted_param}

        # Step through statements in the callee
        for node in sorted(graph.nodes.values(), key=lambda n: n.location.line_number):
            snippet = node.location.code_snippet

            # Check if this node reads any tainted variable
            if any(tv in node.reads for tv in tainted_vars) or any(f" {tv}" in snippet or f"({tv}" in snippet for tv in tainted_vars):
                # Check for sanitizers
                for san_name, (mitigated_vuln, desc) in CROSS_FILE_SANITIZERS.items():
                    if san_name in snippet:
                        sanitizers.append(
                            Sanitizer(
                                location=CodeLocation(
                                    file_path=rel_path,
                                    line_number=node.location.line_number,
                                    column_number=node.location.column_number,
                                    code_snippet=snippet,
                                ),
                                sanitizer_type=desc,
                                function_name=san_name,
                                mitigates=[mitigated_vuln] if mitigated_vuln else [],
                            )
                        )

                # 1. First check if this node calls ANOTHER cross-file function
                cross_file_called = False
                for cs in self.call_sites:
                    if cs.caller_file == current_file and cs.caller_line == node.location.line_number:
                        for arg in cs.arguments:
                            if any(tv in arg for tv in tainted_vars):
                                callee = cs.callee_name
                                next_file = self._resolve_callee_target(callee, cs.imports)
                                if next_file and next_file.exists() and next_file != current_file:
                                    entry = self.function_index.get(callee)
                                    next_param = entry.params[0] if entry and entry.params else "arg"
                                    step_loc = CodeLocation(
                                        file_path=rel_path,
                                        line_number=cs.caller_line,
                                        column_number=1,
                                        code_snippet=f"Cross-file call: {callee}({', '.join(cs.arguments)})",
                                    )
                                    cross_file_called = True
                                    self._trace_into_callee(
                                        current_file=next_file,
                                        func_name=callee,
                                        tainted_param=next_param,
                                        current_chain=current_chain + [step_loc],
                                        sanitizers=list(sanitizers),
                                        depth=depth + 1,
                                        results=results,
                                    )

                if cross_file_called:
                    continue

                # 2. Check if this node is an assignment (propagates taint to new var)
                if node.writes and node.kind not in ("function_decl", "function_entry", "parameter"):
                    tainted_vars.update(node.writes)
                    if not current_chain or current_chain[-1].line_number != node.location.line_number or current_chain[-1].file_path != rel_path:
                        current_chain.append(
                            CodeLocation(
                                file_path=rel_path,
                                line_number=node.location.line_number,
                                column_number=node.location.column_number,
                                code_snippet=snippet,
                            )
                        )

                # 3. Check if this node is a Sink!
                import re
                for sink_pattern, vuln_type in DEFAULT_SINK_MAPPING.items():
                    pattern_re = r'(?:^|\b|\.)' + re.escape(sink_pattern) + r'\s*\('
                    if re.search(pattern_re, snippet):
                        sink_loc = CodeLocation(
                            file_path=rel_path,
                            line_number=node.location.line_number,
                            column_number=node.location.column_number,
                            code_snippet=snippet,
                        )
                        # We have reached a vulnerable sink across files!
                        finding = self._construct_cross_file_finding(
                            source_loc=current_chain[0],
                            intermediate_steps=current_chain[1:],
                            sink_loc=sink_loc,
                            vuln_type=vuln_type,
                            sanitizers=sanitizers,
                        )
                        results.append(finding)
                        return

    def _resolve_callee_target(self, callee_name: str, imports: Dict[str, Path]) -> Optional[Path]:
        """Resolve a function name to its definition file via imports or function index."""
        target = imports.get(callee_name)
        if target:
            return target
        entry = self.function_index.get(callee_name)
        if entry:
            return Path(entry.file_path)
        return None

    def _construct_cross_file_finding(
        self,
        source_loc: CodeLocation,
        intermediate_steps: List[CodeLocation],
        sink_loc: CodeLocation,
        vuln_type: VulnerabilityType,
        sanitizers: List[Sanitizer],
    ) -> NormalizedFinding:
        """Build a normalized finding for an inter-procedural vulnerability."""
        has_effective_sanitizer = any(s.is_effective_against(vuln_type) for s in sanitizers)
        triage_status = TriageStatus.SUPPRESSED if has_effective_sanitizer else TriageStatus.CONFIRMED
        confidence = 0.92

        files_involved = sorted({source_loc.file_path, sink_loc.file_path, *(s.file_path for s in intermediate_steps)})

        evidence_meta = {
            "cross_file": True,
            "files_involved": files_involved,
            "chain_length": len(intermediate_steps) + 2,
            "path_summary": [
                f"SOURCE [{source_loc.file_path}:{source_loc.line_number}] {source_loc.code_snippet}",
                *(f"FLOW [{s.file_path}:{s.line_number}] {s.code_snippet}" for s in intermediate_steps),
                f"SINK [{sink_loc.file_path}:{sink_loc.line_number}] {sink_loc.code_snippet}",
            ],
        }

        evidence = EvidenceBundle(
            source=source_loc,
            sink=sink_loc,
            intermediate_steps=intermediate_steps,
            sanitizers=sanitizers,
            metadata=evidence_meta,
        )

        message = (
            f"Inter-procedural {vuln_type.value} across {len(files_involved)} files: "
            f"Untrusted input from '{source_loc.file_path}:{source_loc.line_number}' "
            f"propagated across modules to dangerous sink '{sink_loc.file_path}:{sink_loc.line_number}'."
        )

        metadata = {
            "cross_file": True,
            "files_involved": files_involved,
            "cwe": self._get_cwe_for_vuln(vuln_type),
            "owasp": self._get_owasp_for_vuln(vuln_type),
        }

        return NormalizedFinding(
            id=str(uuid.uuid4()),
            tool="aegis-cross-file-dfg",
            language="python",
            rule_id=f"aegis.python.interprocedural.{vuln_type.value.lower()}",
            vulnerability_type=vuln_type.value,
            severity=Severity.CRITICAL if vuln_type in [VulnerabilityType.COMMAND_INJECTION, VulnerabilityType.CODE_INJECTION, VulnerabilityType.SQL_INJECTION] else Severity.HIGH,
            triage_status=triage_status,
            confidence=confidence,
            file_path=sink_loc.file_path,
            line_number=sink_loc.line_number,
            message=message,
            evidence=evidence,
            explanation=(
                f"Aegis Inter-procedural Taint Engine traced untrusted external data flowing across "
                f"{len(files_involved)} files ({' -> '.join(files_involved)}) into an unvalidated sink."
            ),
            recommendation=self._get_recommendation_for_vuln(vuln_type),
            metadata=metadata,
            detected_at=datetime.now(),
        )

    def _get_cwe_for_vuln(self, vuln_type: VulnerabilityType) -> List[str]:
        mapping = {
            VulnerabilityType.COMMAND_INJECTION: ["CWE-78: OS Command Injection"],
            VulnerabilityType.CODE_INJECTION: ["CWE-94: Improper Control of Generation of Code"],
            VulnerabilityType.SQL_INJECTION: ["CWE-89: SQL Injection"],
            VulnerabilityType.PATH_TRAVERSAL: ["CWE-22: Path Traversal"],
            VulnerabilityType.SSRF: ["CWE-918: Server-Side Request Forgery"],
            VulnerabilityType.INSECURE_DESERIALIZATION: ["CWE-502: Deserialization of Untrusted Data"],
        }
        return mapping.get(vuln_type, ["CWE-20: Improper Input Validation"])

    def _get_owasp_for_vuln(self, vuln_type: VulnerabilityType) -> List[str]:
        mapping = {
            VulnerabilityType.COMMAND_INJECTION: ["A03:2021 - Injection"],
            VulnerabilityType.CODE_INJECTION: ["A03:2021 - Injection"],
            VulnerabilityType.SQL_INJECTION: ["A03:2021 - Injection"],
            VulnerabilityType.PATH_TRAVERSAL: ["A01:2021 - Broken Access Control"],
            VulnerabilityType.SSRF: ["A10:2021 - Server-Side Request Forgery (SSRF)"],
            VulnerabilityType.INSECURE_DESERIALIZATION: ["A08:2021 - Software and Data Integrity Failures"],
        }
        return mapping.get(vuln_type, ["A03:2021 - Injection"])

    def _get_recommendation_for_vuln(self, vuln_type: VulnerabilityType) -> str:
        if vuln_type == VulnerabilityType.COMMAND_INJECTION:
            return "Avoid shell commands or sanitize arguments with shlex.quote() before passing across module boundaries."
        if vuln_type == VulnerabilityType.SQL_INJECTION:
            return "Use parameterized queries or an ORM; do not concatenate external arguments into SQL strings."
        return "Validate and sanitize all inputs at service and boundary interfaces."

    def _deduplicate_cross_file_findings(self, findings: List[NormalizedFinding]) -> List[NormalizedFinding]:
        """Deduplicate findings sharing the exact same source and sink."""
        seen = set()
        deduped = []
        for f in findings:
            key = (f.evidence.source.file_path, f.evidence.source.line_number, f.evidence.sink.file_path, f.evidence.sink.line_number, f.vulnerability_type)
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped
