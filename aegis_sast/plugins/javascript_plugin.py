"""
JavaScript/Node.js language plugin for Aegis-SAST.

Implements security analysis for JavaScript/Node.js code using Tree-sitter.
Detects SQL Injection, Command Injection, XSS, SSRF, Path Traversal, and other OWASP Top 10 vulnerabilities.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
import re

import tree_sitter_javascript as tsjavascript
from tree_sitter import Language, Parser, Node

from aegis_sast.core.plugin_interface import ILanguagePlugin
from aegis_sast.core.models import (
    TaintSource,
    TaintSink,
    Sanitizer,
    DataFlowPath,
    CodeLocation,
    VulnerabilityType,
)


class JavaScriptPlugin(ILanguagePlugin):
    """JavaScript/Node.js language analysis plugin using Tree-sitter."""

    def __init__(self):
        self.language = Language(tsjavascript.language())
        self.parser = Parser(self.language)

    def get_language_name(self) -> str:
        return "javascript"

    def get_file_extensions(self) -> List[str]:
        return ["js", "mjs", "cjs"]

    def can_analyze(self, file_path: Path) -> bool:
        return file_path.suffix.lstrip(".") in self.get_file_extensions()

    def parse_file(self, file_path: Path) -> Optional[Any]:
        try:
            with open(file_path, 'rb') as f:
                source_code = f.read()
            return self.parser.parse(source_code)
        except Exception:
            return None

    def extract_sources(self, ast: Any, file_path: Path, rules: Dict[str, Any]) -> List[TaintSource]:
        sources = []
        source_rules = rules.get("sources", [])
        if not source_rules:
            return sources

        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            source_lines = f.readlines()

        def visit_node(node: Node):
            node_text = node.text.decode('utf-8', errors='replace')
            for rule in source_rules:
                pattern = rule.get("pattern", "")
                if pattern in node_text and node.type in ["identifier", "member_expression", "call_expression"]:
                    child_matches = any(pattern in c.text.decode('utf-8', errors='replace') for c in node.children)
                    if not child_matches:
                        var_name = self._extract_variable_name(node)
                        location = CodeLocation(
                            file_path=str(file_path),
                            line_number=node.start_point[0] + 1,
                            column_number=node.start_point[1],
                            code_snippet=source_lines[node.start_point[0]].strip() if node.start_point[0] < len(source_lines) else node_text
                        )
                        sources.append(TaintSource(
                            location=location,
                            source_type=rule.get("type", "UNKNOWN"),
                            variable_name=var_name,
                            pattern=pattern
                        ))
            for child in node.children:
                visit_node(child)

        visit_node(ast.root_node)
        return sources

    def extract_sinks(self, ast: Any, file_path: Path, rules: Dict[str, Any]) -> List[TaintSink]:
        sinks = []
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            source_lines = f.readlines()

        sink_rules = []
        for category in ["sqli", "rce", "path_traversal", "xss", "ssrf", "nosqli", "xxe", "ssti", "deserialization", "open_redirect"]:
            if category in rules.get("sinks", {}):
                sink_rules.extend(rules["sinks"][category])

        def visit_node(node: Node):
            node_text = node.text.decode('utf-8', errors='replace')
            for rule in sink_rules:
                pattern = rule.get("pattern", "")
                if node.type == "call_expression" and pattern in node_text:
                    child_call_matches = any(
                        c.type == "call_expression" and pattern in c.text.decode('utf-8', errors='replace')
                        for c in node.children
                    )
                    if not child_call_matches:
                        func_name = self._extract_function_name(node)
                        arguments = self._extract_arguments(node)
                        location = CodeLocation(
                            file_path=str(file_path),
                            line_number=node.start_point[0] + 1,
                            column_number=node.start_point[1],
                            code_snippet=source_lines[node.start_point[0]].strip() if node.start_point[0] < len(source_lines) else node_text
                        )
                        vuln_type = self._map_vuln_type(rule.get("type", "UNKNOWN"))
                        sinks.append(TaintSink(
                            location=location,
                            sink_type=vuln_type,
                            function_name=func_name,
                            pattern=pattern,
                            arguments=arguments
                        ))
            for child in node.children:
                visit_node(child)

        visit_node(ast.root_node)
        return sinks

    def extract_sanitizers(self, ast: Any, file_path: Path, rules: Dict[str, Any]) -> List[Sanitizer]:
        sanitizers = []
        sanitizer_rules = rules.get("sanitizers", [])
        if not sanitizer_rules:
            return sanitizers

        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            source_lines = f.readlines()

        def visit_node(node: Node):
            node_text = node.text.decode('utf-8', errors='replace')
            for rule in sanitizer_rules:
                pattern = rule.get("pattern", "")
                if pattern in node_text and node.type == "call_expression":
                    func_name = self._extract_function_name(node)
                    location = CodeLocation(
                        file_path=str(file_path),
                        line_number=node.start_point[0] + 1,
                        column_number=node.start_point[1],
                        code_snippet=source_lines[node.start_point[0]].strip() if node.start_point[0] < len(source_lines) else node_text
                    )
                    mitigates = [self._map_vuln_type(v) for v in rule.get("mitigates", [])]
                    sanitizers.append(Sanitizer(
                        location=location,
                        sanitizer_type=rule.get("description", "SANITIZER"),
                        function_name=func_name,
                        mitigates=mitigates
                    ))
            for child in node.children:
                visit_node(child)

        visit_node(ast.root_node)
        return sanitizers

    def track_dataflow(self, ast: Any, file_path: Path, source: TaintSource,
                       sinks: List[TaintSink], sanitizers: List[Sanitizer], max_depth: int = 5) -> List[DataFlowPath]:
        paths = []
        tainted_vars = set()
        if source.variable_name and source.variable_name != "unknown":
            tainted_vars.add(source.variable_name)
        step_map: Dict[str, List[CodeLocation]] = {
            var_name: [] for var_name in tainted_vars
        }
        sanitized_var_map: Dict[str, List[Sanitizer]] = {}
        guarded_var_map: Dict[str, List[CodeLocation]] = {}

        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            source_lines = f.readlines()

        def find_source_node(node):
            if node.start_point[0] + 1 == source.location.line_number:
                if source.pattern in node.text.decode('utf-8', errors='replace'):
                    return node
            for child in node.children:
                res = find_source_node(child)
                if res:
                    return res
            return None

        source_ast_node = find_source_node(ast.root_node)
        scope_node = ast.root_node
        if source_ast_node:
            curr = source_ast_node
            while curr:
                if curr.type in ["function_declaration", "arrow_function", "function_expression", "method_definition"]:
                    scope_node = curr
                    break
                curr = curr.parent

        def node_location(node: Node) -> CodeLocation:
            line_number = node.start_point[0] + 1
            snippet = (
                source_lines[node.start_point[0]].strip()
                if node.start_point[0] < len(source_lines)
                else node.text.decode('utf-8', errors='replace')
            )
            return CodeLocation(
                file_path=str(file_path),
                line_number=line_number,
                column_number=node.start_point[1],
                code_snippet=snippet,
            )

        def register_tainted_var(var_name: str, node: Node, supporting_vars: List[str]):
            normalized = var_name.strip()
            if not normalized or normalized == "unknown":
                return

            inherited_steps: List[CodeLocation] = []
            for supporting in supporting_vars:
                inherited_steps.extend(step_map.get(supporting, []))

            location = node_location(node)
            if location.line_number != source.location.line_number:
                inherited_steps.append(location)

            tainted_vars.add(normalized)
            step_map[normalized] = self._dedupe_locations(inherited_steps)

        def register_sanitized_var(var_name: str, node: Node, supporting_vars: List[str], right_text: str):
            related_sanitizers = self._resolve_path_sanitizers(
                expression_text=right_text,
                supporting_vars=supporting_vars,
                sanitizers=sanitizers,
                sanitized_var_map=sanitized_var_map,
                source_line=source.location.line_number,
                sink_line=node.start_point[0] + 1,
            )
            if related_sanitizers:
                sanitized_var_map[var_name] = related_sanitizers

        def register_guard_clause(node: Node):
            guarded_vars = self._extract_guarded_vars(node, tainted_vars)
            if not guarded_vars:
                return

            location = node_location(node)
            for var_name in guarded_vars:
                existing = guarded_var_map.get(var_name, [])
                guarded_var_map[var_name] = self._dedupe_locations(existing + [location])

        def analyze_assignments(node: Node, depth: int = 0):
            if depth > max_depth:
                return

            # Variable declaration: const x = req.query.id
            if node.type in ["variable_declarator", "assignment_expression"]:
                children = node.children
                left = (
                    node.child_by_field_name("name")
                    or node.child_by_field_name("left")
                    or (children[0] if len(children) > 0 else None)
                )
                right = (
                    node.child_by_field_name("value")
                    or node.child_by_field_name("right")
                    or (children[-1] if len(children) > 2 else None)
                )
                if left and right:
                    left_text = left.text.decode('utf-8', errors='replace').strip()
                    right_text = right.text.decode('utf-8', errors='replace')
                    supporting_vars = self._collect_supporting_vars(right_text, tainted_vars)
                    if self._contains_tainted_reference(right_text, tainted_vars, source):
                        register_tainted_var(
                            left_text,
                            node,
                            supporting_vars,
                        )
                        register_sanitized_var(left_text, node, supporting_vars, right_text)

            elif node.type == "if_statement":
                register_guard_clause(node)

            elif node.type == "call_expression":
                call_text = node.text.decode('utf-8', errors='replace')
                if self._contains_tainted_reference(call_text, tainted_vars, source):
                    for sink in sinks:
                        if sink.location.line_number == node.start_point[0] + 1:
                            supporting_vars = self._collect_supporting_vars(
                                call_text,
                                tainted_vars,
                            )
                            if self._all_vars_guarded(supporting_vars, guarded_var_map):
                                continue

                            intermediate_steps: List[CodeLocation] = []
                            for supporting in supporting_vars:
                                intermediate_steps.extend(step_map.get(supporting, []))

                            guard_steps: List[CodeLocation] = []
                            for supporting in supporting_vars:
                                guard_steps.extend(guarded_var_map.get(supporting, []))

                            path_sanitizers = self._resolve_path_sanitizers(
                                expression_text=call_text,
                                supporting_vars=supporting_vars,
                                sanitizers=sanitizers,
                                sanitized_var_map=sanitized_var_map,
                                source_line=source.location.line_number,
                                sink_line=sink.location.line_number,
                            )
                            paths.append(DataFlowPath(
                                source=source,
                                sink=sink,
                                intermediate_steps=self._dedupe_locations(intermediate_steps),
                                sanitizers=path_sanitizers,
                                metadata={
                                    "language": "javascript",
                                    "analysis_depth": "intra-file",
                                    "evidence_quality": "heuristic-dfg-cfg-lite",
                                    "supporting_variables": supporting_vars,
                                    "framework_hints": self._infer_framework_hints(source, sink),
                                    "guard_locations": [
                                        {
                                            "line": location.line_number,
                                            "snippet": location.code_snippet,
                                        }
                                        for location in self._dedupe_locations(guard_steps)
                                    ],
                                },
                            ))

            for child in node.children:
                analyze_assignments(child, depth + 1)

        analyze_assignments(scope_node)
        return paths

    def _contains_tainted_reference(
        self,
        text: str,
        tainted_vars: set,
        source: TaintSource,
    ) -> bool:
        """Return True when one known tainted reference appears in the text."""
        if source.pattern and source.pattern in text:
            return True

        words = set(re.findall(r'[\w$]+', text))
        return any(tvar in words for tvar in tainted_vars)

    def _collect_supporting_vars(self, text: str, tainted_vars: set) -> List[str]:
        """Collect tainted variables that are directly referenced in one expression."""
        words = set(re.findall(r'[\w$]+', text))
        return sorted(tvar for tvar in tainted_vars if tvar in words)

    def _dedupe_locations(self, locations: List[CodeLocation]) -> List[CodeLocation]:
        """Preserve order while removing duplicate evidence steps."""
        seen = set()
        unique_steps = []
        for location in locations:
            key = (
                location.file_path,
                location.line_number,
                location.column_number,
                location.code_snippet,
            )
            if key in seen:
                continue
            seen.add(key)
            unique_steps.append(location)
        return unique_steps

    def _resolve_path_sanitizers(
        self,
        expression_text: str,
        supporting_vars: List[str],
        sanitizers: List[Sanitizer],
        sanitized_var_map: Dict[str, List[Sanitizer]],
        source_line: int,
        sink_line: int,
    ) -> List[Sanitizer]:
        """Return sanitizers that are reachable for the current path."""
        reachable: List[Sanitizer] = []
        lower_text = expression_text.lower()

        for var_name in supporting_vars:
            reachable.extend(sanitized_var_map.get(var_name, []))

        for sanitizer in sanitizers:
            if sanitizer.location.line_number < source_line:
                continue
            if sanitizer.location.line_number > sink_line:
                continue

            func_name = (sanitizer.function_name or "").lower()
            snippet = (sanitizer.location.code_snippet or "").lower()

            if func_name and func_name in lower_text:
                reachable.append(sanitizer)
                continue
            if snippet and snippet in lower_text:
                reachable.append(sanitizer)

        return self._dedupe_sanitizers(reachable)

    def _dedupe_sanitizers(self, sanitizers: List[Sanitizer]) -> List[Sanitizer]:
        """Preserve order while removing duplicate sanitizer references."""
        seen = set()
        unique = []
        for sanitizer in sanitizers:
            key = (
                sanitizer.function_name,
                sanitizer.location.file_path,
                sanitizer.location.line_number,
                sanitizer.location.column_number,
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(sanitizer)
        return unique

    def _extract_guarded_vars(self, node: Node, tainted_vars: set) -> List[str]:
        """Infer which tainted variables are protected by an early-return guard."""
        if node.type != "if_statement":
            return []
        if not self._contains_return(node):
            return []

        text = node.text.decode('utf-8', errors='replace')
        lower_text = text.lower()
        if not self._looks_like_validation_guard(lower_text):
            return []
        return self._collect_supporting_vars(text, tainted_vars)

    def _contains_return(self, node: Node) -> bool:
        """Check whether one subtree contains an early return."""
        if node.type == "return_statement":
            return True
        return any(self._contains_return(child) for child in node.children)

    def _looks_like_validation_guard(self, lower_text: str) -> bool:
        """Heuristic for guard clauses such as `if (!isSafe(x)) return;`."""
        safe_tokens = ["safe", "valid", "sanitize", "escape", "allow", "whitelist"]
        negation_tokens = ["!", "== false", "!= true", "is false"]
        return any(token in lower_text for token in safe_tokens) and any(
            token in lower_text for token in negation_tokens
        )

    def _all_vars_guarded(
        self,
        supporting_vars: List[str],
        guarded_var_map: Dict[str, List[CodeLocation]],
    ) -> bool:
        """Return True when every variable used at the sink is guarded."""
        return bool(supporting_vars) and all(
            var_name in guarded_var_map for var_name in supporting_vars
        )

    def _infer_framework_hints(
        self,
        source: TaintSource,
        sink: TaintSink,
    ) -> List[str]:
        """Attach lightweight framework hints for downstream triage/reporting."""
        combined = " ".join(
            [
                source.pattern or "",
                source.location.code_snippet or "",
                sink.function_name or "",
                sink.location.code_snippet or "",
            ]
        )
        hints = []
        if "req." in combined or "res." in combined:
            hints.append("express")
        if "document." in combined or "innerHTML" in combined:
            hints.append("dom")
        if "axios." in combined or "fetch(" in combined:
            hints.append("http-client")
        return hints

    def _extract_variable_name(self, node: Node) -> str:
        current = node
        while current:
            if current.type in ["variable_declarator", "assignment_expression"]:
                left = current.children[0]
                return left.text.decode('utf-8', errors='replace').strip()
            if current.type in ["function_declaration", "program"]:
                break
            current = current.parent
        return "unknown"

    def _extract_function_name(self, node: Node) -> str:
        if node.type == "call_expression":
            func = node.child_by_field_name("function")
            if func:
                return func.text.decode('utf-8', errors='replace')
        return "unknown"

    def _extract_arguments(self, node: Node) -> List[str]:
        args = []
        if node.type == "call_expression":
            args_node = node.child_by_field_name("arguments")
            if args_node:
                for child in args_node.children:
                    if child.type not in ["(", ")", ","]:
                        args.append(child.text.decode('utf-8', errors='replace'))
        return args

    def _map_vuln_type(self, type_str: str) -> VulnerabilityType:
        mapping = {
            "SQL_INJECTION": VulnerabilityType.SQL_INJECTION,
            "COMMAND_INJECTION": VulnerabilityType.COMMAND_INJECTION,
            "CODE_INJECTION": VulnerabilityType.CODE_INJECTION,
            "PATH_TRAVERSAL": VulnerabilityType.PATH_TRAVERSAL,
            "XSS": VulnerabilityType.XSS,
            "SSRF": VulnerabilityType.SSRF,
            "NOSQL_INJECTION": VulnerabilityType.NOSQL_INJECTION,
            "XXE": VulnerabilityType.XXE,
            "SSTI": VulnerabilityType.SSTI,
            "INSECURE_DESERIALIZATION": VulnerabilityType.INSECURE_DESERIALIZATION,
            "OPEN_REDIRECT": VulnerabilityType.OPEN_REDIRECT,
            "IDOR": VulnerabilityType.IDOR,
            "MASS_ASSIGNMENT": VulnerabilityType.MASS_ASSIGNMENT,
        }
        return mapping.get(type_str, VulnerabilityType.SQL_INJECTION)
