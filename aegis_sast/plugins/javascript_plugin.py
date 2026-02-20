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
        tainted_vars = {source.variable_name}

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

        def analyze_assignments(node: Node, depth: int = 0):
            if depth > max_depth:
                return

            # Variable declaration: const x = req.query.id
            if node.type in ["variable_declarator", "assignment_expression"]:
                children = node.children
                left = children[0] if len(children) > 0 else None
                right = children[-1] if len(children) > 2 else None
                if left and right:
                    left_text = left.text.decode('utf-8', errors='replace').strip()
                    right_text = right.text.decode('utf-8', errors='replace')
                    words = re.findall(r'\b\w+\b', right_text)
                    if any(tvar in words for tvar in tainted_vars):
                        tainted_vars.add(left_text)

            elif node.type == "call_expression":
                call_text = node.text.decode('utf-8', errors='replace')
                words = re.findall(r'\b\w+\b', call_text)
                if any(tvar in words for tvar in tainted_vars):
                    for sink in sinks:
                        if sink.location.line_number == node.start_point[0] + 1:
                            path_sanitizers = [
                                s for s in sanitizers
                                if source.location.line_number < s.location.line_number < sink.location.line_number
                            ]
                            paths.append(DataFlowPath(
                                source=source,
                                sink=sink,
                                intermediate_steps=[],
                                sanitizers=path_sanitizers
                            ))

            for child in node.children:
                analyze_assignments(child, depth + 1)

        analyze_assignments(scope_node)
        return paths

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
