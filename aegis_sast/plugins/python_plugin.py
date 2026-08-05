"""
Python language plugin for Aegis-SAST.

Implements security analysis for Python code using Tree-sitter.
Detects SQL Injection, Command Injection, and Path Traversal vulnerabilities.
"""

import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
import tree_sitter_python as tspython
from tree_sitter import Language, Parser, Node

from aegis_sast.analysis.python_flow_graph import (
    PythonDataflowAnalyzer,
    PythonFlowGraph,
    PythonFlowGraphBuilder,
)
from aegis_sast.core.plugin_interface import ILanguagePlugin
from aegis_sast.core.models import (
    TaintSource,
    TaintSink,
    Sanitizer,
    DataFlowPath,
    CodeLocation,
    VulnerabilityType,
)


class PythonPlugin(ILanguagePlugin):
    """Python language analysis plugin using Tree-sitter."""
    
    def __init__(self):
        self.language = Language(tspython.language())
        self.parser = Parser(self.language)
        self._flow_graph_cache: Dict[str, Tuple[int, PythonFlowGraph]] = {}
    
    def get_language_name(self) -> str:
        return "python"
    
    def get_file_extensions(self) -> List[str]:
        return ["py", "pyw"]
    
    def can_analyze(self, file_path: Path) -> bool:
        """Check if file has .py or .pyw extension."""
        return file_path.suffix.lstrip(".") in self.get_file_extensions()
    
    def parse_file(self, file_path: Path) -> Optional[Any]:
        """Parse Python file into Tree-sitter AST."""
        try:
            with open(file_path, 'rb') as f:
                source_code = f.read()
            
            tree = self.parser.parse(source_code)
            return tree
        
        except Exception as e:
            # Return None if parsing fails
            return None
    
    def extract_sources(
        self,
        ast: Any,
        file_path: Path,
        rules: Dict[str, Any]
    ) -> List[TaintSource]:
        """Extract taint sources from Python AST."""
        sources = []
        source_rules = rules.get("sources", [])
        
        if not source_rules:
            return sources
        
        # Read source code for snippets
        with open(file_path, 'r', encoding='utf-8') as f:
            source_lines = f.readlines()
        
        # Traverse AST to find source patterns
        def visit_node(node: Node):
            node_text = node.text.decode('utf-8', errors='replace')
            
            for rule in source_rules:
                pattern = rule.get("pattern", "")
                
                # Refine matching: Avoid matching parent nodes if child already matches
                # and only match nodes that likely represent the source (identifier, attribute, call)
                if self._node_matches_pattern(node, pattern) and node.type in ["identifier", "attribute", "call"]:
                    # Check if any child already matches the same pattern (to avoid duplicates from parents)
                    child_matches = False
                    for child in node.children:
                        if self._node_matches_pattern(child, pattern):
                            child_matches = True
                            break
                    
                    if not child_matches:
                        # Get variable name if it's an assignment or call
                        var_name = self._extract_variable_name(node)
                        
                        location = CodeLocation(
                            file_path=str(file_path),
                            line_number=node.start_point[0] + 1,
                            column_number=node.start_point[1],
                            code_snippet=source_lines[node.start_point[0]].strip() if node.start_point[0] < len(source_lines) else node_text
                        )
                        
                        source = TaintSource(
                            location=location,
                            source_type=rule.get("type", "UNKNOWN"),
                            variable_name=var_name,
                            pattern=pattern
                        )
                        
                        sources.append(source)
            
            # Recursively visit children
            for child in node.children:
                visit_node(child)
        
        visit_node(ast.root_node)
        return sources
    
    def extract_sinks(
        self,
        ast: Any,
        file_path: Path,
        rules: Dict[str, Any]
    ) -> List[TaintSink]:
        """Extract taint sinks from Python AST."""
        sinks = []
        
        # Read source code
        with open(file_path, 'r', encoding='utf-8') as f:
            source_lines = f.readlines()
        
        # Flatten sink rules from categories
        sink_rules = []
        for category in ["sqli", "rce", "path_traversal", "xss", "ssrf", "nosqli", "xxe", "idor", "ssti", "deserialization", "mass_assignment", "open_redirect"]:
            if category in rules.get("sinks", {}):
                sink_rules.extend(rules["sinks"][category])
        
        def visit_node(node: Node):
            node_text = node.text.decode('utf-8', errors='replace')
            
            for rule in sink_rules:
                pattern = rule.get("pattern", "")
                
                # Refine matching: only match call nodes directly
                if node.type == "call" and self._node_matches_pattern(node, pattern):
                    # Ensure it's the specific call, not a parent call
                    # Check if any child call already matches
                    child_call_matches = False
                    for child in node.children:
                        if child.type == "call" and self._node_matches_pattern(child, pattern):
                            child_call_matches = True
                            break
                    
                    if not child_call_matches:
                        # Extract function name and arguments
                        func_name = self._extract_function_name(node)
                        arguments = self._extract_arguments(node)
                        vuln_type = self._map_vuln_type(rule.get("type", "UNKNOWN"))
                        if self._should_skip_sink_match(vuln_type, func_name, arguments):
                            continue
                        
                        location = CodeLocation(
                            file_path=str(file_path),
                            line_number=node.start_point[0] + 1,
                            column_number=node.start_point[1],
                            code_snippet=source_lines[node.start_point[0]].strip() if node.start_point[0] < len(source_lines) else node_text
                        )
                        
                        sink = TaintSink(
                            location=location,
                            sink_type=vuln_type,
                            function_name=func_name,
                            pattern=pattern,
                            arguments=arguments
                        )
                        
                        sinks.append(sink)
            
            for child in node.children:
                visit_node(child)
        
        visit_node(ast.root_node)
        return sinks
    
    def extract_sanitizers(
        self,
        ast: Any,
        file_path: Path,
        rules: Dict[str, Any]
    ) -> List[Sanitizer]:
        """Extract sanitizer functions from Python AST."""
        sanitizers = []
        sanitizer_rules = rules.get("sanitizers", [])
        
        if not sanitizer_rules:
            return sanitizers
        
        with open(file_path, 'r', encoding='utf-8') as f:
            source_lines = f.readlines()
        
        def visit_node(node: Node):
            node_text = node.text.decode('utf-8', errors='replace')
            
            for rule in sanitizer_rules:
                pattern = rule.get("pattern", "")
                
                if node.type == "call" and self._node_matches_pattern(node, pattern):
                    func_name = self._extract_function_name(node)
                    
                    location = CodeLocation(
                        file_path=str(file_path),
                        line_number=node.start_point[0] + 1,
                        column_number=node.start_point[1],
                        code_snippet=source_lines[node.start_point[0]].strip() if node.start_point[0] < len(source_lines) else node_text
                    )
                    
                    # Map mitigated types to VulnerabilityType
                    mitigates = [
                        self._map_vuln_type(vtype)
                        for vtype in rule.get("mitigates", [])
                    ]
                    
                    sanitizer = Sanitizer(
                        location=location,
                        sanitizer_type=rule.get("description", "SANITIZER"),
                        function_name=func_name,
                        mitigates=mitigates
                    )
                    
                    sanitizers.append(sanitizer)
            
            for child in node.children:
                visit_node(child)
        
        visit_node(ast.root_node)
        return sanitizers
    
    def track_dataflow(
        self,
        ast: Any,
        file_path: Path,
        source: TaintSource,
        sinks: List[TaintSink],
        sanitizers: List[Sanitizer],
        max_depth: int = 5,
        # ---- Cross-file helpers (injected by VulnerabilityDetector) ----
        call_graph=None,          # aegis_sast.analysis.call_graph.FunctionIndex
        import_resolver=None,     # aegis_sast.analysis.call_graph.ImportResolver
        visited_funcs: Optional[Set[str]] = None,  # recursion guard
    ) -> List[DataFlowPath]:
        """
        Track dataflow from a taint source to potential sinks.

        This implementation uses an explicit Python CFG/DFG graph for the
        current file and keeps the older inter-procedural return-taint check
        for local and imported helper functions.
        """
        if visited_funcs is None:
            visited_funcs = set()

        import_map: Dict[str, Path] = {}
        if import_resolver is not None:
            import_map = import_resolver.resolve_imports(file_path)

        flow_graph = self._get_flow_graph(file_path)

        def _callee_return_is_tainted(
            callee_name: str,
            arguments: List[str],
            tainted_vars: Set[str],
        ) -> bool:
            return self._callee_return_is_tainted(
                file_path=file_path,
                callee_name=callee_name,
                arguments=arguments,
                tainted_vars=tainted_vars,
                call_graph=call_graph,
                import_map=import_map,
                visited_funcs=visited_funcs,
            )

        analyzer = PythonDataflowAnalyzer(
            flow_graph,
            callee_taint_resolver=_callee_return_is_tainted,
        )
        return analyzer.trace_paths(
            source,
            sinks,
            sanitizers,
            max_nodes=max(80, max_depth * 40),
        )

    def _get_flow_graph(self, file_path: Path) -> PythonFlowGraph:
        """Build or reuse the explicit CFG/DFG graph for one Python file."""
        path_key = str(file_path)
        try:
            mtime_ns = file_path.stat().st_mtime_ns
        except OSError:
            mtime_ns = -1

        cached = self._flow_graph_cache.get(path_key)
        if cached and cached[0] == mtime_ns:
            return cached[1]

        source_text = file_path.read_text(encoding="utf-8", errors="replace")
        graph = PythonFlowGraphBuilder(file_path, source_text).build()
        self._flow_graph_cache[path_key] = (mtime_ns, graph)
        return graph

    def _callee_return_is_tainted(
        self,
        file_path: Path,
        callee_name: str,
        arguments: List[str],
        tainted_vars: Set[str],
        call_graph=None,
        import_map: Optional[Dict[str, Path]] = None,
        visited_funcs: Optional[Set[str]] = None,
    ) -> bool:
        """Check whether a local or imported helper may return tainted data."""
        import re as _re

        if visited_funcs is None:
            visited_funcs = set()
        if call_graph is None:
            return False

        callee_candidates = self._callee_name_candidates(callee_name)
        if any(candidate in visited_funcs for candidate in callee_candidates):
            return False

        resolved_callee_name = None
        entry = None
        for candidate in callee_candidates:
            entry = call_graph.get(candidate)
            if entry is not None:
                resolved_callee_name = candidate
                break
        if entry is None or resolved_callee_name is None:
            return False

        callee_file = None
        if import_map:
            for candidate in callee_candidates:
                if candidate in import_map:
                    callee_file = import_map[candidate]
                    break
        if callee_file is None and Path(entry.file_path) == file_path:
            callee_file = Path(entry.file_path)
        elif callee_file is None:
            candidate_file = Path(entry.file_path)
            if candidate_file.exists():
                callee_file = candidate_file

        if callee_file is None or not callee_file.exists():
            return False

        def _words(text: str) -> List[str]:
            return _re.findall(r"\b\w+\b", text)

        callee_graph = None
        callee_summary = None
        try:
            callee_graph = self._get_flow_graph(callee_file)
            for candidate in callee_candidates:
                callee_summary = callee_graph.get_function_summary(candidate)
                if callee_summary is not None:
                    resolved_callee_name = candidate
                    break
        except Exception:
            callee_graph = None
            callee_summary = None

        param_names = list(entry.params)
        if callee_summary is not None and len(callee_summary.parameter_names) > len(param_names):
            param_names = list(callee_summary.parameter_names)
        if (
            "." in callee_name
            and param_names
            and param_names[0] in {"self", "cls"}
            and len(param_names) == len(arguments) + 1
        ):
            param_names = param_names[1:]

        tainted_params: Set[str] = set()
        for index, argument in enumerate(arguments):
            if not any(name in _words(argument) for name in tainted_vars):
                continue
            if index < len(param_names):
                tainted_params.add(param_names[index])
            else:
                tainted_params.update(param_names)

        if not tainted_params:
            return False

        if callee_summary is not None:
            dependent_params = set(callee_summary.dependent_parameters)
            if dependent_params.intersection(tainted_params):
                return True
            return False

        visited_funcs.add(resolved_callee_name)
        try:
            callee_bytes = callee_file.read_bytes()
        except OSError:
            return False

        callee_ast = self.parser.parse(callee_bytes)
        tainted_in_callee = set(tainted_params)

        def _scan_callee(node: Node) -> bool:
            """Return True when a return statement can carry tainted data."""
            nonlocal tainted_in_callee

            if node.type == "function_definition":
                name_node = node.children[0] if node.children else None
                for child in node.children:
                    if child.type == "identifier":
                        name_node = child
                        break
                if (
                    name_node
                    and name_node.text.decode("utf-8", errors="replace") != resolved_callee_name
                ):
                    return False

            if node.type == "assignment":
                lhs = node.children[0] if node.children else None
                rhs = node.children[2] if len(node.children) > 2 else None
                if lhs and rhs:
                    rhs_text = rhs.text.decode("utf-8", errors="replace")
                    if any(name in _words(rhs_text) for name in tainted_in_callee):
                        tainted_in_callee.add(
                            lhs.text.decode("utf-8", errors="replace").strip()
                        )

            if node.type == "return_statement":
                for child in node.children:
                    if child.type not in ("return", "comment"):
                        ret_text = child.text.decode("utf-8", errors="replace")
                        if any(name in _words(ret_text) for name in tainted_in_callee):
                            return True

            for child in node.children:
                if _scan_callee(child):
                    return True
            return False

        try:
            return _scan_callee(callee_ast.root_node)
        finally:
            visited_funcs.discard(resolved_callee_name)

    
    # Helper methods
    
    def _extract_variable_name(self, node: Node) -> str:
        """Extract variable name from assignment by traversing up the AST."""
        current = node
        # Traverse up until we find an assignment or reach the root
        while current:
            if current.type == "assignment":
                # In Python, an assignment node has children: targets, '=', value
                # Or for multiple assignments: target1, target2, ..., '=', value
                left_child = current.children[0]
                return left_child.text.decode('utf-8').strip()
            
            # Stop if we reach a level that shouldn't be part of an assignment expression
            if current.type in ["function_definition", "class_definition", "module"]:
                break
                
            current = current.parent
        
        return "unknown"

    @staticmethod
    def _callee_name_candidates(callee_name: str) -> List[str]:
        """Return full and leaf callee names for method-call resolution."""
        candidates = [callee_name]
        leaf_name = callee_name.rsplit(".", 1)[-1].strip()
        if leaf_name and leaf_name not in candidates:
            candidates.append(leaf_name)
        return candidates

    def _should_skip_sink_match(
        self,
        vuln_type: VulnerabilityType,
        function_name: str,
        arguments: List[str],
    ) -> bool:
        """Skip sink matches that already look like well-parameterized safe calls."""
        return (
            vuln_type == VulnerabilityType.SQL_INJECTION
            and self._is_parameterized_sql_call(function_name, arguments)
        )

    @staticmethod
    def _is_parameterized_sql_call(function_name: str, arguments: List[str]) -> bool:
        """Return True for DB-API execute-style calls with bound parameters."""
        if not function_name.endswith(".execute") and not function_name.endswith(".executemany"):
            return False
        if len(arguments) >= 2:
            return True
        return any(argument.startswith("params=") or argument.startswith("parameters=") for argument in arguments)

    def _node_matches_pattern(self, node: Node, pattern: str) -> bool:
        """Return True when a node matches one reviewable source/sink pattern."""
        normalized_pattern = pattern.strip()
        if not normalized_pattern:
            return False

        if node.type == "call":
            return self._call_matches_pattern(node, normalized_pattern)

        node_text = node.text.decode('utf-8', errors='replace').strip()

        return node_text == normalized_pattern

    def _call_matches_pattern(self, node: Node, pattern: str) -> bool:
        """Match exact callable names and optional argument-shape hints."""
        if node.type != "call":
            return False

        pattern_name, call_constraints = self._parse_call_pattern(pattern)
        if not self._call_name_matches(self._extract_function_name(node), pattern_name):
            return False
        return self._call_satisfies_constraints(node, call_constraints)

    @staticmethod
    def _parse_call_pattern(pattern: str) -> Tuple[str, Dict[str, Any]]:
        """Split one legacy rule pattern into a callable name and argument hints."""
        normalized = pattern.strip()
        if not normalized:
            return "", {}

        if "(" not in normalized:
            return normalized, {}

        call_name, remainder = normalized.split("(", 1)
        call_name = call_name.rstrip()
        args_hint = remainder.rsplit(")", 1)[0]
        constraints: Dict[str, Any] = {}

        if "**" in args_hint:
            constraints["requires_kwargs_splat"] = True

        keyword_equals = {
            match.group(1): match.group(2)
            for match in re.finditer(
                r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)",
                args_hint,
            )
        }
        if keyword_equals:
            constraints["keyword_equals"] = keyword_equals

        return call_name, constraints

    def _call_satisfies_constraints(
        self,
        node: Node,
        constraints: Dict[str, Any],
    ) -> bool:
        """Validate optional argument-shape constraints from one rule pattern."""
        if not constraints:
            return True

        arguments = self._extract_arguments(node)
        normalized_arguments = [self._normalize_argument_text(arg) for arg in arguments]

        if constraints.get("requires_kwargs_splat"):
            if not any(arg.startswith("**") for arg in normalized_arguments):
                return False

        keyword_equals = constraints.get("keyword_equals", {})
        for key, value in keyword_equals.items():
            expected = f"{key}={value}"
            if expected not in normalized_arguments:
                return False

        return True

    @staticmethod
    def _normalize_argument_text(argument: str) -> str:
        """Collapse argument whitespace so keyword hints compare reliably."""
        compact = re.sub(r"\s+", "", argument or "")
        return compact.strip()

    @staticmethod
    def _call_name_matches(function_name: str, pattern_name: str) -> bool:
        """Match a function name directly or by controlled method suffix rules."""
        if not function_name or function_name == "unknown" or not pattern_name:
            return False
        if pattern_name.startswith("."):
            return function_name.endswith(pattern_name)
        if function_name == pattern_name:
            return True
        if "." not in pattern_name and function_name.endswith(f".{pattern_name}"):
            return True
        return False
    
    def _extract_function_name(self, node: Node) -> str:
        """Extract function name from call node."""
        if node.type == "call":
            func_node = node.child_by_field_name("function")
            if func_node:
                return func_node.text.decode('utf-8', errors='replace').strip()
        
        return "unknown"
    
    def _extract_arguments(self, node: Node) -> List[str]:
        """Extract arguments from call node."""
        arguments = []
        
        if node.type == "call":
            args_node = node.child_by_field_name("arguments")
            if args_node:
                for child in args_node.children:
                    if child.type not in ["(", ")", ","]:
                        arguments.append(child.text.decode('utf-8'))
        
        return arguments
    
    def _map_vuln_type(self, type_str: str) -> VulnerabilityType:
        """Map string type to VulnerabilityType enum."""
        mapping = {
            "SQL_INJECTION": VulnerabilityType.SQL_INJECTION,
            "COMMAND_INJECTION": VulnerabilityType.COMMAND_INJECTION,
            "CODE_INJECTION": VulnerabilityType.CODE_INJECTION,
            "PATH_TRAVERSAL": VulnerabilityType.PATH_TRAVERSAL,
            "XPATH_INJECTION": VulnerabilityType.XPATH_INJECTION,
            "LDAP_INJECTION": VulnerabilityType.LDAP_INJECTION,
            "XXE": VulnerabilityType.XXE,
            "SSRF": VulnerabilityType.SSRF,
            "XSS": VulnerabilityType.XSS,
            "NOSQL_INJECTION": VulnerabilityType.NOSQL_INJECTION,
            "IDOR": VulnerabilityType.IDOR,
            "SSTI": VulnerabilityType.SSTI,
            "INSECURE_DESERIALIZATION": VulnerabilityType.INSECURE_DESERIALIZATION,
            "MASS_ASSIGNMENT": VulnerabilityType.MASS_ASSIGNMENT,
            "OPEN_REDIRECT": VulnerabilityType.OPEN_REDIRECT,
        }
        
        return mapping.get(type_str, VulnerabilityType.SQL_INJECTION)
