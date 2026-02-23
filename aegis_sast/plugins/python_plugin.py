"""
Python language plugin for Aegis-SAST.

Implements security analysis for Python code using Tree-sitter.
Detects SQL Injection, Command Injection, and Path Traversal vulnerabilities.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional, Set
import tree_sitter_python as tspython
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


class PythonPlugin(ILanguagePlugin):
    """Python language analysis plugin using Tree-sitter."""
    
    def __init__(self):
        self.language = Language(tspython.language())
        self.parser = Parser(self.language)
    
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
            node_text = node.text.decode('utf-8')
            
            for rule in source_rules:
                pattern = rule.get("pattern", "")
                
                # Refine matching: Avoid matching parent nodes if child already matches
                # and only match nodes that likely represent the source (identifier, attribute, call)
                if pattern in node_text and node.type in ["identifier", "attribute", "call"]:
                    # Check if any child already matches the same pattern (to avoid duplicates from parents)
                    child_matches = False
                    for child in node.  children:
                        if pattern in child.text.decode('utf-8'):
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
            node_text = node.text.decode('utf-8')
            
            for rule in sink_rules:
                pattern = rule.get("pattern", "")
                
                # Refine matching: only match call nodes directly
                if node.type == "call" and pattern in node_text:
                    # Ensure it's the specific call, not a parent call
                    # Check if any child call already matches
                    child_call_matches = False
                    for child in node.children:
                        if child.type == "call" and pattern in child.text.decode('utf-8'):
                            child_call_matches = True
                            break
                    
                    if not child_call_matches:
                        # Extract function name and arguments
                        func_name = self._extract_function_name(node)
                        arguments = self._extract_arguments(node)
                        
                        location = CodeLocation(
                            file_path=str(file_path),
                            line_number=node.start_point[0] + 1,
                            column_number=node.start_point[1],
                            code_snippet=source_lines[node.start_point[0]].strip() if node.start_point[0] < len(source_lines) else node_text
                        )
                        
                        # Map rule type to VulnerabilityType
                        vuln_type = self._map_vuln_type(rule.get("type", "UNKNOWN"))
                        
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
            node_text = node.text.decode('utf-8')
            
            for rule in sanitizer_rules:
                pattern = rule.get("pattern", "")
                
                if pattern in node_text and node.type == "call":
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

        Level-B inter-procedural support:
          - When a tainted variable is passed to a locally-imported function
            we resolve that function to its definition file, parse it and
            check whether its return value propagates the taint.
          - Recursion is prevented via *visited_funcs*.
          - Multiple return paths: conservative — if ANY path taints the
            return variable, the whole call is treated as tainted.
        """
        import re as _re

        paths: List[DataFlowPath] = []
        tainted_vars: Set[str] = {source.variable_name}

        if visited_funcs is None:
            visited_funcs = set()

        # Build import map for *this* file so we can resolve callees.
        import_map: Dict[str, Path] = {}
        if import_resolver is not None:
            import_map = import_resolver.resolve_imports(file_path)

        # Read source lines for snippet extraction
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            source_lines = fh.readlines()

        # ------------------------------------------------------------------
        # Helpers
        # ------------------------------------------------------------------

        def _words(text: str) -> List[str]:
            return _re.findall(r"\b\w+\b", text)

        def _is_tainted(text: str) -> bool:
            words = _words(text)
            return any(tv in words for tv in tainted_vars)

        def _find_source_node(node: Node) -> Optional[Node]:
            if node.start_point[0] + 1 == source.location.line_number:
                if source.pattern in node.text.decode("utf-8", errors="replace"):
                    return node
            for child in node.children:
                res = _find_source_node(child)
                if res:
                    return res
            return None

        def _find_scope(start: Optional[Node]) -> Node:
            if start is None:
                return ast.root_node
            curr: Optional[Node] = start
            while curr:
                if curr.type in ("function_definition", "class_definition"):
                    return curr
                curr = curr.parent
            return ast.root_node

        def _is_callee_return_tainted(
            callee_name: str, caller_args: str
        ) -> bool:
            """
            Resolve *callee_name* through the import map, parse its file,
            and determine whether the callee taints its return value when
            given tainted arguments.
            """
            if callee_name in visited_funcs:
                return False  # recursion guard
            if callee_name not in import_map:
                return False
            callee_file = import_map[callee_name]

            # Also need the FunctionIndex entry to know parameter names
            if call_graph is None:
                return False
            entry = call_graph.get(callee_name)
            if entry is None:
                return False

            visited_funcs.add(callee_name)

            # Map caller tainted variables → callee parameter names
            callee_tainted: Set[str] = set()
            arg_words = _words(caller_args)
            for idx, param in enumerate(entry.params):
                # If ANY tainted var appears in the call args, mark the
                # corresponding parameter as tainted (positional heuristic).
                if any(tv in arg_words for tv in tainted_vars):
                    callee_tainted.add(param)

            if not callee_tainted:
                return False

            # Parse the callee file and check return vars
            try:
                callee_bytes = callee_file.read_bytes()
            except OSError:
                return False

            callee_ast = self.parser.parse(callee_bytes)

            try:
                with open(callee_file, "r", encoding="utf-8", errors="replace") as fh:
                    callee_lines = fh.readlines()
            except OSError:
                return False

            # Run a lightweight intra-procedural analysis inside the callee
            # to propagate taint through assignments and check returns.
            tainted_in_callee = set(callee_tainted)

            def _scan_callee(node: Node) -> bool:
                """Return True if any return statement is tainted."""
                nonlocal tainted_in_callee

                # We only care about the function body that matches entry.name
                if node.type == "function_definition":
                    name_node = node.children[0] if node.children else None
                    for child in node.children:
                        if child.type == "identifier":
                            name_node = child
                            break
                    if name_node and name_node.text.decode("utf-8", errors="replace") != callee_name:
                        return False  # different function, skip

                if node.type == "assignment":
                    lhs = node.children[0] if node.children else None
                    rhs = node.children[2] if len(node.children) > 2 else None
                    if lhs and rhs:
                        rhs_text = rhs.text.decode("utf-8", errors="replace")
                        if any(tv in _words(rhs_text) for tv in tainted_in_callee):
                            tainted_in_callee.add(
                                lhs.text.decode("utf-8", errors="replace").strip()
                            )

                if node.type == "return_statement":
                    for child in node.children:
                        if child.type not in ("return", "comment"):
                            ret_text = child.text.decode("utf-8", errors="replace")
                            if any(tv in _words(ret_text) for tv in tainted_in_callee):
                                return True  # conservative: tainted return

                for child in node.children:
                    if _scan_callee(child):
                        return True
                return False

            return _scan_callee(callee_ast.root_node)

        # ------------------------------------------------------------------
        # Main analysis loop
        # ------------------------------------------------------------------

        source_ast_node = _find_source_node(ast.root_node)
        scope_node = _find_scope(source_ast_node)

        def analyze_node(node: Node, depth: int = 0) -> None:
            if depth > max_depth:
                return

            # ---- Assignment: propagate taint ----
            if node.type == "assignment":
                left_node = node.children[0] if node.children else None
                right_node = node.children[2] if len(node.children) > 2 else None

                if left_node and right_node:
                    left_text = left_node.text.decode("utf-8", errors="replace").strip()
                    right_text = right_node.text.decode("utf-8", errors="replace")

                    # Direct alias propagation  (b = a, c = b …)
                    if _is_tainted(right_text):
                        tainted_vars.add(left_text)
                    else:
                        # Cross-file: lhs = imported_func(tainted_arg)
                        if right_node.type == "call":
                            func_node = right_node.child_by_field_name("function")
                            args_node = right_node.child_by_field_name("arguments")
                            if func_node and args_node:
                                callee_name = func_node.text.decode("utf-8", errors="replace").strip()
                                args_text = args_node.text.decode("utf-8", errors="replace")
                                if _is_tainted(args_text) and _is_callee_return_tainted(
                                    callee_name, args_text
                                ):
                                    tainted_vars.add(left_text)

            # ---- Call: check if tainted vars reach a known sink ----
            elif node.type == "call":
                call_text = node.text.decode("utf-8", errors="replace")

                if _is_tainted(call_text):
                    for sink in sinks:
                        if sink.location.line_number == node.start_point[0] + 1:
                            path_sanitizers = [
                                s for s in sanitizers
                                if source.location.line_number
                                < s.location.line_number
                                < sink.location.line_number
                            ]
                            paths.append(
                                DataFlowPath(
                                    source=source,
                                    sink=sink,
                                    intermediate_steps=[],
                                    sanitizers=path_sanitizers,
                                )
                            )

            for child in node.children:
                analyze_node(child, depth + 1)

        analyze_node(scope_node)
        return paths

    
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
    
    def _extract_function_name(self, node: Node) -> str:
        """Extract function name from call node."""
        if node.type == "call":
            func_node = node.child_by_field_name("function")
            if func_node:
                return func_node.text.decode('utf-8')
        
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
