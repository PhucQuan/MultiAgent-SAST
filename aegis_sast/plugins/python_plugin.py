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
        max_depth: int = 5
    ) -> List[DataFlowPath]:
        """
        Track dataflow from source to sinks using inter-procedural taint analysis.
        
        This is a simplified implementation. A production version would need:
        - Symbol table for variable tracking
        - Function call graph
        - Interprocedural analysis across files
        - More sophisticated taint propagation rules
        """
        paths = []
        
        # Build a simple variable tracking map
        tainted_vars = {source.variable_name}
        
        # Read source code
        with open(file_path, 'r', encoding='utf-8') as f:
            source_lines = f.readlines()
        
        # Find the function scope for the source
        def find_source_node(node):
            if node.start_point[0] + 1 == source.location.line_number:
                if source.pattern in node.text.decode('utf-8'):
                    return node
            for child in node.children:
                res = find_source_node(child)
                if res: return res
            return None
            
        source_ast_node = find_source_node(ast.root_node)
        
        # Traverse up to find function scope
        scope_node = ast.root_node
        if source_ast_node:
            curr = source_ast_node
            while curr:
                if curr.type in ["function_definition", "class_definition"]:
                    scope_node = curr
                    break
                curr = curr.parent
        
        # Track taint propagation through assignments
        def analyze_assignments(node: Node, depth: int = 0):
            if depth > max_depth:
                return
            
            # Case 1: Track Variable Re-assignment
            # If `a = request.args.get()`, and later `b = a`, then `b` becomes tainted.
            if node.type == "assignment":
                # Find left side (target variable) and right side (value)
                left_node = node.children[0] if len(node.children) > 0 else None
                right_node = node.children[2] if len(node.children) > 2 else None
                
                if left_node and right_node:
                    left_text = left_node.text.decode('utf-8').strip()
                    right_text = right_node.text.decode('utf-8')
                    
                    # If the right side contains any known tainted variable, the left side is tainted
                    # Better check: split by non-word chars to avoid matching substrings (e.g., 'a' in 'var')
                    import re
                    words = re.findall(r'\b\w+\b', right_text)
                    if any(tvar in words for tvar in tainted_vars) or any(tvar in right_text for tvar in tainted_vars):
                        tainted_vars.add(left_text)
            
            # Case 2: Check if tainted variables reach Sinks
            elif node.type == "call":
                call_text = node.text.decode('utf-8')
                
                # Check if arguments contain tainted variables
                import re
                words = re.findall(r'\b\w+\b', call_text)
                if any(tvar in words for tvar in tainted_vars) or any(tvar in call_text for tvar in tainted_vars):
                    # Check if this node is exactly one of our parsed sinks
                    for sink in sinks:
                        # Match by line number to ensure it's the exact same sink node
                        if sink.location.line_number == node.start_point[0] + 1:
                            
                            # Check if the path goes through a sanitizer
                            path_sanitizers = []
                            for san in sanitizers:
                                # Simplistic effective check: sanitizer is between source and sink
                                if source.location.line_number < san.location.line_number < sink.location.line_number:
                                    path_sanitizers.append(san)
                            
                            dataflow_path = DataFlowPath(
                                source=source,
                                sink=sink,
                                intermediate_steps=[],  # Still simplified, but logic is better
                                sanitizers=path_sanitizers
                            )
                            
                            paths.append(dataflow_path)
            
            # Recurse into children
            for child in node.children:
                analyze_assignments(child, depth + 1)
        
        analyze_assignments(scope_node)
        
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
