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
                
                # Check if this node matches the pattern
                if pattern in node_text:
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
        for category in ["sqli", "rce", "path_traversal"]:
            if category in rules.get("sinks", {}):
                sink_rules.extend(rules["sinks"][category])
        
        def visit_node(node: Node):
            node_text = node.text.decode('utf-8')
            
            for rule in sink_rules:
                pattern = rule.get("pattern", "")
                
                if pattern in node_text and node.type == "call":
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
        
        # Track taint propagation through assignments
        def analyze_assignments(node: Node, depth: int = 0):
            if depth > max_depth:
                return
            
            if node.type == "assignment":
                # Check if right side contains tainted variable
                right_text = node.text.decode('utf-8')
                
                if any(tvar in right_text for tvar in tainted_vars):
                    # Left side becomes tainted
                    left_node = node.children[0] if node.children else None
                    if left_node:
                        new_var = left_node.text.decode('utf-8')
                        tainted_vars.add(new_var)
            
            # Handle function calls that might propagate taint
            elif node.type == "call":
                call_text = node.text.decode('utf-8')
                
                # Check if arguments contain tainted variables
                if any(tvar in call_text for tvar in tainted_vars):
                    # Check if this is a sink
                    for sink in sinks:
                        if sink.location.line_number == node.start_point[0] + 1:
                            # Found a dataflow path from source to sink
                            
                            # Check if path goes through sanitizer
                            path_sanitizers = []
                            for san in sanitizers:
                                # Simple check: sanitizer between source and sink
                                if (source.location.line_number < san.location.line_number < sink.location.line_number):
                                    path_sanitizers.append(san)
                            
                            dataflow_path = DataFlowPath(
                                source=source,
                                sink=sink,
                                intermediate_steps=[],  # Simplified: no intermediate tracking
                                sanitizers=path_sanitizers
                            )
                            
                            paths.append(dataflow_path)
            
            # Recurse into children
            for child in node.children:
                analyze_assignments(child, depth + 1)
        
        analyze_assignments(ast.root_node)
        
        return paths
    
    # Helper methods
    
    def _extract_variable_name(self, node: Node) -> str:
        """Extract variable name from assignment or call."""
        # Try to find identifier in parent assignment
        parent = node.parent
        
        if parent and parent.type == "assignment":
            left_child = parent.children[0] if parent.children else None
            if left_child:
                return left_child.text.decode('utf-8')
        
        # Default: use part of the expression
        text = node.text.decode('utf-8')
        if '=' in text:
            return text.split('=')[0].strip()
        
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
        }
        
        return mapping.get(type_str, VulnerabilityType.SQL_INJECTION)
