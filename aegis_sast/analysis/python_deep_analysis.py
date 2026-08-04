"""
Python-specific deep analysis helpers.

This module keeps cross-file indexing and imported-source synthesis separate
from the generic vulnerability detector so the detector can stay focused on
plugin orchestration and report-level coordination.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
import re
from typing import TYPE_CHECKING, Any, Callable, Optional, Sequence

from aegis_sast.core.models import CodeLocation, TaintSource

if TYPE_CHECKING:
    from aegis_sast.analysis.call_graph import FunctionIndex, ImportResolver
else:
    FunctionIndex = Any
    ImportResolver = Any


@dataclass(frozen=True)
class PythonProjectContext:
    """Shared Python-only analysis context reused across files in one scan."""

    project_root: Path
    function_index: FunctionIndex
    import_resolver: ImportResolver


@dataclass
class PythonFileAnalysis:
    """Per-file deep-analysis output that augments normal plugin scanning."""

    synthetic_sources: list[TaintSource]
    function_index: FunctionIndex
    import_resolver: ImportResolver

    def track_kwargs(self) -> dict[str, object]:
        """Build plugin kwargs without leaking Python internals upstream."""
        return {
            "call_graph": self.function_index,
            "import_resolver": self.import_resolver,
            "visited_funcs": set(),
        }


class PythonDeepAnalyzer:
    """Owns Python-only project context and imported-source synthesis."""

    def __init__(
        self,
        function_index_factory: Optional[Callable[[], FunctionIndex]] = None,
        import_resolver_factory: Optional[Callable[[Path], ImportResolver]] = None,
    ) -> None:
        self._function_index_factory = function_index_factory
        self._import_resolver_factory = import_resolver_factory

    def build_context(
        self,
        project_root: Path,
        exclude_dir_names: Optional[Sequence[str]] = None,
        exclude_globs: Optional[Sequence[str]] = None,
    ) -> PythonProjectContext:
        """Build the shared Python project context once for one scan root."""
        function_index_factory, import_resolver_factory = self._resolve_factories()
        function_index = function_index_factory()
        function_index.build(
            project_root,
            exclude_dir_names=exclude_dir_names,
            exclude_globs=exclude_globs,
        )
        return PythonProjectContext(
            project_root=project_root,
            function_index=function_index,
            import_resolver=import_resolver_factory(project_root),
        )

    def prepare_file_analysis(
        self,
        syntax_tree,
        file_path: Path,
        *,
        project_root: Optional[Path] = None,
        context: Optional[PythonProjectContext] = None,
        source_rules: Optional[list[dict]] = None,
    ) -> PythonFileAnalysis:
        """Prepare Python-only analysis state for one file."""
        resolved_context = context or self.build_context(project_root or file_path.parent)
        import_map = resolved_context.import_resolver.resolve_imports(file_path)
        synthetic_sources = self.extract_cross_file_sources(
            syntax_tree=syntax_tree,
            file_path=file_path,
            import_map=import_map,
            function_index=resolved_context.function_index,
            source_rules=source_rules or [],
        )
        return PythonFileAnalysis(
            synthetic_sources=synthetic_sources,
            function_index=resolved_context.function_index,
            import_resolver=resolved_context.import_resolver,
        )

    def extract_cross_file_sources(
        self,
        *,
        syntax_tree,
        file_path: Path,
        import_map: dict[str, Path],
        function_index: FunctionIndex,
        source_rules: list[dict],
    ) -> list[TaintSource]:
        """
        Create synthetic local sources for imported helpers that return tainted
        values so normal intra-file taint tracking can keep working.
        """
        synthetic: list[TaintSource] = []
        callee_rule_cache: dict[tuple[str, str], Optional[dict]] = {}

        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return synthetic

        def find_callee_source_rule(callee_name: str):
            callee_file = import_map.get(callee_name)
            if not callee_file:
                return None

            entry = function_index.get(callee_name) if function_index is not None else None
            if entry is None:
                return None

            try:
                resolved_callee_file = callee_file.resolve()
                resolved_entry_file = Path(entry.file_path).resolve()
            except OSError:
                return None

            if resolved_callee_file != resolved_entry_file:
                return None

            cache_key = (str(resolved_callee_file), callee_name)
            if cache_key not in callee_rule_cache:
                callee_rule_cache[cache_key] = self._resolve_callee_source_rule(
                    callee_file=resolved_callee_file,
                    callee_name=callee_name,
                    source_rules=source_rules,
                )
            return callee_rule_cache[cache_key]

        def walk(node) -> None:
            if node.type == "assignment":
                lhs = node.children[0] if node.children else None
                rhs = node.children[2] if len(node.children) > 2 else None
                if lhs and rhs and rhs.type == "call":
                    func_node = rhs.child_by_field_name("function")
                    if func_node:
                        callee = func_node.text.decode("utf-8", errors="replace").strip()
                        matched_rule = find_callee_source_rule(callee)
                        if matched_rule:
                            variable_name = lhs.text.decode("utf-8", errors="replace").strip()
                            line_number = node.start_point[0]
                            snippet = (
                                lines[line_number].strip()
                                if line_number < len(lines)
                                else ""
                            )
                            synthetic.append(
                                TaintSource(
                                    location=CodeLocation(
                                        file_path=str(file_path),
                                        line_number=line_number + 1,
                                        column_number=node.start_point[1],
                                        code_snippet=snippet,
                                    ),
                                    source_type=matched_rule.get(
                                        "type",
                                        "CROSS_FILE_SOURCE",
                                    ),
                                    variable_name=variable_name,
                                    pattern=matched_rule.get("pattern", f"{callee}("),
                                )
                            )

            for child in node.children:
                walk(child)

        walk(syntax_tree.root_node)
        return synthetic

    def _resolve_callee_source_rule(
        self,
        *,
        callee_file: Path,
        callee_name: str,
        source_rules: list[dict],
    ) -> Optional[dict]:
        """Return the source rule when an imported helper returns tainted data."""
        try:
            source_text = callee_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

        try:
            module = ast.parse(source_text, filename=str(callee_file))
        except SyntaxError:
            return None

        function_node = self._find_named_function(module, callee_name)
        if function_node is None:
            return None

        tainted_assignments: dict[str, dict] = {}
        statements = sorted(
            self._iter_taint_relevant_nodes(function_node),
            key=lambda node: (
                getattr(node, "lineno", 0),
                getattr(node, "col_offset", 0),
            ),
        )

        for node in statements:
            if isinstance(node, ast.Assign):
                source_rule = self._match_source_rule_in_expression(node.value, source_rules)
                if source_rule is None:
                    source_rule = self._propagated_source_rule(node.value, tainted_assignments)
                if source_rule is not None:
                    for target in node.targets:
                        for name in self._extract_assigned_names(target):
                            tainted_assignments.setdefault(name, source_rule)
                continue

            if isinstance(node, ast.AnnAssign):
                source_rule = self._match_source_rule_in_expression(node.value, source_rules)
                if source_rule is None:
                    source_rule = self._propagated_source_rule(node.value, tainted_assignments)
                if source_rule is not None:
                    for name in self._extract_assigned_names(node.target):
                        tainted_assignments.setdefault(name, source_rule)
                continue

            if isinstance(node, ast.AugAssign):
                source_rule = self._propagated_source_rule(node.value, tainted_assignments)
                if source_rule is not None:
                    for name in self._extract_assigned_names(node.target):
                        tainted_assignments.setdefault(name, source_rule)
                continue

            if isinstance(node, ast.Return):
                source_rule = self._match_source_rule_in_expression(node.value, source_rules)
                if source_rule is not None:
                    return source_rule

                source_rule = self._propagated_source_rule(node.value, tainted_assignments)
                if source_rule is not None:
                    return source_rule

        return None

    @staticmethod
    def _find_named_function(module: ast.AST, callee_name: str):
        """Find the first function definition that matches the imported callee."""
        for node in ast.walk(module):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == callee_name:
                return node
        return None

    def _iter_taint_relevant_nodes(self, function_node: ast.AST):
        """Yield assignments and returns while skipping nested scopes."""
        for child in ast.iter_child_nodes(function_node):
            if isinstance(
                child,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
            ):
                continue
            if isinstance(child, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Return)):
                yield child
            yield from self._iter_taint_relevant_nodes(child)

    def _match_source_rule_in_expression(
        self,
        expression: Optional[ast.AST],
        source_rules: list[dict],
    ) -> Optional[dict]:
        """Return the first source rule that directly appears in one expression."""
        if expression is None:
            return None

        for rule in source_rules:
            pattern = rule.get("pattern", "")
            if pattern and self._expression_mentions_source_pattern(expression, pattern):
                return rule
        return None

    def _propagated_source_rule(
        self,
        expression: Optional[ast.AST],
        tainted_assignments: dict[str, dict],
    ) -> Optional[dict]:
        """Return the originating source rule when locals already became tainted."""
        if expression is None or not tainted_assignments:
            return None

        for name in self._extract_read_names(expression):
            source_rule = tainted_assignments.get(name)
            if source_rule is not None:
                return source_rule
        return None

    @staticmethod
    def _extract_assigned_names(target: ast.AST) -> list[str]:
        """Collect variable names written by one assignment target."""
        names: list[str] = []

        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                names.extend(PythonDeepAnalyzer._extract_assigned_names(element))
        elif isinstance(target, ast.Attribute):
            names.append(PythonDeepAnalyzer._safe_unparse_ast(target))

        return names

    @staticmethod
    def _extract_read_names(expression: ast.AST) -> list[str]:
        """Collect variable names read inside one expression."""
        names: list[str] = []
        for node in ast.walk(expression):
            if isinstance(node, ast.Name):
                names.append(node.id)
        return names

    @staticmethod
    def _expression_mentions_source_pattern(expression: ast.AST, pattern: str) -> bool:
        """Check whether an AST expression directly exposes a configured source pattern."""
        normalized = pattern.strip()
        if not normalized:
            return False

        head = normalized.split("(", 1)[0].strip()
        if not head:
            return False

        if isinstance(expression, ast.Call):
            callee_text = PythonDeepAnalyzer._safe_unparse_ast(expression.func)
            if callee_text == head or callee_text.endswith(f".{head}"):
                return True
            if "." in head and callee_text.startswith(f"{head}."):
                return True

        expression_text = PythonDeepAnalyzer._safe_unparse_ast(expression)
        boundary_pattern = re.compile(
            rf"(^|[^A-Za-z0-9_]){re.escape(head)}(?:\(|\.|$)"
        )
        return expression_text == head or bool(boundary_pattern.search(expression_text))

    @staticmethod
    def _safe_unparse_ast(node: ast.AST) -> str:
        """Best-effort AST string rendering for cross-file source heuristics."""
        try:
            return ast.unparse(node)
        except Exception:
            return ""

    def _resolve_factories(
        self,
    ) -> tuple[Callable[[], FunctionIndex], Callable[[Path], ImportResolver]]:
        """Load tree-sitter-backed helpers only when Python deep analysis runs."""
        if self._function_index_factory is None or self._import_resolver_factory is None:
            from aegis_sast.analysis.call_graph import FunctionIndex, ImportResolver

            if self._function_index_factory is None:
                self._function_index_factory = FunctionIndex
            if self._import_resolver_factory is None:
                self._import_resolver_factory = ImportResolver

        return self._function_index_factory, self._import_resolver_factory
