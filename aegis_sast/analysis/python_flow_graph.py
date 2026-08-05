"""Explicit Python CFG/DFG construction and graph-based taint tracing."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from aegis_sast.core.models import (
    CodeLocation,
    DataFlowPath,
    Sanitizer,
    TaintSink,
    TaintSource,
    VulnerabilityType,
)


def _safe_unparse(node: ast.AST) -> str:
    """Best-effort source rendering for one AST node."""
    try:
        return ast.unparse(node)
    except Exception:
        return node.__class__.__name__


def _clone_env(env: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
    """Copy a variable-definition environment."""
    return {name: set(node_ids) for name, node_ids in env.items()}


def _merge_envs(*envs: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
    """Merge branch environments conservatively by union."""
    merged: Dict[str, Set[str]] = {}
    for env in envs:
        for name, node_ids in env.items():
            merged.setdefault(name, set()).update(node_ids)
    return merged


def _word_tokens(text: str) -> List[str]:
    """Split a code snippet into word-like tokens."""
    return re.findall(r"\b\w+\b", text)


class _NameCollector(ast.NodeVisitor):
    """Collect variable names used inside one AST subtree."""

    def __init__(self) -> None:
        self.names: List[str] = []

    def visit_Name(self, node: ast.Name) -> None:  # noqa: N802 - ast visitor API
        self.names.append(node.id)


def _extract_read_names(node: Optional[ast.AST]) -> List[str]:
    """Return variable names read by an AST node."""
    if node is None:
        return []
    collector = _NameCollector()
    collector.visit(node)
    return collector.names


def _extract_write_names(node: ast.AST) -> List[str]:
    """Return variable names written by an assignment target."""
    names: List[str] = []
    if isinstance(node, ast.Name):
        names.append(node.id)
    elif isinstance(node, (ast.Tuple, ast.List)):
        for child in node.elts:
            names.extend(_extract_write_names(child))
    elif isinstance(node, ast.Attribute):
        names.append(_safe_unparse(node))
    elif isinstance(node, ast.Subscript):
        if isinstance(node.value, ast.Name):
            names.append(node.value.id)
        elif isinstance(node.value, ast.Attribute):
            names.append(_safe_unparse(node.value))
    return names


def _extract_call_info(call: ast.Call) -> Tuple[str, List[str]]:
    """Return callee text and rendered argument expressions."""
    callee = _safe_unparse(call.func)
    arguments = [_safe_unparse(arg) for arg in call.args]
    arguments.extend(
        [
            f"{keyword.arg}={_safe_unparse(keyword.value)}"
            if keyword.arg
            else _safe_unparse(keyword.value)
            for keyword in call.keywords
        ]
    )
    return callee, arguments


_MUTATING_METHOD_NAMES = {
    "add",
    "add_section",
    "append",
    "extend",
    "insert",
    "set",
    "setdefault",
    "update",
}


def _extract_mutated_receiver_names(call: ast.Call) -> List[str]:
    """Return receiver names for common mutating method calls."""
    func = call.func
    if not isinstance(func, ast.Attribute):
        return []
    if func.attr not in _MUTATING_METHOD_NAMES:
        return []
    if isinstance(func.value, ast.Name):
        return [func.value.id]
    if isinstance(func.value, ast.Attribute):
        return [_safe_unparse(func.value)]
    return []


@dataclass
class PythonFlowNode:
    """One executable or synthetic node inside the Python flow graph."""

    node_id: str
    kind: str
    label: str
    location: CodeLocation
    scope_name: str
    reads: List[str] = field(default_factory=list)
    writes: List[str] = field(default_factory=list)
    callee_name: Optional[str] = None
    arguments: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PythonFlowEdge:
    """Directed edge in the CFG or DFG."""

    source_id: str
    target_id: str
    kind: str
    label: Optional[str] = None

    def to_dict(self) -> Dict[str, Optional[str]]:
        """Convert the edge to a JSON-friendly dictionary."""
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "kind": self.kind,
            "label": self.label,
        }


@dataclass
class PythonFunctionSummary:
    """Compact taint-oriented summary for one local Python function."""

    function_name: str
    parameter_names: List[str] = field(default_factory=list)
    parameter_node_ids: List[str] = field(default_factory=list)
    return_node_ids: List[str] = field(default_factory=list)
    dependent_parameters: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def returns_tainted_from_parameters(self) -> bool:
        """Return True when at least one parameter can influence a return."""
        return bool(self.dependent_parameters)


@dataclass
class PythonFlowGraph:
    """Combined control-flow/data-flow graph for one Python file."""

    file_path: str
    nodes: Dict[str, PythonFlowNode] = field(default_factory=dict)
    cfg_edges: List[PythonFlowEdge] = field(default_factory=list)
    dfg_edges: List[PythonFlowEdge] = field(default_factory=list)
    line_index: Dict[int, List[str]] = field(default_factory=dict)
    function_entries: Dict[str, str] = field(default_factory=dict)
    function_parameter_nodes: Dict[str, List[str]] = field(default_factory=dict)
    function_return_nodes: Dict[str, List[str]] = field(default_factory=dict)
    function_summaries: Dict[str, PythonFunctionSummary] = field(default_factory=dict)

    def add_node(self, node: PythonFlowNode) -> None:
        """Register one node and index it by source line."""
        self.nodes[node.node_id] = node
        self.line_index.setdefault(node.location.line_number, []).append(node.node_id)

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        kind: str,
        label: Optional[str] = None,
    ) -> None:
        """Append one edge to the CFG or DFG collection."""
        edge = PythonFlowEdge(source_id, target_id, kind, label)
        if kind == "cfg":
            self.cfg_edges.append(edge)
        else:
            self.dfg_edges.append(edge)

    def successors(self, node_id: str, kind: str = "cfg") -> List[str]:
        """Return ordered successor node identifiers for one edge kind."""
        edges = self.cfg_edges if kind == "cfg" else self.dfg_edges
        return [edge.target_id for edge in edges if edge.source_id == node_id]

    def find_preferred_node(
        self,
        line_number: int,
        preferred_kinds: Iterable[str],
    ) -> Optional[PythonFlowNode]:
        """Pick the most relevant node on one source line."""
        preferred = list(preferred_kinds)
        for node_id in self.line_index.get(line_number, []):
            node = self.nodes[node_id]
            if node.kind in preferred:
                return node
        for node_id in self.line_index.get(line_number, []):
            node = self.nodes[node_id]
            if node.kind not in {"function_decl", "function_entry", "parameter", "merge"}:
                return node
        for node_id in self.line_index.get(line_number, []):
            return self.nodes[node_id]
        return None

    def summary(self) -> Dict[str, Any]:
        """Return compact graph statistics for reporting and triage."""
        kinds: Dict[str, int] = {}
        for node in self.nodes.values():
            kinds[node.kind] = kinds.get(node.kind, 0) + 1
        return {
            "node_count": len(self.nodes),
            "cfg_edge_count": len(self.cfg_edges),
            "dfg_edge_count": len(self.dfg_edges),
            "function_summary_count": len(self.function_summaries),
            "kinds": kinds,
        }

    def get_function_summary(self, function_name: str) -> Optional[PythonFunctionSummary]:
        """Return a taint-oriented summary for one local function if available."""
        return self.function_summaries.get(function_name)


@dataclass
class _LoopContext:
    """Builder-side context used to wire break/continue edges."""

    loop_node_id: str
    exit_node_id: str
    break_exit_ids: List[str] = field(default_factory=list)
    continue_exit_ids: List[str] = field(default_factory=list)
    break_envs: List[Dict[str, Set[str]]] = field(default_factory=list)
    continue_envs: List[Dict[str, Set[str]]] = field(default_factory=list)


class PythonFlowGraphBuilder:
    """Build an explicit CFG and DFG from Python source code."""

    def __init__(self, file_path: Path, source_text: str):
        self.file_path = Path(file_path)
        self.source_text = source_text
        self.source_lines = source_text.splitlines()
        self.tree = ast.parse(source_text, filename=str(file_path))
        self.graph = PythonFlowGraph(file_path=str(file_path))
        self._counter = 0
        self._loop_stack: List[_LoopContext] = []

    def build(self) -> PythonFlowGraph:
        """Construct the graph for the current file."""
        self._process_block(self.tree.body, {}, "<module>")
        self._finalize_function_summaries()
        return self.graph

    def _next_id(self, prefix: str = "n") -> str:
        self._counter += 1
        return f"{prefix}{self._counter}"

    def _code_location(self, node: ast.AST, fallback_label: str) -> CodeLocation:
        line_number = max(getattr(node, "lineno", 1), 1)
        column_number = max(getattr(node, "col_offset", 0), 0)
        snippet = (
            self.source_lines[line_number - 1].strip()
            if 0 < line_number <= len(self.source_lines)
            else fallback_label
        )
        return CodeLocation(
            file_path=str(self.file_path),
            line_number=line_number,
            column_number=column_number,
            code_snippet=snippet or fallback_label,
        )

    def _new_node(
        self,
        node: ast.AST,
        kind: str,
        label: str,
        scope_name: str,
        reads: Optional[List[str]] = None,
        writes: Optional[List[str]] = None,
        callee_name: Optional[str] = None,
        arguments: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PythonFlowNode:
        flow_node = PythonFlowNode(
            node_id=self._next_id(),
            kind=kind,
            label=label,
            location=self._code_location(node, label),
            scope_name=scope_name,
            reads=reads or [],
            writes=writes or [],
            callee_name=callee_name,
            arguments=arguments or [],
            metadata=metadata or {},
        )
        self.graph.add_node(flow_node)
        return flow_node

    def _new_merge_node(
        self,
        anchor: ast.AST,
        scope_name: str,
        label: str = "merge",
    ) -> PythonFlowNode:
        return self._new_node(anchor, "merge", label, scope_name)

    def _add_dfg_reads(
        self,
        env: Dict[str, Set[str]],
        reads: Iterable[str],
        target_node_id: str,
    ) -> None:
        for name in reads:
            for source_node_id in env.get(name, set()):
                self.graph.add_edge(source_node_id, target_node_id, "dfg", name)

    def _process_block(
        self,
        statements: List[ast.stmt],
        env: Dict[str, Set[str]],
        scope_name: str,
    ) -> Tuple[Optional[str], List[str], Dict[str, Set[str]]]:
        entry_id: Optional[str] = None
        exit_ids: List[str] = []
        current_env = _clone_env(env)

        for statement in statements:
            stmt_entry, stmt_exits, current_env = self._process_statement(
                statement,
                current_env,
                scope_name,
            )
            if stmt_entry is None:
                continue
            if entry_id is None:
                entry_id = stmt_entry
            for prev_exit in exit_ids:
                self.graph.add_edge(prev_exit, stmt_entry, "cfg", "next")
            exit_ids = list(stmt_exits)
            if entry_id is not None and not exit_ids:
                # Stop walking the block once control flow can no longer fall through.
                break

        return entry_id, exit_ids, current_env

    def _process_statement(
        self,
        statement: ast.stmt,
        env: Dict[str, Set[str]],
        scope_name: str,
    ) -> Tuple[Optional[str], List[str], Dict[str, Set[str]]]:
        if isinstance(statement, ast.FunctionDef):
            return self._process_function(statement, env, scope_name)
        if isinstance(statement, ast.Assign):
            return self._process_assign(statement, env, scope_name)
        if isinstance(statement, ast.AnnAssign):
            return self._process_annotated_assign(statement, env, scope_name)
        if isinstance(statement, ast.AugAssign):
            return self._process_augmented_assign(statement, env, scope_name)
        if isinstance(statement, ast.Expr):
            return self._process_expression(statement, env, scope_name)
        if isinstance(statement, ast.If):
            return self._process_if(statement, env, scope_name)
        if hasattr(ast, "Match") and isinstance(statement, ast.Match):
            return self._process_match(statement, env, scope_name)
        if isinstance(statement, ast.While):
            return self._process_while(statement, env, scope_name)
        if isinstance(statement, ast.For):
            return self._process_for(statement, env, scope_name)
        if isinstance(statement, ast.Try):
            return self._process_try(statement, env, scope_name)
        if isinstance(statement, ast.Return):
            return self._process_return(statement, env, scope_name)
        if isinstance(statement, ast.Raise):
            return self._process_raise(statement, env, scope_name)
        if isinstance(statement, ast.Break):
            return self._process_break(statement, env, scope_name)
        if isinstance(statement, ast.Continue):
            return self._process_continue(statement, env, scope_name)
        if isinstance(statement, ast.With):
            return self._process_with(statement, env, scope_name)

        label = _safe_unparse(statement)
        node = self._new_node(
            statement,
            "statement",
            label,
            scope_name,
            reads=_extract_read_names(statement),
        )
        self._add_dfg_reads(env, node.reads, node.node_id)
        return node.node_id, [node.node_id], _clone_env(env)

    def _process_function(
        self,
        statement: ast.FunctionDef,
        env: Dict[str, Set[str]],
        parent_scope: str,
    ) -> Tuple[Optional[str], List[str], Dict[str, Set[str]]]:
        declaration = self._new_node(
            statement,
            "function_decl",
            f"def {statement.name}(...)",
            parent_scope,
            writes=[statement.name],
        )
        env_after = _clone_env(env)
        env_after[statement.name] = {declaration.node_id}

        entry = self._new_node(
            statement,
            "function_entry",
            f"enter {statement.name}",
            statement.name,
            metadata={"function_name": statement.name},
        )
        self.graph.add_edge(declaration.node_id, entry.node_id, "cfg", "enter")
        self.graph.function_entries[statement.name] = entry.node_id
        self.graph.function_parameter_nodes.setdefault(statement.name, [])
        self.graph.function_return_nodes.setdefault(statement.name, [])

        local_env: Dict[str, Set[str]] = {}
        previous_id = entry.node_id
        parameters = (
            list(statement.args.posonlyargs)
            + list(statement.args.args)
            + list(statement.args.kwonlyargs)
        )
        if statement.args.vararg:
            parameters.append(statement.args.vararg)
        if statement.args.kwarg:
            parameters.append(statement.args.kwarg)

        for parameter in parameters:
            param_node = self._new_node(
                statement,
                "parameter",
                f"param {parameter.arg}",
                statement.name,
                writes=[parameter.arg],
                metadata={
                    "function_name": statement.name,
                    "parameter_name": parameter.arg,
                },
            )
            self.graph.add_edge(previous_id, param_node.node_id, "cfg", "param")
            local_env[parameter.arg] = {param_node.node_id}
            self.graph.function_parameter_nodes[statement.name].append(param_node.node_id)
            previous_id = param_node.node_id

        body_entry, body_exits, _ = self._process_block(
            statement.body,
            local_env,
            statement.name,
        )
        if body_entry:
            self.graph.add_edge(previous_id, body_entry, "cfg", "body")
        elif previous_id != entry.node_id:
            self.graph.add_edge(entry.node_id, previous_id, "cfg", "empty-body")

        return declaration.node_id, [declaration.node_id], env_after

    def _process_assign(
        self,
        statement: ast.Assign,
        env: Dict[str, Set[str]],
        scope_name: str,
    ) -> Tuple[str, List[str], Dict[str, Set[str]]]:
        writes: List[str] = []
        for target in statement.targets:
            writes.extend(_extract_write_names(target))
        reads = _extract_read_names(statement.value)
        label = _safe_unparse(statement)
        callee_name = None
        arguments: List[str] = []
        metadata: Dict[str, Any] = {}
        if isinstance(statement.value, ast.Call):
            callee_name, arguments = _extract_call_info(statement.value)
            metadata["is_call_assignment"] = True
        if any(isinstance(target, ast.Subscript) for target in statement.targets):
            metadata["is_container_write"] = True

        node = self._new_node(
            statement,
            "assignment",
            label,
            scope_name,
            reads=reads,
            writes=writes,
            callee_name=callee_name,
            arguments=arguments,
            metadata=metadata,
        )
        self._add_dfg_reads(env, reads, node.node_id)

        env_after = _clone_env(env)
        for name in writes:
            env_after[name] = {node.node_id}
        return node.node_id, [node.node_id], env_after

    def _process_annotated_assign(
        self,
        statement: ast.AnnAssign,
        env: Dict[str, Set[str]],
        scope_name: str,
    ) -> Tuple[str, List[str], Dict[str, Set[str]]]:
        writes = _extract_write_names(statement.target)
        reads = _extract_read_names(statement.value)
        node = self._new_node(
            statement,
            "assignment",
            _safe_unparse(statement),
            scope_name,
            reads=reads,
            writes=writes,
        )
        self._add_dfg_reads(env, reads, node.node_id)
        env_after = _clone_env(env)
        for name in writes:
            env_after[name] = {node.node_id}
        return node.node_id, [node.node_id], env_after

    def _process_augmented_assign(
        self,
        statement: ast.AugAssign,
        env: Dict[str, Set[str]],
        scope_name: str,
    ) -> Tuple[str, List[str], Dict[str, Set[str]]]:
        writes = _extract_write_names(statement.target)
        reads = _extract_read_names(statement.target) + _extract_read_names(statement.value)
        node = self._new_node(
            statement,
            "assignment",
            _safe_unparse(statement),
            scope_name,
            reads=reads,
            writes=writes,
        )
        self._add_dfg_reads(env, reads, node.node_id)
        env_after = _clone_env(env)
        for name in writes:
            env_after[name] = {node.node_id}
        return node.node_id, [node.node_id], env_after

    def _process_expression(
        self,
        statement: ast.Expr,
        env: Dict[str, Set[str]],
        scope_name: str,
    ) -> Tuple[str, List[str], Dict[str, Set[str]]]:
        reads = _extract_read_names(statement.value)
        callee_name = None
        arguments: List[str] = []
        kind = "expression"
        writes: List[str] = []
        if isinstance(statement.value, ast.Call):
            callee_name, arguments = _extract_call_info(statement.value)
            kind = "call"
            writes = _extract_mutated_receiver_names(statement.value)
        node = self._new_node(
            statement,
            kind,
            _safe_unparse(statement),
            scope_name,
            reads=reads,
            writes=writes,
            callee_name=callee_name,
            arguments=arguments,
        )
        self._add_dfg_reads(env, reads, node.node_id)
        env_after = _clone_env(env)
        for name in writes:
            env_after[name] = {node.node_id}
        return node.node_id, [node.node_id], env_after

    def _process_if(
        self,
        statement: ast.If,
        env: Dict[str, Set[str]],
        scope_name: str,
    ) -> Tuple[str, List[str], Dict[str, Set[str]]]:
        reads = _extract_read_names(statement.test)
        branch_node = self._new_node(
            statement,
            "branch",
            f"if {_safe_unparse(statement.test)}",
            scope_name,
            reads=reads,
        )
        self._add_dfg_reads(env, reads, branch_node.node_id)

        body_entry, body_exits, body_env = self._process_block(
            statement.body,
            _clone_env(env),
            scope_name,
        )
        else_entry, else_exits, else_env = self._process_block(
            statement.orelse,
            _clone_env(env),
            scope_name,
        )

        merge_node = self._new_merge_node(statement, scope_name, "if-merge")

        if body_entry:
            self.graph.add_edge(branch_node.node_id, body_entry, "cfg", "true")
            for exit_id in body_exits:
                self.graph.add_edge(exit_id, merge_node.node_id, "cfg", "merge")
        else:
            self.graph.add_edge(branch_node.node_id, merge_node.node_id, "cfg", "true")

        if else_entry:
            self.graph.add_edge(branch_node.node_id, else_entry, "cfg", "false")
            for exit_id in else_exits:
                self.graph.add_edge(exit_id, merge_node.node_id, "cfg", "merge")
        else:
            self.graph.add_edge(branch_node.node_id, merge_node.node_id, "cfg", "false")
            else_env = _clone_env(env)

        merged_env = _merge_envs(body_env, else_env)
        return branch_node.node_id, [merge_node.node_id], merged_env

    def _process_match(
        self,
        statement: ast.Match,
        env: Dict[str, Set[str]],
        scope_name: str,
    ) -> Tuple[str, List[str], Dict[str, Set[str]]]:
        """Approximate Python ``match`` as a multi-branch merge."""
        reads = _extract_read_names(statement.subject)
        branch_node = self._new_node(
            statement,
            "branch",
            f"match {_safe_unparse(statement.subject)}",
            scope_name,
            reads=reads,
        )
        self._add_dfg_reads(env, reads, branch_node.node_id)

        merge_node = self._new_merge_node(statement, scope_name, "match-merge")
        case_envs: List[Dict[str, Set[str]]] = []

        for index, case in enumerate(statement.cases):
            case_env = _clone_env(env)
            body_entry, body_exits, body_env = self._process_block(
                case.body,
                case_env,
                scope_name,
            )
            edge_label = f"case-{index}"
            if body_entry:
                self.graph.add_edge(branch_node.node_id, body_entry, "cfg", edge_label)
                for exit_id in body_exits:
                    self.graph.add_edge(exit_id, merge_node.node_id, "cfg", "merge")
                case_envs.append(body_env)
            else:
                self.graph.add_edge(branch_node.node_id, merge_node.node_id, "cfg", edge_label)
                case_envs.append(case_env)

        if not statement.cases:
            self.graph.add_edge(branch_node.node_id, merge_node.node_id, "cfg", "no-case")
            case_envs.append(_clone_env(env))

        merged_env = _merge_envs(*case_envs) if case_envs else _clone_env(env)
        return branch_node.node_id, [merge_node.node_id], merged_env

    def _process_while(
        self,
        statement: ast.While,
        env: Dict[str, Set[str]],
        scope_name: str,
    ) -> Tuple[str, List[str], Dict[str, Set[str]]]:
        reads = _extract_read_names(statement.test)
        loop_node = self._new_node(
            statement,
            "loop",
            f"while {_safe_unparse(statement.test)}",
            scope_name,
            reads=reads,
        )
        self._add_dfg_reads(env, reads, loop_node.node_id)

        merge_node = self._new_merge_node(statement, scope_name, "while-exit")
        loop_context = _LoopContext(loop_node.node_id, merge_node.node_id)
        self._loop_stack.append(loop_context)
        body_entry, body_exits, body_env = self._process_block(
            statement.body,
            _clone_env(env),
            scope_name,
        )
        self._loop_stack.pop()

        if body_entry:
            self.graph.add_edge(loop_node.node_id, body_entry, "cfg", "true")
            for exit_id in body_exits:
                self.graph.add_edge(exit_id, loop_node.node_id, "cfg", "back")
        for exit_id in loop_context.continue_exit_ids:
            self.graph.add_edge(exit_id, loop_node.node_id, "cfg", "continue")
        for exit_id in loop_context.break_exit_ids:
            self.graph.add_edge(exit_id, merge_node.node_id, "cfg", "break")

        no_break_env = _merge_envs(env, body_env, *loop_context.continue_envs)
        if statement.orelse:
            else_entry, else_exits, else_env = self._process_block(
                statement.orelse,
                no_break_env,
                scope_name,
            )
            if else_entry:
                self.graph.add_edge(loop_node.node_id, else_entry, "cfg", "false")
                for exit_id in else_exits:
                    self.graph.add_edge(exit_id, merge_node.node_id, "cfg", "merge")
            else:
                self.graph.add_edge(loop_node.node_id, merge_node.node_id, "cfg", "false")
                else_env = no_break_env
        else:
            self.graph.add_edge(loop_node.node_id, merge_node.node_id, "cfg", "false")
            else_env = no_break_env

        merged_env = _merge_envs(
            else_env,
            *loop_context.break_envs,
        )
        return loop_node.node_id, [merge_node.node_id], merged_env

    def _process_for(
        self,
        statement: ast.For,
        env: Dict[str, Set[str]],
        scope_name: str,
    ) -> Tuple[str, List[str], Dict[str, Set[str]]]:
        writes = _extract_write_names(statement.target)
        reads = _extract_read_names(statement.iter)
        loop_node = self._new_node(
            statement,
            "loop",
            f"for {_safe_unparse(statement.target)} in {_safe_unparse(statement.iter)}",
            scope_name,
            reads=reads,
            writes=writes,
        )
        self._add_dfg_reads(env, reads, loop_node.node_id)

        body_env_seed = _clone_env(env)
        for name in writes:
            body_env_seed[name] = {loop_node.node_id}
        merge_node = self._new_merge_node(statement, scope_name, "for-exit")
        loop_context = _LoopContext(loop_node.node_id, merge_node.node_id)
        self._loop_stack.append(loop_context)
        body_entry, body_exits, body_env = self._process_block(
            statement.body,
            body_env_seed,
            scope_name,
        )
        self._loop_stack.pop()

        if body_entry:
            self.graph.add_edge(loop_node.node_id, body_entry, "cfg", "true")
            for exit_id in body_exits:
                self.graph.add_edge(exit_id, loop_node.node_id, "cfg", "back")
        for exit_id in loop_context.continue_exit_ids:
            self.graph.add_edge(exit_id, loop_node.node_id, "cfg", "continue")
        for exit_id in loop_context.break_exit_ids:
            self.graph.add_edge(exit_id, merge_node.node_id, "cfg", "break")

        no_break_env = _merge_envs(env, body_env_seed, body_env, *loop_context.continue_envs)
        if statement.orelse:
            else_entry, else_exits, else_env = self._process_block(
                statement.orelse,
                no_break_env,
                scope_name,
            )
            if else_entry:
                self.graph.add_edge(loop_node.node_id, else_entry, "cfg", "false")
                for exit_id in else_exits:
                    self.graph.add_edge(exit_id, merge_node.node_id, "cfg", "merge")
            else:
                self.graph.add_edge(loop_node.node_id, merge_node.node_id, "cfg", "false")
                else_env = no_break_env
        else:
            self.graph.add_edge(loop_node.node_id, merge_node.node_id, "cfg", "false")
            else_env = no_break_env

        merged_env = _merge_envs(
            else_env,
            *loop_context.break_envs,
        )
        return loop_node.node_id, [merge_node.node_id], merged_env

    def _process_return(
        self,
        statement: ast.Return,
        env: Dict[str, Set[str]],
        scope_name: str,
    ) -> Tuple[str, List[str], Dict[str, Set[str]]]:
        reads = _extract_read_names(statement.value)
        node = self._new_node(
            statement,
            "return",
            _safe_unparse(statement),
            scope_name,
            reads=reads,
            metadata={"function_name": scope_name},
        )
        self._add_dfg_reads(env, reads, node.node_id)
        if scope_name != "<module>":
            self.graph.function_return_nodes.setdefault(scope_name, []).append(node.node_id)
        return node.node_id, [], _clone_env(env)

    def _process_raise(
        self,
        statement: ast.Raise,
        env: Dict[str, Set[str]],
        scope_name: str,
    ) -> Tuple[str, List[str], Dict[str, Set[str]]]:
        reads = _extract_read_names(statement.exc) + _extract_read_names(statement.cause)
        node = self._new_node(
            statement,
            "raise",
            _safe_unparse(statement),
            scope_name,
            reads=reads,
        )
        self._add_dfg_reads(env, reads, node.node_id)
        return node.node_id, [], _clone_env(env)

    def _process_break(
        self,
        statement: ast.Break,
        env: Dict[str, Set[str]],
        scope_name: str,
    ) -> Tuple[str, List[str], Dict[str, Set[str]]]:
        node = self._new_node(
            statement,
            "break",
            "break",
            scope_name,
        )
        if self._loop_stack:
            self._loop_stack[-1].break_exit_ids.append(node.node_id)
            self._loop_stack[-1].break_envs.append(_clone_env(env))
        return node.node_id, [], _clone_env(env)

    def _process_continue(
        self,
        statement: ast.Continue,
        env: Dict[str, Set[str]],
        scope_name: str,
    ) -> Tuple[str, List[str], Dict[str, Set[str]]]:
        node = self._new_node(
            statement,
            "continue",
            "continue",
            scope_name,
        )
        if self._loop_stack:
            self._loop_stack[-1].continue_exit_ids.append(node.node_id)
            self._loop_stack[-1].continue_envs.append(_clone_env(env))
        return node.node_id, [], _clone_env(env)

    def _process_with(
        self,
        statement: ast.With,
        env: Dict[str, Set[str]],
        scope_name: str,
    ) -> Tuple[str, List[str], Dict[str, Set[str]]]:
        reads: List[str] = []
        for item in statement.items:
            reads.extend(_extract_read_names(item.context_expr))
            if item.optional_vars:
                reads.extend(_extract_read_names(item.optional_vars))

        with_node = self._new_node(
            statement,
            "with",
            _safe_unparse(statement),
            scope_name,
            reads=reads,
        )
        self._add_dfg_reads(env, reads, with_node.node_id)

        body_entry, body_exits, body_env = self._process_block(
            statement.body,
            _clone_env(env),
            scope_name,
        )
        if body_entry:
            self.graph.add_edge(with_node.node_id, body_entry, "cfg", "body")
            return with_node.node_id, body_exits, body_env
        return with_node.node_id, [with_node.node_id], _clone_env(env)

    def _process_try(
        self,
        statement: ast.Try,
        env: Dict[str, Set[str]],
        scope_name: str,
    ) -> Tuple[str, List[str], Dict[str, Set[str]]]:
        try_node = self._new_node(
            statement,
            "try",
            "try",
            scope_name,
        )

        body_entry, body_exits, body_env = self._process_block(
            statement.body,
            _clone_env(env),
            scope_name,
        )
        if body_entry:
            self.graph.add_edge(try_node.node_id, body_entry, "cfg", "try")

        fallthrough_exits: List[str] = []
        fallthrough_envs: List[Dict[str, Set[str]]] = []

        if body_exits:
            if statement.orelse:
                else_entry, else_exits, else_env = self._process_block(
                    statement.orelse,
                    _clone_env(body_env),
                    scope_name,
                )
                if else_entry:
                    for exit_id in body_exits:
                        self.graph.add_edge(exit_id, else_entry, "cfg", "orelse")
                    fallthrough_exits.extend(else_exits)
                    if else_exits:
                        fallthrough_envs.append(else_env)
                else:
                    fallthrough_exits.extend(body_exits)
                    fallthrough_envs.append(body_env)
            else:
                fallthrough_exits.extend(body_exits)
                fallthrough_envs.append(body_env)

        for handler in statement.handlers:
            handler_node = self._new_node(
                handler,
                "except",
                f"except {_safe_unparse(handler.type) if handler.type else 'Exception'}",
                scope_name,
                writes=[handler.name] if handler.name else [],
            )
            self.graph.add_edge(try_node.node_id, handler_node.node_id, "cfg", "except")

            handler_env = _clone_env(env)
            if handler.name:
                handler_env[handler.name] = {handler_node.node_id}

            handler_entry, handler_exits, handler_env_after = self._process_block(
                handler.body,
                handler_env,
                scope_name,
            )
            if handler_entry:
                self.graph.add_edge(handler_node.node_id, handler_entry, "cfg", "handler")
                if handler_exits:
                    fallthrough_exits.extend(handler_exits)
                    fallthrough_envs.append(handler_env_after)
            else:
                fallthrough_exits.append(handler_node.node_id)
                fallthrough_envs.append(handler_env)

        if not statement.finalbody:
            merged_env = _merge_envs(*fallthrough_envs) if fallthrough_envs else _clone_env(env)
            return try_node.node_id, fallthrough_exits, merged_env

        final_node = self._new_node(
            statement.finalbody[0],
            "finally",
            "finally",
            scope_name,
        )
        if fallthrough_exits:
            for exit_id in fallthrough_exits:
                self.graph.add_edge(exit_id, final_node.node_id, "cfg", "finally")
        else:
            self.graph.add_edge(try_node.node_id, final_node.node_id, "cfg", "finally")

        final_seed_env = _merge_envs(*fallthrough_envs) if fallthrough_envs else _clone_env(env)
        final_entry, final_exits, final_env = self._process_block(
            statement.finalbody,
            final_seed_env,
            scope_name,
        )
        if final_entry and final_entry != final_node.node_id:
            self.graph.add_edge(final_node.node_id, final_entry, "cfg", "body")
            return try_node.node_id, final_exits, final_env

        return try_node.node_id, [final_node.node_id], final_seed_env

    def _finalize_function_summaries(self) -> None:
        """Derive lightweight taint summaries for local helper functions."""
        reverse_dfg: Dict[str, List[str]] = {}
        for edge in self.graph.dfg_edges:
            reverse_dfg.setdefault(edge.target_id, []).append(edge.source_id)

        for function_name, parameter_node_ids in self.graph.function_parameter_nodes.items():
            return_node_ids = self.graph.function_return_nodes.get(function_name, [])
            parameter_name_by_node: Dict[str, str] = {}
            for node_id in parameter_node_ids:
                node = self.graph.nodes[node_id]
                parameter_name = (
                    node.metadata.get("parameter_name")
                    or (node.writes[0] if node.writes else node.node_id)
                )
                parameter_name_by_node[node_id] = parameter_name

            dependent_parameters: Set[str] = set()
            for return_node_id in return_node_ids:
                dependent_parameters.update(
                    self._collect_parameter_dependencies(
                        return_node_id,
                        parameter_name_by_node,
                        reverse_dfg,
                    )
                )

            parameter_names = [
                parameter_name_by_node[node_id]
                for node_id in parameter_node_ids
                if node_id in parameter_name_by_node
            ]
            ordered_deps = [name for name in parameter_names if name in dependent_parameters]
            ordered_deps.extend(
                sorted(
                    dependent_parameters.difference(ordered_deps),
                )
            )

            self.graph.function_summaries[function_name] = PythonFunctionSummary(
                function_name=function_name,
                parameter_names=parameter_names,
                parameter_node_ids=list(parameter_node_ids),
                return_node_ids=list(return_node_ids),
                dependent_parameters=ordered_deps,
                metadata={
                    "return_count": len(return_node_ids),
                    "parameter_count": len(parameter_node_ids),
                },
            )

    @staticmethod
    def _collect_parameter_dependencies(
        return_node_id: str,
        parameter_name_by_node: Dict[str, str],
        reverse_dfg: Dict[str, List[str]],
    ) -> Set[str]:
        """Walk reverse DFG edges from one return node back to parameter nodes."""
        dependencies: Set[str] = set()
        visited: Set[str] = set()
        stack: List[str] = [return_node_id]

        while stack:
            current = stack.pop()
            for source_id in reverse_dfg.get(current, []):
                if source_id in visited:
                    continue
                visited.add(source_id)
                parameter_name = parameter_name_by_node.get(source_id)
                if parameter_name:
                    dependencies.add(parameter_name)
                stack.append(source_id)

        return dependencies


class PythonDataflowAnalyzer:
    """Trace tainted paths over the explicit Python flow graph."""

    _CALL_ASSIGNMENT_ACCESSOR_METHODS = {
        "b64decode",
        "b64encode",
        "decode",
        "doSomething",
        "encode",
        "get",
        "loads",
        "pop",
        "read",
        "unquote",
        "unquote_plus",
    }

    def __init__(
        self,
        graph: PythonFlowGraph,
        callee_taint_resolver: Optional[
            Callable[[str, List[str], Set[str]], bool]
        ] = None,
    ):
        self.graph = graph
        self.callee_taint_resolver = callee_taint_resolver

    def trace_paths(
        self,
        source: TaintSource,
        sinks: List[TaintSink],
        sanitizers: List[Sanitizer],
        max_nodes: int = 160,
    ) -> List[DataFlowPath]:
        """Trace tainted data from one source to reachable sinks."""
        source_node = self.graph.find_preferred_node(
            source.location.line_number,
            ("assignment", "call", "expression", "branch", "loop", "return"),
        )
        if source_node is None:
            return []

        initial_taint: Set[str] = set()
        if source.variable_name and source.variable_name != "unknown":
            initial_taint.add(source.variable_name)
        initial_taint.update(source_node.writes)

        sanitizers_by_line: Dict[int, List[Sanitizer]] = {}
        for sanitizer in sanitizers:
            sanitizers_by_line.setdefault(
                sanitizer.location.line_number,
                [],
            ).append(sanitizer)

        visited: Set[Tuple[str, Tuple[str, ...], Tuple[str, ...]]] = set()
        stack: List[Tuple[str, Set[str], List[str], List[Sanitizer]]] = [
            (
                source_node.node_id,
                set(initial_taint),
                [source_node.node_id],
                [],
            )
        ]
        paths: List[DataFlowPath] = []
        seen_paths: Set[Tuple[int, Tuple[str, ...]]] = set()

        while stack:
            node_id, tainted_vars, path_node_ids, path_sanitizers = stack.pop()
            state_key = (
                node_id,
                tuple(sorted(tainted_vars)),
                tuple(sorted(self._sanitizer_key(item) for item in path_sanitizers)),
            )
            if state_key in visited or len(path_node_ids) > max_nodes:
                continue
            visited.add(state_key)

            node = self.graph.nodes[node_id]
            current_taint = set(tainted_vars)
            current_sanitizers = list(path_sanitizers)

            self._apply_transfer(
                node,
                current_taint,
                source,
                current_sanitizers,
                sanitizers_by_line.get(node.location.line_number, []),
            )

            for sink in self._matching_sinks(node, sinks):
                if not self._node_reaches_sink(node, sink, current_taint):
                    continue
                path_key = (sink.location.line_number, tuple(path_node_ids))
                if path_key in seen_paths:
                    continue
                seen_paths.add(path_key)
                paths.append(
                    self._build_dataflow_path(
                        source,
                        sink,
                        path_node_ids,
                        current_sanitizers,
                    )
                )

            for successor_id in self.graph.successors(node_id, "cfg"):
                stack.append(
                    (
                        successor_id,
                        set(current_taint),
                        path_node_ids + [successor_id],
                        list(current_sanitizers),
                    )
                )

        return paths

    def _apply_transfer(
        self,
        node: PythonFlowNode,
        tainted_vars: Set[str],
        source: TaintSource,
        path_sanitizers: List[Sanitizer],
        line_sanitizers: List[Sanitizer],
    ) -> None:
        if source.location.line_number == node.location.line_number:
            if source.variable_name and source.variable_name != "unknown":
                tainted_vars.add(source.variable_name)
            tainted_vars.update(node.writes)
            return

        reads = list(node.reads) + list(node.arguments)
        if node.metadata.get("is_call_assignment"):
            read_is_tainted = self._call_assignment_reads_taint_writes(
                node,
                tainted_vars,
            )
        else:
            read_is_tainted = any(
                self._mentions_taint(token, tainted_vars) for token in reads
            )
        callee_returns_tainted = False

        if (
            node.callee_name
            and node.writes
            and node.arguments
            and self.callee_taint_resolver is not None
            and any(self._mentions_taint(token, tainted_vars) for token in node.arguments)
            and self.callee_taint_resolver(
                node.callee_name,
                node.arguments,
                set(tainted_vars),
            )
        ):
            callee_returns_tainted = True

        should_taint_writes = read_is_tainted or callee_returns_tainted
        if node.writes:
            if should_taint_writes:
                tainted_vars.update(node.writes)
            elif self._resets_written_values(node):
                for write_name in node.writes:
                    tainted_vars.discard(write_name)

        if line_sanitizers and any(
            self._mentions_taint(token, tainted_vars) for token in reads
        ):
            known_keys = {self._sanitizer_key(item) for item in path_sanitizers}
            for sanitizer in line_sanitizers:
                sanitizer_key = self._sanitizer_key(sanitizer)
                if sanitizer_key not in known_keys:
                    path_sanitizers.append(sanitizer)
                    known_keys.add(sanitizer_key)

    def _matching_sinks(
        self,
        node: PythonFlowNode,
        sinks: List[TaintSink],
    ) -> List[TaintSink]:
        matches: List[TaintSink] = []
        for sink in sinks:
            if sink.location.line_number != node.location.line_number:
                continue
            if node.callee_name and sink.function_name:
                if sink.function_name in node.callee_name or node.callee_name in sink.function_name:
                    matches.append(sink)
                    continue
            matches.append(sink)
        return matches

    def _node_reaches_sink(
        self,
        node: PythonFlowNode,
        sink: TaintSink,
        tainted_vars: Set[str],
    ) -> bool:
        candidates = self._sink_relevant_candidates(node, sink)
        if not candidates:
            candidates = list(node.arguments) + list(sink.arguments) + [node.label]
        return any(self._mentions_taint(token, tainted_vars) for token in candidates)

    def _sink_relevant_candidates(
        self,
        node: PythonFlowNode,
        sink: TaintSink,
    ) -> List[str]:
        """Return only the sink arguments that matter for taint reachability."""
        arguments = list(node.arguments) or list(sink.arguments)
        if not arguments:
            return [node.label]

        if sink.sink_type in {
            VulnerabilityType.COMMAND_INJECTION,
            VulnerabilityType.CODE_INJECTION,
        }:
            return self._command_injection_candidates(arguments, sink)

        if sink.sink_type == VulnerabilityType.PATH_TRAVERSAL:
            return self._path_traversal_candidates(arguments, sink)

        return arguments + [node.label]

    def _command_injection_candidates(
        self,
        arguments: List[str],
        sink: TaintSink,
    ) -> List[str]:
        """Select the arguments that actually influence command execution."""
        function_name = (sink.function_name or "").strip()

        if function_name in {
            "subprocess.run",
            "subprocess.call",
            "subprocess.Popen",
            "subprocess.check_call",
            "subprocess.check_output",
        }:
            relevant = self._select_positional_or_named_arguments(
                arguments,
                named_arguments={"args"},
                positional_indexes={0},
            )
            return relevant or arguments[:1]

        if function_name in {"os.system", "eval", "exec", "__import__"}:
            relevant = self._select_positional_or_named_arguments(
                arguments,
                named_arguments=set(),
                positional_indexes={0},
            )
            return relevant or arguments[:1]

        return arguments

    def _path_traversal_candidates(
        self,
        arguments: List[str],
        sink: TaintSink,
    ) -> List[str]:
        """Select the path-bearing arguments that influence file access."""
        function_name = (sink.function_name or "").strip()

        if function_name == "open" or function_name.endswith(".open"):
            relevant = self._select_positional_or_named_arguments(
                arguments,
                named_arguments={"file"},
                positional_indexes={0},
            )
            return relevant or arguments[:1]

        return arguments

    def _select_positional_or_named_arguments(
        self,
        arguments: List[str],
        *,
        named_arguments: Set[str],
        positional_indexes: Set[int],
    ) -> List[str]:
        """Pick relevant positional arguments and specific keyword arguments."""
        selected: List[str] = []
        positional_index = 0

        for argument in arguments:
            keyword_name, keyword_value = self._split_keyword_argument(argument)
            if keyword_name is None:
                if positional_index in positional_indexes:
                    selected.append(argument)
                positional_index += 1
                continue
            if keyword_name in named_arguments:
                selected.append(keyword_value)

        return selected

    def _call_assignment_reads_taint_writes(
        self,
        node: PythonFlowNode,
        tainted_vars: Set[str],
    ) -> bool:
        """Propagate taint across common call-assignment transforms and accessors."""
        if any(self._mentions_taint(argument, tainted_vars) for argument in node.arguments):
            summary = self._lookup_local_summary(node.callee_name)
            if summary is not None:
                return summary.returns_tainted_from_parameters
            return True

        receiver = self._callee_receiver(node.callee_name)
        if not receiver or not self._mentions_taint(receiver, tainted_vars):
            return False

        method_name = self._callee_leaf_name(node.callee_name)
        return method_name in self._CALL_ASSIGNMENT_ACCESSOR_METHODS

    def _lookup_local_summary(self, callee_name: Optional[str]):
        """Find a same-file function summary by full or leaf callee name."""
        if not callee_name:
            return None
        candidates = [callee_name]
        leaf_name = self._callee_leaf_name(callee_name)
        if leaf_name not in candidates:
            candidates.append(leaf_name)
        for candidate in candidates:
            summary = self.graph.get_function_summary(candidate)
            if summary is not None:
                return summary
        return None

    @staticmethod
    def _callee_leaf_name(callee_name: Optional[str]) -> str:
        """Return the last callable segment from one rendered callee name."""
        if not callee_name:
            return ""
        tail = callee_name.rsplit(".", 1)[-1]
        match = re.search(r"([A-Za-z_]\w*)\s*$", tail)
        return match.group(1) if match else tail.strip()

    @staticmethod
    def _callee_receiver(callee_name: Optional[str]) -> str:
        """Return the receiver expression from one rendered method call name."""
        if not callee_name or "." not in callee_name:
            return ""
        receiver, _, _ = callee_name.rpartition(".")
        return receiver.strip()

    @staticmethod
    def _split_keyword_argument(argument: str) -> Tuple[str | None, str]:
        """Split a simple keyword argument rendered as ``name=value``."""
        keyword_name, separator, keyword_value = argument.partition("=")
        if separator != "=":
            return None, argument
        if not re.match(r"^[A-Za-z_]\w*$", keyword_name.strip()):
            return None, argument
        return keyword_name.strip(), keyword_value.strip()

    def _build_dataflow_path(
        self,
        source: TaintSource,
        sink: TaintSink,
        path_node_ids: List[str],
        path_sanitizers: List[Sanitizer],
    ) -> DataFlowPath:
        intermediate_steps: List[CodeLocation] = []
        seen_locations: Set[Tuple[str, int, int]] = set()

        for node_id in path_node_ids[1:-1]:
            node = self.graph.nodes[node_id]
            if node.kind in {"merge", "function_decl", "function_entry", "parameter"}:
                continue
            key = (
                node.location.file_path,
                node.location.line_number,
                node.location.column_number,
            )
            if key in seen_locations:
                continue
            seen_locations.add(key)
            intermediate_steps.append(node.location)

        path_node_set = set(path_node_ids)
        involved_dfg_edges = [
            edge.to_dict()
            for edge in self.graph.dfg_edges
            if edge.source_id in path_node_set and edge.target_id in path_node_set
        ]
        local_callee_summaries: List[Dict[str, Any]] = []
        seen_callee_summaries: Set[Tuple[str, int]] = set()
        for node_id in path_node_ids:
            node = self.graph.nodes[node_id]
            if not node.callee_name:
                continue
            function_summary = self.graph.get_function_summary(node.callee_name)
            if function_summary is None:
                continue
            summary_key = (function_summary.function_name, node.location.line_number)
            if summary_key in seen_callee_summaries:
                continue
            seen_callee_summaries.add(summary_key)
            local_callee_summaries.append(
                {
                    "function_name": function_summary.function_name,
                    "call_site_line": node.location.line_number,
                    "dependent_parameters": list(function_summary.dependent_parameters),
                    "return_count": function_summary.metadata.get("return_count", 0),
                }
            )

        return DataFlowPath(
            source=source,
            sink=sink,
            intermediate_steps=intermediate_steps,
            sanitizers=path_sanitizers,
            metadata={
                "analysis_engine": "python-flow-graph-v1",
                "graph_version": "v1.2",
                "graph_summary": self.graph.summary(),
                "cfg_path_node_ids": list(path_node_ids),
                "dfg_path_edges": involved_dfg_edges,
                "local_callee_summaries": local_callee_summaries,
            },
        )

    @staticmethod
    def _mentions_taint(token: str, tainted_vars: Set[str]) -> bool:
        words = _word_tokens(token)
        return any(name in words for name in tainted_vars)

    @staticmethod
    def _sanitizer_key(sanitizer: Sanitizer) -> str:
        return (
            f"{sanitizer.function_name}:"
            f"{sanitizer.location.file_path}:"
            f"{sanitizer.location.line_number}"
        )

    @staticmethod
    def _resets_written_values(node: PythonFlowNode) -> bool:
        if node.metadata.get("is_container_write"):
            return False
        return node.kind in {"assignment", "loop", "parameter"}
