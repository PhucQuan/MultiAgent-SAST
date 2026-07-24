"""Dependency-light dataflow tests for JavaScript and Java plugins."""

from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path

from aegis_sast.core.models import (
    CodeLocation,
    Sanitizer,
    TaintSink,
    TaintSource,
    VulnerabilityType,
)


def _install_tree_sitter_stubs() -> None:
    """Install lightweight stubs when tree-sitter packages are unavailable."""
    if "tree_sitter" not in sys.modules:
        tree_sitter = types.ModuleType("tree_sitter")

        class Language:
            def __init__(self, *_args, **_kwargs):
                pass

        class Parser:
            def __init__(self, *_args, **_kwargs):
                pass

            def parse(self, *_args, **_kwargs):
                return None

        class Node:
            pass

        tree_sitter.Language = Language
        tree_sitter.Parser = Parser
        tree_sitter.Node = Node
        sys.modules["tree_sitter"] = tree_sitter

    if "tree_sitter_javascript" not in sys.modules:
        module = types.ModuleType("tree_sitter_javascript")
        module.language = lambda: object()
        sys.modules["tree_sitter_javascript"] = module

    if "tree_sitter_java" not in sys.modules:
        module = types.ModuleType("tree_sitter_java")
        module.language = lambda: object()
        sys.modules["tree_sitter_java"] = module


_install_tree_sitter_stubs()

JavaScriptPlugin = importlib.import_module(
    "aegis_sast.plugins.javascript_plugin"
).JavaScriptPlugin
JavaPlugin = importlib.import_module("aegis_sast.plugins.java_plugin").JavaPlugin


class FakeNode:
    """Tiny tree node that mimics the tree-sitter API used by plugin tests."""

    def __init__(
        self,
        node_type: str,
        text: str,
        line_number: int,
        *,
        column_number: int = 0,
        children: list["FakeNode"] | None = None,
        fields: dict[str, "FakeNode"] | None = None,
    ) -> None:
        self.type = node_type
        self.text = text.encode("utf-8")
        self.start_point = (line_number, column_number)
        self.children = children or []
        self._fields = fields or {}
        self.parent = None

        for child in self.children:
            child.parent = self

    def child_by_field_name(self, name: str):
        return self._fields.get(name)


class FakeTree:
    """Simple wrapper matching the parse tree interface used by plugins."""

    def __init__(self, root_node: FakeNode) -> None:
        self.root_node = root_node


def test_javascript_plugin_tracks_assignment_chain_and_metadata(tmp_path):
    """JavaScript DFG-lite should preserve intermediate evidence and hints."""
    source_file = tmp_path / "handler.js"
    source_file.write_text(
        "\n".join(
            [
                "const userId = req.query.id;",
                'const sql = "SELECT * FROM users WHERE id = " + userId;',
                "db.query(sql);",
            ]
        ),
        encoding="utf-8",
    )

    source_value = FakeNode("member_expression", "req.query.id", 0)
    source_name = FakeNode("identifier", "userId", 0)
    source_decl = FakeNode(
        "variable_declarator",
        "const userId = req.query.id",
        0,
        children=[source_name, source_value],
        fields={"name": source_name, "value": source_value},
    )

    sql_value = FakeNode("binary_expression", '"SELECT" + userId', 1)
    sql_name = FakeNode("identifier", "sql", 1)
    sql_decl = FakeNode(
        "variable_declarator",
        'const sql = "SELECT" + userId',
        1,
        children=[sql_name, sql_value],
        fields={"name": sql_name, "value": sql_value},
    )

    sink_call = FakeNode("call_expression", "db.query(sql)", 2)
    method_scope = FakeNode(
        "function_declaration",
        "function handler(req, res) { ... }",
        0,
        children=[source_decl, sql_decl, sink_call],
    )
    tree = FakeTree(FakeNode("program", "program", 0, children=[method_scope]))

    source = TaintSource(
        location=CodeLocation(str(source_file), 1, 0, "const userId = req.query.id;"),
        source_type="HTTP_PARAM",
        variable_name="userId",
        pattern="req.query",
    )
    sink = TaintSink(
        location=CodeLocation(str(source_file), 3, 0, "db.query(sql);"),
        sink_type=VulnerabilityType.SQL_INJECTION,
        function_name="db.query",
        pattern=".query(",
        arguments=["sql"],
    )

    paths = JavaScriptPlugin().track_dataflow(
        tree,
        source_file,
        source,
        [sink],
        [],
    )

    assert len(paths) == 1
    assert [step.line_number for step in paths[0].intermediate_steps] == [2]
    assert paths[0].metadata["language"] == "javascript"
    assert paths[0].metadata["supporting_variables"] == ["sql"]
    assert "express" in paths[0].metadata["framework_hints"]


def test_javascript_plugin_prunes_guarded_sink_and_tracks_sanitizer(tmp_path):
    """JavaScript CFG-lite should honor guard clauses and relevant sanitizers."""
    source_file = tmp_path / "handler.js"
    source_file.write_text(
        "\n".join(
            [
                "const userId = req.query.id;",
                "if (!isSafe(userId)) { return; }",
                "const safeId = sanitize(userId);",
                "db.query(safeId);",
            ]
        ),
        encoding="utf-8",
    )

    guarded_source_value = FakeNode("member_expression", "req.query.id", 0)
    guarded_source_name = FakeNode("identifier", "userId", 0)
    guarded_source_decl = FakeNode(
        "variable_declarator",
        "const userId = req.query.id",
        0,
        children=[guarded_source_name, guarded_source_value],
        fields={"name": guarded_source_name, "value": guarded_source_value},
    )
    guard_return = FakeNode("return_statement", "return", 1)
    guard_stmt = FakeNode(
        "if_statement",
        "if (!isSafe(userId)) { return; }",
        1,
        children=[guard_return],
    )
    guarded_sink_call = FakeNode("call_expression", "db.query(userId)", 3)
    guarded_sink = TaintSink(
        location=CodeLocation(str(source_file), 4, 0, "db.query(userId);"),
        sink_type=VulnerabilityType.SQL_INJECTION,
        function_name="db.query",
        pattern=".query(",
        arguments=["userId"],
    )
    guarded_scope = FakeNode(
        "function_declaration",
        "function guarded(req, res) { ... }",
        0,
        children=[guarded_source_decl, guard_stmt, guarded_sink_call],
    )

    sanitized_source_value = FakeNode("member_expression", "req.query.id", 0)
    sanitized_source_name = FakeNode("identifier", "userId", 0)
    sanitized_source_decl = FakeNode(
        "variable_declarator",
        "const userId = req.query.id",
        0,
        children=[sanitized_source_name, sanitized_source_value],
        fields={"name": sanitized_source_name, "value": sanitized_source_value},
    )
    safe_value = FakeNode("call_expression", "sanitize(userId)", 2)
    safe_name = FakeNode("identifier", "safeId", 2)
    safe_decl = FakeNode(
        "variable_declarator",
        "const safeId = sanitize(userId)",
        2,
        children=[safe_name, safe_value],
        fields={"name": safe_name, "value": safe_value},
    )
    sanitized_sink_call = FakeNode("call_expression", "db.query(safeId)", 3)
    sanitized_scope = FakeNode(
        "function_declaration",
        "function sanitized(req, res) { ... }",
        0,
        children=[sanitized_source_decl, safe_decl, sanitized_sink_call],
    )

    source = TaintSource(
        location=CodeLocation(str(source_file), 1, 0, "const userId = req.query.id;"),
        source_type="HTTP_PARAM",
        variable_name="userId",
        pattern="req.query",
    )
    sanitized_sink = TaintSink(
        location=CodeLocation(str(source_file), 4, 0, "db.query(safeId);"),
        sink_type=VulnerabilityType.SQL_INJECTION,
        function_name="db.query",
        pattern=".query(",
        arguments=["safeId"],
    )
    sanitizer = Sanitizer(
        location=CodeLocation(str(source_file), 3, 0, "const safeId = sanitize(userId);"),
        sanitizer_type="Input sanitization",
        function_name="sanitize",
        mitigates=[VulnerabilityType.SQL_INJECTION],
    )

    guarded_paths = JavaScriptPlugin().track_dataflow(
        FakeTree(FakeNode("program", "program", 0, children=[guarded_scope])),
        source_file,
        source,
        [guarded_sink],
        [],
    )
    sanitized_paths = JavaScriptPlugin().track_dataflow(
        FakeTree(FakeNode("program", "program", 0, children=[sanitized_scope])),
        source_file,
        source,
        [sanitized_sink],
        [sanitizer],
    )

    assert guarded_paths == []
    assert len(sanitized_paths) == 1
    assert [item.function_name for item in sanitized_paths[0].sanitizers] == ["sanitize"]


def test_java_plugin_tracks_assignment_chain_and_metadata(tmp_path):
    """Java DFG-lite should preserve intermediate evidence and framework hints."""
    source_file = tmp_path / "Controller.java"
    source_file.write_text(
        "\n".join(
            [
                'String input = request.getParameter("id");',
                "String sql = input;",
                "statement.executeQuery(sql);",
            ]
        ),
        encoding="utf-8",
    )

    source_value = FakeNode("method_invocation", 'request.getParameter("id")', 0)
    source_name = FakeNode("identifier", "input", 0)
    source_var = FakeNode(
        "variable_declarator",
        'input = request.getParameter("id")',
        0,
        children=[source_name, source_value],
        fields={"name": source_name, "value": source_value},
    )
    source_decl = FakeNode(
        "local_variable_declaration",
        'String input = request.getParameter("id");',
        0,
        children=[FakeNode("type_identifier", "String", 0), source_var],
    )

    sql_value = FakeNode("identifier", "input", 1)
    sql_name = FakeNode("identifier", "sql", 1)
    sql_var = FakeNode(
        "variable_declarator",
        "sql = input",
        1,
        children=[sql_name, sql_value],
        fields={"name": sql_name, "value": sql_value},
    )
    sql_decl = FakeNode(
        "local_variable_declaration",
        "String sql = input;",
        1,
        children=[FakeNode("type_identifier", "String", 1), sql_var],
    )

    sink_call = FakeNode("method_invocation", "statement.executeQuery(sql)", 2)
    method_scope = FakeNode(
        "method_declaration",
        "public void handler() { ... }",
        0,
        children=[source_decl, sql_decl, sink_call],
    )
    tree = FakeTree(FakeNode("program", "program", 0, children=[method_scope]))

    source = TaintSource(
        location=CodeLocation(
            str(source_file),
            1,
            0,
            'String input = request.getParameter("id");',
        ),
        source_type="HTTP_PARAM",
        variable_name="input",
        pattern="getParameter(",
    )
    sink = TaintSink(
        location=CodeLocation(str(source_file), 3, 0, "statement.executeQuery(sql);"),
        sink_type=VulnerabilityType.SQL_INJECTION,
        function_name="Statement.executeQuery",
        pattern=".executeQuery(",
        arguments=["sql"],
    )

    paths = JavaPlugin().track_dataflow(
        tree,
        source_file,
        source,
        [sink],
        [],
    )

    assert len(paths) == 1
    assert [step.line_number for step in paths[0].intermediate_steps] == [2]
    assert paths[0].metadata["language"] == "java"
    assert paths[0].metadata["supporting_variables"] == ["sql"]
    assert "servlet" in paths[0].metadata["framework_hints"]
    assert "jdbc" in paths[0].metadata["framework_hints"]


def test_java_plugin_prunes_guarded_sink_and_tracks_sanitizer(tmp_path):
    """Java CFG-lite should honor guard clauses and relevant sanitizers."""
    source_file = tmp_path / "Controller.java"
    source_file.write_text(
        "\n".join(
            [
                'String input = request.getParameter("id");',
                "if (!Validator.isSafe(input)) { return; }",
                "String safeSql = sanitize(input);",
                "statement.executeQuery(safeSql);",
            ]
        ),
        encoding="utf-8",
    )

    guarded_source_value = FakeNode("method_invocation", 'request.getParameter("id")', 0)
    guarded_source_name = FakeNode("identifier", "input", 0)
    guarded_source_var = FakeNode(
        "variable_declarator",
        'input = request.getParameter("id")',
        0,
        children=[guarded_source_name, guarded_source_value],
        fields={"name": guarded_source_name, "value": guarded_source_value},
    )
    guarded_source_decl = FakeNode(
        "local_variable_declaration",
        'String input = request.getParameter("id");',
        0,
        children=[FakeNode("type_identifier", "String", 0), guarded_source_var],
    )
    guard_return = FakeNode("return_statement", "return;", 1)
    guard_stmt = FakeNode(
        "if_statement",
        "if (!Validator.isSafe(input)) { return; }",
        1,
        children=[guard_return],
    )
    guarded_sink_call = FakeNode("method_invocation", "statement.executeQuery(input)", 3)
    guarded_sink = TaintSink(
        location=CodeLocation(str(source_file), 4, 0, "statement.executeQuery(input);"),
        sink_type=VulnerabilityType.SQL_INJECTION,
        function_name="Statement.executeQuery",
        pattern=".executeQuery(",
        arguments=["input"],
    )
    guarded_scope = FakeNode(
        "method_declaration",
        "public void guarded() { ... }",
        0,
        children=[guarded_source_decl, guard_stmt, guarded_sink_call],
    )

    sanitized_source_value = FakeNode("method_invocation", 'request.getParameter("id")', 0)
    sanitized_source_name = FakeNode("identifier", "input", 0)
    sanitized_source_var = FakeNode(
        "variable_declarator",
        'input = request.getParameter("id")',
        0,
        children=[sanitized_source_name, sanitized_source_value],
        fields={"name": sanitized_source_name, "value": sanitized_source_value},
    )
    sanitized_source_decl = FakeNode(
        "local_variable_declaration",
        'String input = request.getParameter("id");',
        0,
        children=[FakeNode("type_identifier", "String", 0), sanitized_source_var],
    )
    safe_value = FakeNode("method_invocation", "sanitize(input)", 2)
    safe_name = FakeNode("identifier", "safeSql", 2)
    safe_var = FakeNode(
        "variable_declarator",
        "safeSql = sanitize(input)",
        2,
        children=[safe_name, safe_value],
        fields={"name": safe_name, "value": safe_value},
    )
    safe_decl = FakeNode(
        "local_variable_declaration",
        "String safeSql = sanitize(input);",
        2,
        children=[FakeNode("type_identifier", "String", 2), safe_var],
    )

    sanitized_sink_call = FakeNode("method_invocation", "statement.executeQuery(safeSql)", 3)
    sanitized_scope = FakeNode(
        "method_declaration",
        "public void sanitized() { ... }",
        0,
        children=[sanitized_source_decl, safe_decl, sanitized_sink_call],
    )

    source = TaintSource(
        location=CodeLocation(
            str(source_file),
            1,
            0,
            'String input = request.getParameter("id");',
        ),
        source_type="HTTP_PARAM",
        variable_name="input",
        pattern="getParameter(",
    )
    sanitized_sink = TaintSink(
        location=CodeLocation(str(source_file), 4, 0, "statement.executeQuery(safeSql);"),
        sink_type=VulnerabilityType.SQL_INJECTION,
        function_name="Statement.executeQuery",
        pattern=".executeQuery(",
        arguments=["safeSql"],
    )
    sanitizer = Sanitizer(
        location=CodeLocation(str(source_file), 3, 0, "String safeSql = sanitize(input);"),
        sanitizer_type="Input sanitization",
        function_name="sanitize",
        mitigates=[VulnerabilityType.SQL_INJECTION],
    )

    guarded_paths = JavaPlugin().track_dataflow(
        FakeTree(FakeNode("program", "program", 0, children=[guarded_scope])),
        source_file,
        source,
        [guarded_sink],
        [],
    )
    sanitized_paths = JavaPlugin().track_dataflow(
        FakeTree(FakeNode("program", "program", 0, children=[sanitized_scope])),
        source_file,
        source,
        [sanitized_sink],
        [sanitizer],
    )

    assert guarded_paths == []
    assert len(sanitized_paths) == 1
    assert [item.function_name for item in sanitized_paths[0].sanitizers] == ["sanitize"]
