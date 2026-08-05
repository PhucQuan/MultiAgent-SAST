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
    """Install lightweight stubs only for packages that are truly unavailable."""
    try:
        import tree_sitter  # noqa: F401
    except ImportError:
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

    try:
        import tree_sitter_javascript  # noqa: F401
    except ImportError:
        module = types.ModuleType("tree_sitter_javascript")
        module.language = lambda: object()
        sys.modules["tree_sitter_javascript"] = module

    try:
        import tree_sitter_java  # noqa: F401
    except ImportError:
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


def test_java_plugin_extract_sinks_matches_constructor_patterns(tmp_path):
    """Java custom-rule sinks should also match constructor-style object creation."""
    source_file = tmp_path / "Controller.java"
    source_file.write_text(
        "new java.io.FileInputStream(path);\n",
        encoding="utf-8",
    )

    type_node = FakeNode("type_identifier", "java.io.FileInputStream", 0)
    argument_node = FakeNode("identifier", "path", 0)
    arguments = FakeNode(
        "argument_list",
        "(path)",
        0,
        children=[
            FakeNode("(", "(", 0),
            argument_node,
            FakeNode(")", ")", 0),
        ],
    )
    constructor = FakeNode(
        "object_creation_expression",
        "new java.io.FileInputStream(path)",
        0,
        children=[type_node, arguments],
        fields={"type": type_node, "arguments": arguments},
    )
    tree = FakeTree(FakeNode("program", "program", 0, children=[constructor]))

    rules = {
        "sinks": {
            "path_traversal": [
                {
                    "pattern": "new java.io.FileInputStream(",
                    "type": "PATH_TRAVERSAL",
                    "severity": "CRITICAL",
                    "description": "Imported constructor sink",
                }
            ]
        }
    }

    sinks = JavaPlugin().extract_sinks(tree, source_file, rules)

    assert len(sinks) == 1
    assert sinks[0].function_name == "java.io.FileInputStream"
    assert sinks[0].arguments == ["path"]


def test_java_plugin_tracks_tainted_collection_into_command_sink(tmp_path):
    """Java dataflow should carry taint through list-building before ProcessBuilder.command."""
    source_file = tmp_path / "Controller.java"
    source_file.write_text(
        "\n".join(
            [
                'String param = request.getHeader("cmd");',
                "List<String> argList = new ArrayList<>();",
                'argList.add("echo " + param);',
                "pb.command(argList);",
            ]
        ),
        encoding="utf-8",
    )

    source_value = FakeNode("method_invocation", 'request.getHeader("cmd")', 0)
    source_name = FakeNode("identifier", "param", 0)
    source_var = FakeNode(
        "variable_declarator",
        'param = request.getHeader("cmd")',
        0,
        children=[source_name, source_value],
        fields={"name": source_name, "value": source_value},
    )
    source_decl = FakeNode(
        "local_variable_declaration",
        'String param = request.getHeader("cmd");',
        0,
        children=[FakeNode("type_identifier", "String", 0), source_var],
    )

    list_value = FakeNode("object_creation_expression", "new ArrayList<>()", 1)
    list_name = FakeNode("identifier", "argList", 1)
    list_var = FakeNode(
        "variable_declarator",
        "argList = new ArrayList<>()",
        1,
        children=[list_name, list_value],
        fields={"name": list_name, "value": list_value},
    )
    list_decl = FakeNode(
        "local_variable_declaration",
        "List<String> argList = new ArrayList<>();",
        1,
        children=[FakeNode("type_identifier", "List", 1), list_var],
    )

    add_name = FakeNode("identifier", "add", 2)
    add_target = FakeNode("identifier", "argList", 2)
    add_arg = FakeNode('binary_expression', '"echo " + param', 2)
    add_args = FakeNode(
        "argument_list",
        '("echo " + param)',
        2,
        children=[FakeNode("(", "(", 2), add_arg, FakeNode(")", ")", 2)],
    )
    add_call = FakeNode(
        "method_invocation",
        'argList.add("echo " + param)',
        2,
        children=[add_target, add_name, add_args],
        fields={"object": add_target, "name": add_name, "arguments": add_args},
    )

    command_name = FakeNode("identifier", "command", 3)
    command_target = FakeNode("identifier", "pb", 3)
    command_arg = FakeNode("identifier", "argList", 3)
    command_args = FakeNode(
        "argument_list",
        "(argList)",
        3,
        children=[FakeNode("(", "(", 3), command_arg, FakeNode(")", ")", 3)],
    )
    command_call = FakeNode(
        "method_invocation",
        "pb.command(argList)",
        3,
        children=[command_target, command_name, command_args],
        fields={"object": command_target, "name": command_name, "arguments": command_args},
    )

    method_scope = FakeNode(
        "method_declaration",
        "public void handler() { ... }",
        0,
        children=[source_decl, list_decl, add_call, command_call],
    )
    tree = FakeTree(FakeNode("program", "program", 0, children=[method_scope]))

    source = TaintSource(
        location=CodeLocation(str(source_file), 1, 0, 'String param = request.getHeader("cmd");'),
        source_type="HTTP_HEADER",
        variable_name="param",
        pattern="getHeader(",
    )
    sink = TaintSink(
        location=CodeLocation(str(source_file), 4, 0, "pb.command(argList);"),
        sink_type=VulnerabilityType.COMMAND_INJECTION,
        function_name="command",
        pattern=".command(",
        arguments=["argList"],
    )

    paths = JavaPlugin().track_dataflow(
        tree,
        source_file,
        source,
        [sink],
        [],
    )

    assert len(paths) == 1
    assert paths[0].metadata["supporting_variables"] == ["argList"]
    assert [step.line_number for step in paths[0].intermediate_steps] == [3]


def test_java_plugin_tracks_tainted_sql_into_prepare_call_sink(tmp_path):
    """Java dataflow should reach nested `prepareCall(sql)` sinks inside local declarations."""
    source_file = tmp_path / "Controller.java"
    source_file.write_text(
        "\n".join(
            [
                'String param = request.getHeader("id");',
                'String sql = "{call " + param + "}";',
                "CallableStatement statement = connection.prepareCall(sql);",
            ]
        ),
        encoding="utf-8",
    )

    source_value = FakeNode("method_invocation", 'request.getHeader("id")', 0)
    source_name = FakeNode("identifier", "param", 0)
    source_var = FakeNode(
        "variable_declarator",
        'param = request.getHeader("id")',
        0,
        children=[source_name, source_value],
        fields={"name": source_name, "value": source_value},
    )
    source_decl = FakeNode(
        "local_variable_declaration",
        'String param = request.getHeader("id");',
        0,
        children=[FakeNode("type_identifier", "String", 0), source_var],
    )

    sql_value = FakeNode('binary_expression', '"{call " + param + "}"', 1)
    sql_name = FakeNode("identifier", "sql", 1)
    sql_var = FakeNode(
        "variable_declarator",
        'sql = "{call " + param + "}"',
        1,
        children=[sql_name, sql_value],
        fields={"name": sql_name, "value": sql_value},
    )
    sql_decl = FakeNode(
        "local_variable_declaration",
        'String sql = "{call " + param + "}";',
        1,
        children=[FakeNode("type_identifier", "String", 1), sql_var],
    )

    call_name = FakeNode("identifier", "prepareCall", 2)
    call_target = FakeNode("identifier", "connection", 2)
    call_arg = FakeNode("identifier", "sql", 2)
    call_args = FakeNode(
        "argument_list",
        "(sql)",
        2,
        children=[FakeNode("(", "(", 2), call_arg, FakeNode(")", ")", 2)],
    )
    call_value = FakeNode(
        "method_invocation",
        "connection.prepareCall(sql)",
        2,
        children=[call_target, call_name, call_args],
        fields={"object": call_target, "name": call_name, "arguments": call_args},
    )
    stmt_name = FakeNode("identifier", "statement", 2)
    stmt_var = FakeNode(
        "variable_declarator",
        "statement = connection.prepareCall(sql)",
        2,
        children=[stmt_name, call_value],
        fields={"name": stmt_name, "value": call_value},
    )
    stmt_decl = FakeNode(
        "local_variable_declaration",
        "CallableStatement statement = connection.prepareCall(sql);",
        2,
        children=[FakeNode("type_identifier", "CallableStatement", 2), stmt_var],
    )

    method_scope = FakeNode(
        "method_declaration",
        "public void handler() { ... }",
        0,
        children=[source_decl, sql_decl, stmt_decl],
    )
    tree = FakeTree(FakeNode("program", "program", 0, children=[method_scope]))

    source = TaintSource(
        location=CodeLocation(str(source_file), 1, 0, 'String param = request.getHeader("id");'),
        source_type="HTTP_HEADER",
        variable_name="param",
        pattern="getHeader(",
    )
    sink = TaintSink(
        location=CodeLocation(str(source_file), 3, 0, "CallableStatement statement = connection.prepareCall(sql);"),
        sink_type=VulnerabilityType.SQL_INJECTION,
        function_name="prepareCall",
        pattern="prepareCall(",
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
    assert paths[0].metadata["supporting_variables"] == ["sql"]
    assert [step.line_number for step in paths[0].intermediate_steps] == [2]


def test_java_plugin_extracts_prepare_statement_sink_and_tracks_tainted_sql(tmp_path):
    """Java rules should catch tainted SQL passed into prepareStatement overloads."""
    source_file = tmp_path / "Controller.java"
    source_file.write_text(
        "\n".join(
            [
                'String param = request.getParameter("id");',
                'String sql = "SELECT * FROM users WHERE id = " + param;',
                "PreparedStatement statement = connection.prepareStatement(",
                "    sql,",
                "    java.sql.ResultSet.TYPE_FORWARD_ONLY,",
                "    java.sql.ResultSet.CONCUR_READ_ONLY",
                ");",
            ]
        ),
        encoding="utf-8",
    )

    source_value = FakeNode("method_invocation", 'request.getParameter("id")', 0)
    source_name = FakeNode("identifier", "param", 0)
    source_var = FakeNode(
        "variable_declarator",
        'param = request.getParameter("id")',
        0,
        children=[source_name, source_value],
        fields={"name": source_name, "value": source_value},
    )
    source_decl = FakeNode(
        "local_variable_declaration",
        'String param = request.getParameter("id");',
        0,
        children=[FakeNode("type_identifier", "String", 0), source_var],
    )

    sql_value = FakeNode('binary_expression', '"SELECT * FROM users WHERE id = " + param', 1)
    sql_name = FakeNode("identifier", "sql", 1)
    sql_var = FakeNode(
        "variable_declarator",
        'sql = "SELECT * FROM users WHERE id = " + param',
        1,
        children=[sql_name, sql_value],
        fields={"name": sql_name, "value": sql_value},
    )
    sql_decl = FakeNode(
        "local_variable_declaration",
        'String sql = "SELECT * FROM users WHERE id = " + param;',
        1,
        children=[FakeNode("type_identifier", "String", 1), sql_var],
    )

    prepare_name = FakeNode("identifier", "prepareStatement", 2)
    prepare_target = FakeNode("identifier", "connection", 2)
    sql_arg = FakeNode("identifier", "sql", 2)
    type_arg = FakeNode("field_access", "java.sql.ResultSet.TYPE_FORWARD_ONLY", 3)
    concur_arg = FakeNode("field_access", "java.sql.ResultSet.CONCUR_READ_ONLY", 4)
    prepare_args = FakeNode(
        "argument_list",
        "(sql, java.sql.ResultSet.TYPE_FORWARD_ONLY, java.sql.ResultSet.CONCUR_READ_ONLY)",
        2,
        children=[
            FakeNode("(", "(", 2),
            sql_arg,
            FakeNode(",", ",", 2),
            type_arg,
            FakeNode(",", ",", 2),
            concur_arg,
            FakeNode(")", ")", 4),
        ],
    )
    prepare_value = FakeNode(
        "method_invocation",
        "connection.prepareStatement(sql, java.sql.ResultSet.TYPE_FORWARD_ONLY, java.sql.ResultSet.CONCUR_READ_ONLY)",
        2,
        children=[prepare_target, prepare_name, prepare_args],
        fields={"object": prepare_target, "name": prepare_name, "arguments": prepare_args},
    )
    statement_name = FakeNode("identifier", "statement", 2)
    statement_var = FakeNode(
        "variable_declarator",
        "statement = connection.prepareStatement(sql, java.sql.ResultSet.TYPE_FORWARD_ONLY, java.sql.ResultSet.CONCUR_READ_ONLY)",
        2,
        children=[statement_name, prepare_value],
        fields={"name": statement_name, "value": prepare_value},
    )
    statement_decl = FakeNode(
        "local_variable_declaration",
        "PreparedStatement statement = connection.prepareStatement(sql, java.sql.ResultSet.TYPE_FORWARD_ONLY, java.sql.ResultSet.CONCUR_READ_ONLY);",
        2,
        children=[FakeNode("type_identifier", "PreparedStatement", 2), statement_var],
    )

    method_scope = FakeNode(
        "method_declaration",
        "public void handler() { ... }",
        0,
        children=[source_decl, sql_decl, statement_decl],
    )
    tree = FakeTree(FakeNode("program", "program", 0, children=[method_scope]))

    rules = {
        "sinks": {
            "sqli": [
                {
                    "pattern": "prepareStatement(",
                    "type": "SQL_INJECTION",
                    "severity": "CRITICAL",
                    "description": "PreparedStatement created from dynamic SQL",
                }
            ]
        }
    }

    plugin = JavaPlugin()
    sinks = plugin.extract_sinks(tree, source_file, rules)

    assert len(sinks) == 1
    assert sinks[0].function_name == "prepareStatement"
    assert sinks[0].arguments[0] == "sql"

    source = TaintSource(
        location=CodeLocation(str(source_file), 1, 0, 'String param = request.getParameter("id");'),
        source_type="HTTP_PARAM",
        variable_name="param",
        pattern="getParameter(",
    )

    paths = plugin.track_dataflow(
        tree,
        source_file,
        source,
        sinks,
        [],
    )

    assert len(paths) == 1
    assert paths[0].metadata["supporting_variables"] == ["sql"]
    assert [step.line_number for step in paths[0].intermediate_steps] == [2]


def test_java_plugin_extracts_header_enumeration_source_and_tracks_execute_update(tmp_path):
    """Java source extraction should carry getHeaders taint through nextElement into SQL sinks."""
    source_file = tmp_path / "Controller.java"
    source_file.write_text(
        "\n".join(
            [
                'Enumeration<String> headers = request.getHeaders("X-Cmd");',
                "String param = headers.nextElement();",
                'String sql = "INSERT INTO logs(message) VALUES (\'" + param + "\')";',
                "statement.executeUpdate(sql);",
            ]
        ),
        encoding="utf-8",
    )

    headers_value = FakeNode("method_invocation", 'request.getHeaders("X-Cmd")', 0)
    headers_name = FakeNode("identifier", "headers", 0)
    headers_var = FakeNode(
        "variable_declarator",
        'headers = request.getHeaders("X-Cmd")',
        0,
        children=[headers_name, headers_value],
        fields={"name": headers_name, "value": headers_value},
    )
    headers_decl = FakeNode(
        "local_variable_declaration",
        'Enumeration<String> headers = request.getHeaders("X-Cmd");',
        0,
        children=[FakeNode("type_identifier", "Enumeration", 0), headers_var],
    )

    next_name = FakeNode("identifier", "nextElement", 1)
    next_target = FakeNode("identifier", "headers", 1)
    next_args = FakeNode(
        "argument_list",
        "()",
        1,
        children=[FakeNode("(", "(", 1), FakeNode(")", ")", 1)],
    )
    next_value = FakeNode(
        "method_invocation",
        "headers.nextElement()",
        1,
        children=[next_target, next_name, next_args],
        fields={"object": next_target, "name": next_name, "arguments": next_args},
    )
    param_name = FakeNode("identifier", "param", 1)
    param_var = FakeNode(
        "variable_declarator",
        "param = headers.nextElement()",
        1,
        children=[param_name, next_value],
        fields={"name": param_name, "value": next_value},
    )
    param_decl = FakeNode(
        "local_variable_declaration",
        "String param = headers.nextElement();",
        1,
        children=[FakeNode("type_identifier", "String", 1), param_var],
    )

    sql_value = FakeNode('binary_expression', '"INSERT INTO logs(message) VALUES (\'" + param + "\')"', 2)
    sql_name = FakeNode("identifier", "sql", 2)
    sql_var = FakeNode(
        "variable_declarator",
        'sql = "INSERT INTO logs(message) VALUES (\'" + param + "\')"',
        2,
        children=[sql_name, sql_value],
        fields={"name": sql_name, "value": sql_value},
    )
    sql_decl = FakeNode(
        "local_variable_declaration",
        'String sql = "INSERT INTO logs(message) VALUES (\'" + param + "\')";',
        2,
        children=[FakeNode("type_identifier", "String", 2), sql_var],
    )

    sink_name = FakeNode("identifier", "executeUpdate", 3)
    sink_target = FakeNode("identifier", "statement", 3)
    sink_arg = FakeNode("identifier", "sql", 3)
    sink_args = FakeNode(
        "argument_list",
        "(sql)",
        3,
        children=[FakeNode("(", "(", 3), sink_arg, FakeNode(")", ")", 3)],
    )
    sink_call = FakeNode(
        "method_invocation",
        "statement.executeUpdate(sql)",
        3,
        children=[sink_target, sink_name, sink_args],
        fields={"object": sink_target, "name": sink_name, "arguments": sink_args},
    )

    method_scope = FakeNode(
        "method_declaration",
        "public void handler() { ... }",
        0,
        children=[headers_decl, param_decl, sql_decl, sink_call],
    )
    tree = FakeTree(FakeNode("program", "program", 0, children=[method_scope]))

    rules = {
        "sources": [
            {
                "pattern": "getHeaders(",
                "type": "HTTP_HEADER",
                "severity": "MEDIUM",
            }
        ],
        "sinks": {
            "sqli": [
                {
                    "pattern": ".executeUpdate(",
                    "type": "SQL_INJECTION",
                    "severity": "CRITICAL",
                    "description": "SQL update execution",
                }
            ]
        },
    }

    plugin = JavaPlugin()
    sources = plugin.extract_sources(tree, source_file, rules)
    sinks = plugin.extract_sinks(tree, source_file, rules)

    assert len(sources) == 1
    assert sources[0].variable_name == "headers"
    assert len(sinks) == 1
    assert sinks[0].function_name == "executeUpdate"

    paths = plugin.track_dataflow(
        tree,
        source_file,
        sources[0],
        sinks,
        [],
    )

    assert len(paths) == 1
    assert paths[0].metadata["supporting_variables"] == ["sql"]
    assert [step.line_number for step in paths[0].intermediate_steps] == [2, 3]


def test_java_plugin_tracks_tainted_path_into_constructor_sink(tmp_path):
    """Java dataflow should also report constructor sinks such as FileInputStream(fileName)."""
    source_file = tmp_path / "Controller.java"
    source_file.write_text(
        "\n".join(
            [
                'String param = request.getParameter("file");',
                'String fileName = baseDir + param;',
                "FileInputStream fis = new FileInputStream(fileName);",
            ]
        ),
        encoding="utf-8",
    )

    source_value = FakeNode("method_invocation", 'request.getParameter("file")', 0)
    source_name = FakeNode("identifier", "param", 0)
    source_var = FakeNode(
        "variable_declarator",
        'param = request.getParameter("file")',
        0,
        children=[source_name, source_value],
        fields={"name": source_name, "value": source_value},
    )
    source_decl = FakeNode(
        "local_variable_declaration",
        'String param = request.getParameter("file");',
        0,
        children=[FakeNode("type_identifier", "String", 0), source_var],
    )

    path_value = FakeNode("binary_expression", "baseDir + param", 1)
    path_name = FakeNode("identifier", "fileName", 1)
    path_var = FakeNode(
        "variable_declarator",
        "fileName = baseDir + param",
        1,
        children=[path_name, path_value],
        fields={"name": path_name, "value": path_value},
    )
    path_decl = FakeNode(
        "local_variable_declaration",
        "String fileName = baseDir + param;",
        1,
        children=[FakeNode("type_identifier", "String", 1), path_var],
    )

    ctor_type = FakeNode("type_identifier", "FileInputStream", 2)
    ctor_arg = FakeNode("identifier", "fileName", 2)
    ctor_args = FakeNode(
        "argument_list",
        "(fileName)",
        2,
        children=[FakeNode("(", "(", 2), ctor_arg, FakeNode(")", ")", 2)],
    )
    ctor_value = FakeNode(
        "object_creation_expression",
        "new FileInputStream(fileName)",
        2,
        children=[ctor_type, ctor_args],
        fields={"type": ctor_type, "arguments": ctor_args},
    )
    ctor_name = FakeNode("identifier", "fis", 2)
    ctor_var = FakeNode(
        "variable_declarator",
        "fis = new FileInputStream(fileName)",
        2,
        children=[ctor_name, ctor_value],
        fields={"name": ctor_name, "value": ctor_value},
    )
    ctor_decl = FakeNode(
        "local_variable_declaration",
        "FileInputStream fis = new FileInputStream(fileName);",
        2,
        children=[FakeNode("type_identifier", "FileInputStream", 2), ctor_var],
    )

    method_scope = FakeNode(
        "method_declaration",
        "public void handler() { ... }",
        0,
        children=[source_decl, path_decl, ctor_decl],
    )
    tree = FakeTree(FakeNode("program", "program", 0, children=[method_scope]))

    source = TaintSource(
        location=CodeLocation(str(source_file), 1, 0, 'String param = request.getParameter("file");'),
        source_type="HTTP_PARAM",
        variable_name="param",
        pattern="getParameter(",
    )
    sink = TaintSink(
        location=CodeLocation(str(source_file), 3, 0, "FileInputStream fis = new FileInputStream(fileName);"),
        sink_type=VulnerabilityType.PATH_TRAVERSAL,
        function_name="FileInputStream",
        pattern="new FileInputStream(",
        arguments=["fileName"],
    )

    paths = JavaPlugin().track_dataflow(
        tree,
        source_file,
        source,
        [sink],
        [],
    )

    assert len(paths) == 1
    assert paths[0].metadata["supporting_variables"] == ["fileName"]
    assert [step.line_number for step in paths[0].intermediate_steps] == [2]
