"""Tests for the explicit Python CFG/DFG engine and its detector integration."""

from pathlib import Path
import importlib.util

from aegis_sast.analysis.python_flow_graph import (
    PythonDataflowAnalyzer,
    PythonFlowGraphBuilder,
)
from aegis_sast.core.models import (
    CodeLocation,
    Sanitizer,
    TaintSink,
    TaintSource,
    VulnerabilityType,
)

_HAS_TREE_SITTER_PYTHON = importlib.util.find_spec("tree_sitter_python") is not None


def test_python_flow_graph_builder_creates_cfg_and_dfg_edges(tmp_path):
    """The Python flow graph should expose explicit branch and data dependencies."""
    target = Path(tmp_path) / "service.py"
    target.write_text(
        "\n".join(
            [
                "def handler():",
                "    user_id = request.args.get('id')",
                "    if user_id:",
                "        query = \"SELECT * FROM users WHERE id = '\" + user_id + \"'\"",
                "    else:",
                "        query = \"SELECT 1\"",
                "    cursor.execute(query)",
            ]
        ),
        encoding="utf-8",
    )

    graph = PythonFlowGraphBuilder(
        target,
        target.read_text(encoding="utf-8"),
    ).build()
    summary = graph.summary()

    assert summary["node_count"] >= 8
    assert summary["cfg_edge_count"] >= 8
    assert summary["dfg_edge_count"] >= 3
    assert "branch" in summary["kinds"]
    assert graph.find_preferred_node(4, ("assignment",)) is not None


def test_python_flow_graph_prunes_unreachable_nodes_after_return(tmp_path):
    """Statements after a terminating return should not become reachable CFG nodes."""
    target = Path(tmp_path) / "service.py"
    target.write_text(
        "\n".join(
            [
                "def handler():",
                "    cmd = request.args.get('cmd')",
                "    return 'blocked'",
                "    os.system(cmd)",
            ]
        ),
        encoding="utf-8",
    )

    graph = PythonFlowGraphBuilder(
        target,
        target.read_text(encoding="utf-8"),
    ).build()

    assert graph.find_preferred_node(4, ("call",)) is None


def test_python_dataflow_clears_taint_on_safe_reassignment(tmp_path):
    """A safe overwrite should remove prior taint from the same variable."""
    target = Path(tmp_path) / "service.py"
    target.write_text(
        "\n".join(
            [
                "def handler():",
                "    cmd = request.args.get('cmd')",
                "    cmd = 'echo safe'",
                "    os.system(cmd)",
            ]
        ),
        encoding="utf-8",
    )

    graph = PythonFlowGraphBuilder(
        target,
        target.read_text(encoding="utf-8"),
    ).build()
    analyzer = PythonDataflowAnalyzer(graph)

    source = TaintSource(
        CodeLocation(str(target), 2, 4, "cmd = request.args.get('cmd')"),
        "HTTP_PARAM",
        "cmd",
        "request.args.get",
    )
    sink = TaintSink(
        CodeLocation(str(target), 4, 4, "os.system(cmd)"),
        VulnerabilityType.COMMAND_INJECTION,
        "os.system",
        "os.system(",
        arguments=["cmd"],
    )

    paths = analyzer.trace_paths(source, [sink], [])
    assert paths == []


def test_python_flow_graph_models_try_except_finally(tmp_path):
    """The explicit CFG should keep structured edges for try/except/finally blocks."""
    target = Path(tmp_path) / "service.py"
    target.write_text(
        "\n".join(
            [
                "def handler():",
                "    cmd = request.args.get('cmd')",
                "    try:",
                "        risky(cmd)",
                "    except Exception as exc:",
                "        logger.error(exc)",
                "    finally:",
                "        cleanup()",
            ]
        ),
        encoding="utf-8",
    )

    graph = PythonFlowGraphBuilder(
        target,
        target.read_text(encoding="utf-8"),
    ).build()
    summary = graph.summary()

    assert summary["kinds"]["try"] == 1
    assert summary["kinds"]["except"] == 1
    assert summary["kinds"]["finally"] == 1
    assert any(edge.label == "except" for edge in graph.cfg_edges)
    assert any(edge.label == "finally" for edge in graph.cfg_edges)


def test_python_flow_graph_models_break_and_continue_edges(tmp_path):
    """Loop control statements should become explicit CFG edges."""
    target = Path(tmp_path) / "service.py"
    target.write_text(
        "\n".join(
            [
                "def handler(items):",
                "    for item in items:",
                "        if item == 'skip':",
                "            continue",
                "        if item == 'stop':",
                "            break",
                "        sink(item)",
            ]
        ),
        encoding="utf-8",
    )

    graph = PythonFlowGraphBuilder(
        target,
        target.read_text(encoding="utf-8"),
    ).build()
    summary = graph.summary()

    assert summary["kinds"]["continue"] == 1
    assert summary["kinds"]["break"] == 1
    assert any(edge.label == "continue" for edge in graph.cfg_edges)
    assert any(edge.label == "break" for edge in graph.cfg_edges)
    assert graph.find_preferred_node(7, ("call",)) is not None


def test_python_flow_graph_models_for_else_path(tmp_path):
    """A for-else block should route the loop false edge into the else body."""
    target = Path(tmp_path) / "service.py"
    target.write_text(
        "\n".join(
            [
                "def handler(items):",
                "    for item in items:",
                "        if item == 'stop':",
                "            break",
                "    else:",
                "        sink('clean')",
                "    sink('done')",
            ]
        ),
        encoding="utf-8",
    )

    graph = PythonFlowGraphBuilder(
        target,
        target.read_text(encoding="utf-8"),
    ).build()

    else_node = graph.find_preferred_node(6, ("call",))
    assert else_node is not None
    assert any(
        edge.label == "false" and edge.target_id == else_node.node_id
        for edge in graph.cfg_edges
    )
    assert any(edge.label == "break" for edge in graph.cfg_edges)


def test_python_flow_graph_prunes_unreachable_nodes_after_continue(tmp_path):
    """Statements after a direct continue should not remain in the loop body graph."""
    target = Path(tmp_path) / "service.py"
    target.write_text(
        "\n".join(
            [
                "def handler(items):",
                "    for item in items:",
                "        continue",
                "        sink(item)",
                "    sink('done')",
            ]
        ),
        encoding="utf-8",
    )

    graph = PythonFlowGraphBuilder(
        target,
        target.read_text(encoding="utf-8"),
    ).build()

    assert graph.find_preferred_node(4, ("call",)) is None
    assert graph.find_preferred_node(5, ("call",)) is not None


def test_python_flow_graph_models_while_else_path(tmp_path):
    """A while-else block should keep the else body on the no-break path."""
    target = Path(tmp_path) / "service.py"
    target.write_text(
        "\n".join(
            [
                "def handler(flag):",
                "    while flag:",
                "        flag = False",
                "    else:",
                "        sink('clean')",
                "    sink('done')",
            ]
        ),
        encoding="utf-8",
    )

    graph = PythonFlowGraphBuilder(
        target,
        target.read_text(encoding="utf-8"),
    ).build()

    else_node = graph.find_preferred_node(5, ("call",))
    assert else_node is not None
    assert any(
        edge.label == "false" and edge.target_id == else_node.node_id
        for edge in graph.cfg_edges
    )
    assert graph.find_preferred_node(6, ("call",)) is not None


def test_python_flow_graph_builds_function_return_dependency_summaries(tmp_path):
    """Function summaries should record which parameters can influence returns."""
    target = Path(tmp_path) / "service.py"
    target.write_text(
        "\n".join(
            [
                "def relay(user_id, fallback):",
                "    chosen = user_id",
                "    return chosen",
                "",
                "def constant_only(user_id, fallback):",
                "    chosen = 'safe'",
                "    return chosen",
            ]
        ),
        encoding="utf-8",
    )

    graph = PythonFlowGraphBuilder(
        target,
        target.read_text(encoding="utf-8"),
    ).build()
    relay_summary = graph.get_function_summary("relay")
    constant_summary = graph.get_function_summary("constant_only")

    assert relay_summary is not None
    assert relay_summary.dependent_parameters == ["user_id"]
    assert relay_summary.returns_tainted_from_parameters is True
    assert constant_summary is not None
    assert constant_summary.dependent_parameters == []
    assert graph.summary()["function_summary_count"] == 2


def test_python_dataflow_uses_function_summary_for_call_assignment(tmp_path):
    """Call assignments should use function summaries instead of tainting by argument alone."""
    target = Path(tmp_path) / "service.py"
    target.write_text(
        "\n".join(
            [
                "def relay(cmd):",
                "    alias = cmd",
                "    return alias",
                "",
                "def handler():",
                "    cmd = request.args.get('cmd')",
                "    prepared = relay(cmd)",
                "    os.system(prepared)",
            ]
        ),
        encoding="utf-8",
    )

    graph = PythonFlowGraphBuilder(
        target,
        target.read_text(encoding="utf-8"),
    ).build()

    def resolver(callee_name, arguments, tainted_vars):
        summary = graph.get_function_summary(callee_name)
        if summary is None:
            return False
        tainted_params = set()
        for index, argument in enumerate(arguments):
            words = set(argument.replace("(", " ").replace(")", " ").replace(",", " ").split())
            if not words.intersection(tainted_vars):
                continue
            if index < len(summary.parameter_names):
                tainted_params.add(summary.parameter_names[index])
            else:
                tainted_params.update(summary.parameter_names)
        return bool(set(summary.dependent_parameters).intersection(tainted_params))

    analyzer = PythonDataflowAnalyzer(graph, callee_taint_resolver=resolver)
    source = TaintSource(
        CodeLocation(str(target), 6, 4, "cmd = request.args.get('cmd')"),
        "HTTP_PARAM",
        "cmd",
        "request.args.get",
    )
    sink = TaintSink(
        CodeLocation(str(target), 8, 4, "os.system(prepared)"),
        VulnerabilityType.COMMAND_INJECTION,
        "os.system",
        "os.system(",
        arguments=["prepared"],
    )

    paths = analyzer.trace_paths(source, [sink], [])

    assert len(paths) == 1
    assert paths[0].metadata["local_callee_summaries"][0]["function_name"] == "relay"


def test_python_dataflow_does_not_taint_safe_helper_call_assignment(tmp_path):
    """A helper that returns a constant should not taint the receiving variable."""
    target = Path(tmp_path) / "service.py"
    target.write_text(
        "\n".join(
            [
                "def safe_helper(cmd):",
                "    return 'echo safe'",
                "",
                "def handler():",
                "    cmd = request.args.get('cmd')",
                "    prepared = safe_helper(cmd)",
                "    os.system(prepared)",
            ]
        ),
        encoding="utf-8",
    )

    graph = PythonFlowGraphBuilder(
        target,
        target.read_text(encoding="utf-8"),
    ).build()

    def resolver(callee_name, arguments, tainted_vars):
        summary = graph.get_function_summary(callee_name)
        if summary is None:
            return False
        tainted_params = set()
        for index, argument in enumerate(arguments):
            words = set(argument.replace("(", " ").replace(")", " ").replace(",", " ").split())
            if not words.intersection(tainted_vars):
                continue
            if index < len(summary.parameter_names):
                tainted_params.add(summary.parameter_names[index])
            else:
                tainted_params.update(summary.parameter_names)
        return bool(set(summary.dependent_parameters).intersection(tainted_params))

    analyzer = PythonDataflowAnalyzer(graph, callee_taint_resolver=resolver)
    source = TaintSource(
        CodeLocation(str(target), 5, 4, "cmd = request.args.get('cmd')"),
        "HTTP_PARAM",
        "cmd",
        "request.args.get",
    )
    sink = TaintSink(
        CodeLocation(str(target), 7, 4, "os.system(prepared)"),
        VulnerabilityType.COMMAND_INJECTION,
        "os.system",
        "os.system(",
        arguments=["prepared"],
    )

    paths = analyzer.trace_paths(source, [sink], [])

    assert paths == []


def test_python_plugin_cfg_stops_unreachable_sink_after_return(tmp_path):
    """A return statement should terminate the CFG path before the sink."""
    if not _HAS_TREE_SITTER_PYTHON:
        return

    from aegis_sast.plugins.python_plugin import PythonPlugin

    target = Path(tmp_path) / "service.py"
    target.write_text(
        "\n".join(
            [
                "def handler():",
                "    cmd = request.args.get('cmd')",
                "    return 'blocked'",
                "    os.system(cmd)",
            ]
        ),
        encoding="utf-8",
    )

    plugin = PythonPlugin()
    tree = plugin.parse_file(target)

    source = TaintSource(
        CodeLocation(str(target), 2, 4, "cmd = request.args.get('cmd')"),
        "HTTP_PARAM",
        "cmd",
        "request.args.get",
    )
    sink = TaintSink(
        CodeLocation(str(target), 4, 4, "os.system(cmd)"),
        VulnerabilityType.COMMAND_INJECTION,
        "os.system",
        "os.system(",
        arguments=["cmd"],
    )

    paths = plugin.track_dataflow(tree, target, source, [sink], [])
    assert paths == []


def test_python_plugin_attaches_graph_metadata_to_dataflow(tmp_path):
    """Graph-driven tracking should emit intermediate steps and graph statistics."""
    if not _HAS_TREE_SITTER_PYTHON:
        return

    from aegis_sast.plugins.python_plugin import PythonPlugin

    target = Path(tmp_path) / "service.py"
    target.write_text(
        "\n".join(
            [
                "def handler():",
                "    cmd = request.args.get('cmd')",
                "    prepared = cmd",
                "    os.system(prepared)",
            ]
        ),
        encoding="utf-8",
    )

    plugin = PythonPlugin()
    tree = plugin.parse_file(target)

    source = TaintSource(
        CodeLocation(str(target), 2, 4, "cmd = request.args.get('cmd')"),
        "HTTP_PARAM",
        "cmd",
        "request.args.get",
    )
    sink = TaintSink(
        CodeLocation(str(target), 4, 4, "os.system(prepared)"),
        VulnerabilityType.COMMAND_INJECTION,
        "os.system",
        "os.system(",
        arguments=["prepared"],
    )
    sanitizer = Sanitizer(
        CodeLocation(str(target), 3, 4, "prepared = cmd"),
        "IDENTITY",
        "identity",
        mitigates=[],
    )

    paths = plugin.track_dataflow(tree, target, source, [sink], [sanitizer])

    assert len(paths) == 1
    assert any(step.line_number == 3 for step in paths[0].intermediate_steps)
    assert paths[0].metadata["analysis_engine"] == "python-flow-graph-v1"
    assert paths[0].metadata["graph_version"] == "v1.2"
    assert paths[0].metadata["graph_summary"]["cfg_edge_count"] > 0
    assert paths[0].metadata["graph_summary"]["dfg_edge_count"] > 0


def test_detector_synthesizes_same_file_helper_source(tmp_path):
    """Detector should catch sources hidden behind a helper in the same file."""
    if not _HAS_TREE_SITTER_PYTHON:
        return

    from aegis_sast.analysis.rule_engine import RuleEngine
    from aegis_sast.analysis.vulnerability_detector import VulnerabilityDetector

    target = Path(tmp_path) / "service.py"
    target.write_text(
        "\n".join(
            [
                "import os",
                "def get_cmd():",
                "    return request.args.get('cmd')",
                "",
                "def handler():",
                "    cmd = get_cmd()",
                "    os.system(cmd)",
            ]
        ),
        encoding="utf-8",
    )

    detector = VulnerabilityDetector(RuleEngine())
    vulnerabilities = detector.analyze_file(target, project_root=tmp_path)

    assert vulnerabilities
    assert any(vuln.vuln_type == VulnerabilityType.COMMAND_INJECTION for vuln in vulnerabilities)
