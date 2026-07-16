"""Manual smoke tests for the pure Python CFG/DFG graph engine.

This script intentionally avoids Tree-sitter so it can run even when the
full plugin environment is not ready yet.
"""

from __future__ import annotations

import sys
from pathlib import Path
from tempfile import TemporaryDirectory

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegis_sast.analysis.python_flow_graph import (
    PythonDataflowAnalyzer,
    PythonFlowGraphBuilder,
)
from aegis_sast.core.models import (
    CodeLocation,
    TaintSink,
    TaintSource,
    VulnerabilityType,
)


def _build_graph(tmp_dir: Path, filename: str, source_text: str):
    target = tmp_dir / filename
    target.write_text(source_text, encoding="utf-8")
    graph = PythonFlowGraphBuilder(target, source_text).build()
    return target, graph


def smoke_safe_reassignment(tmp_dir: Path) -> None:
    """Safe overwrite should clear taint before the sink."""
    target, graph = _build_graph(
        tmp_dir,
        "safe_reassignment.py",
        "\n".join(
            [
                "def handler():",
                "    cmd = request.args.get('cmd')",
                "    cmd = 'echo safe'",
                "    os.system(cmd)",
            ]
        ),
    )
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
    print("[ok] safe_reassignment", {"paths": len(paths), "summary": graph.summary()})
    if paths:
        raise AssertionError("safe overwrite should remove taint before the sink")


def smoke_return_pruning(tmp_dir: Path) -> None:
    """Code after return should not appear as a reachable node."""
    _, graph = _build_graph(
        tmp_dir,
        "return_pruning.py",
        "\n".join(
            [
                "def handler():",
                "    cmd = request.args.get('cmd')",
                "    return 'blocked'",
                "    os.system(cmd)",
            ]
        ),
    )
    line4 = graph.line_index.get(4, [])
    print("[ok] return_pruning", {"line4_nodes": line4, "summary": graph.summary()})
    if line4:
        raise AssertionError("unreachable statement after return should not be in CFG")


def smoke_loop_control(tmp_dir: Path) -> None:
    """Loop control edges should exist for break/continue."""
    _, graph = _build_graph(
        tmp_dir,
        "loop_control.py",
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
    )
    labels = sorted({edge.label for edge in graph.cfg_edges if edge.label})
    print("[ok] loop_control", {"labels": labels, "summary": graph.summary()})
    if "continue" not in labels or "break" not in labels:
        raise AssertionError("loop control labels were not emitted")


def smoke_loop_else(tmp_dir: Path) -> None:
    """Loop false edge should be able to enter the else body."""
    _, graph = _build_graph(
        tmp_dir,
        "loop_else.py",
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
    )
    else_nodes = graph.line_index.get(6, [])
    labels = sorted({edge.label for edge in graph.cfg_edges if edge.label})
    print("[ok] loop_else", {"line6_nodes": else_nodes, "labels": labels})
    if not else_nodes:
        raise AssertionError("loop else body was not added to the graph")


def smoke_function_summary(tmp_dir: Path) -> None:
    """Function summaries should map returns back to dependent parameters."""
    _, graph = _build_graph(
        tmp_dir,
        "function_summary.py",
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
    )
    relay_summary = graph.get_function_summary("relay")
    constant_summary = graph.get_function_summary("constant_only")
    payload = {
        "relay": relay_summary.dependent_parameters if relay_summary else None,
        "constant_only": (
            constant_summary.dependent_parameters if constant_summary else None
        ),
        "graph_summary": graph.summary(),
    }
    print("[ok] function_summary", payload)
    if relay_summary is None or relay_summary.dependent_parameters != ["user_id"]:
        raise AssertionError("relay summary should depend on user_id")
    if constant_summary is None or constant_summary.dependent_parameters:
        raise AssertionError("constant_only summary should have no tainted parameters")


def main() -> None:
    with TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        smoke_safe_reassignment(tmp_dir)
        smoke_return_pruning(tmp_dir)
        smoke_loop_control(tmp_dir)
        smoke_loop_else(tmp_dir)
        smoke_function_summary(tmp_dir)
    print("[done] manual_graph_smoke")


if __name__ == "__main__":
    main()
