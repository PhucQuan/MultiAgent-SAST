"""Evidence tests assert actual dependency paths, not just node counts."""
import json
from pathlib import Path

import pytest

from aegis_sast.analysis.investigation_graph import InvestigationAnalyzer, validate_graph


CASES = [
    ("two_sources", "import os\na = input('a')\nb = input('b')\nos.system(a + b)\n", 2, 1, 2),
    ("two_sinks", "import os\na = input()\nos.system(a)\nos.popen(a)\n", 1, 2, 2),
    ("branches", "import os\na = input()\nif flag:\n    cmd = a + 'x'\nelse:\n    cmd = a + 'y'\nos.system(cmd)\n", 1, 1, 2),
    ("return", "import os\ndef wrap(x):\n    y = x + '!'\n    return y\na = input()\nos.system(wrap(a))\n", 1, 1, 1),
    ("sanitized", "import os, shlex\na = input()\nif flag:\n    cmd = shlex.quote(a)\nelse:\n    cmd = a\nos.system(cmd)\n", 1, 1, 2),
    ("reassignment", "import os\na = input()\na = 'safe'\nos.system(a)\n", 0, 1, 0),
    ("sink_only", "import pickle\npickle.loads(blob)\n", 0, 1, 0),
    ("no_trace", "import os\ndef execute(value):\n    os.system(value)\n", 0, 1, 0),
    ("attribute", "import os\nbox.cmd = input()\nos.system(box.cmd)\n", 1, 1, 1),
    ("dictionary", "import os\ndata = {'bad': input(), 'safe': 'hello'}\nos.system(data['bad'])\nos.system(data['safe'])\n", 1, 2, 1),
    ("list", "import os\ndata = [input(), 'safe']\nos.system(data[0])\nos.system(data[1])\n", 1, 2, 1),
    ("branch_return", "import os\ndef f():\n    a = input()\n    if flag:\n        return\n    os.system(a)\n", 1, 1, 1),
]


@pytest.mark.parametrize("name,code,sources,sinks,paths", CASES, ids=[c[0] for c in CASES])
def test_paths(tmp_path, name, code, sources, sinks, paths):
    file = tmp_path / f"{name}.py"
    file.write_text(code, encoding="utf-8")
    analyzer = InvestigationAnalyzer([file]).analyze()
    graph = analyzer.graph_for(str(file), 1, len(code.splitlines()))
    validate_graph(graph)
    assert len(graph["sources"]) == sources
    assert len(graph["sinks"]) == sinks
    assert len(graph["paths"]) == paths
    assert all(path["verified"] for path in graph["paths"])
    assert json.loads(json.dumps(graph)) == graph
    assert graph == InvestigationAnalyzer([file]).analyze().graph_for(str(file), 1, len(code.splitlines()))
    for node in graph["nodes"]:
        assert Path(node["file"]).exists()
        assert 1 <= node["line"] <= len(code.splitlines())
        assert node["snippet"] in code
    if name == "sanitized":
        assert sorted(len(p["sanitizers"]) for p in graph["paths"]) == [0, 1]
    if name == "branches":
        assert len({tuple(p["control_node_ids"]) for p in graph["paths"]}) == 2
    if name == "return":
        assert {e["relation"] for e in graph["edges"]} >= {"argument_passing", "parameter_binding", "return_value"}


def test_cross_file_and_call_contexts(tmp_path):
    helper = tmp_path / "helper.py"
    helper.write_text("def build(x):\n    return x + '!'\n")
    app = tmp_path / "app.py"
    app.write_text("import os\nfrom helper import build\na = build(input())\nb = build('safe')\nos.system(a)\nos.system(b)\n")
    analyzer = InvestigationAnalyzer([app, helper]).analyze()
    graph = analyzer.graph_for(str(app), 1, 6)
    validate_graph(graph)
    assert len(graph["paths"]) == 1
    assert {n["file"] for n in graph["nodes"]} == {str(app), str(helper)}
    assert any(e["relation"] == "return_value" for e in graph["edges"])
    assert analyzer.graph_for(str(app), 6)["paths"] == []


def test_unknown_return_is_never_verified(tmp_path):
    file = tmp_path / "unknown.py"
    file.write_text("import os\na = input()\nb = unknown(a)\nos.system(b)\n")
    graph = InvestigationAnalyzer([file]).analyze().graph_for(str(file), 4)
    validate_graph(graph)
    assert graph["evidence_mode"] == "partial_path"
    assert not graph["paths"][0]["verified"]
    assert any(not edge["verified"] for edge in graph["edges"])
    assert graph["paths"][0]["analysis_limitations"]


def test_bounded_large_graph(tmp_path):
    file = tmp_path / "large.py"
    file.write_text("import os\nx = input()\n" + "".join(f"if flag{i}:\n    x = x + 'a'\nelse:\n    x = x + 'b'\n" for i in range(12)) + "os.system(x)\n")
    analyzer = InvestigationAnalyzer([file], max_paths=16, max_states=16).analyze()
    graph = analyzer.graph_for(str(file), 51)
    validate_graph(graph)
    assert len(graph["paths"]) <= 16
    assert graph["truncated"]
    assert analyzer.steps < analyzer.max_steps


@pytest.mark.parametrize("expression,name", [
    ("pickle.loads(data)", "pickle.loads"), ("yaml.unsafe_load(data)", "yaml.unsafe_load"),
    ("requests.get(url)", "requests.get"), ("redirect(target)", "redirect"),
    ("os.system(command)", "os.system"), ("cursor.execute(query)", "cursor.execute"),
])
def test_exact_sink_identity(tmp_path, expression, name):
    file = tmp_path / "sink.py"
    file.write_text(expression + "\n")
    graph = InvestigationAnalyzer([file]).analyze().graph_for(str(file), 1)
    assert graph["evidence_mode"] == "sink_only"
    assert graph["nodes"][0]["label"] == name
    assert graph["nodes"][0]["snippet"] == expression
    assert not graph["sources"] and not graph["paths"]
