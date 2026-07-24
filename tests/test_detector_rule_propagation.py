"""Regression tests for detector-side rule selection and propagation."""

from pathlib import Path
from types import SimpleNamespace

from aegis_sast.analysis.rule_engine import RuleEngine
from aegis_sast.analysis.vulnerability_detector import VulnerabilityDetector
from aegis_sast.core.models import (
    CodeLocation,
    DataFlowPath,
    TaintSink,
    TaintSource,
    VulnerabilityType,
    Severity,
)
from aegis_sast.core.plugin_interface import ILanguagePlugin
from aegis_sast.core.registry import PluginRegistry


class FakeLanguagePlugin(ILanguagePlugin):
    """Dependency-free plugin used to validate rule propagation behavior."""

    def __init__(self, language: str, extension: str):
        self._language = language
        self._extension = extension
        self.last_rules = None

    def get_language_name(self) -> str:
        return self._language

    def get_file_extensions(self):
        return [self._extension]

    def can_analyze(self, file_path: Path) -> bool:
        return file_path.suffix.lstrip(".") == self._extension

    def parse_file(self, file_path: Path):
        return object()

    def extract_sources(self, ast, file_path: Path, rules):
        self.last_rules = rules
        source_rule = rules["sources"][0]
        return [
            TaintSource(
                location=CodeLocation(
                    file_path=str(file_path),
                    line_number=1,
                    column_number=0,
                    code_snippet=f"const input = {source_rule['pattern']};",
                ),
                source_type=source_rule["type"],
                variable_name="input",
                pattern=source_rule["pattern"],
            )
        ]

    def extract_sinks(self, ast, file_path: Path, rules):
        self.last_rules = rules
        sink_rule = next(iter(rules["sinks"].values()))[0]
        return [
            TaintSink(
                location=CodeLocation(
                    file_path=str(file_path),
                    line_number=3,
                    column_number=0,
                    code_snippet=f"danger.{sink_rule['pattern']}input);",
                ),
                sink_type=VulnerabilityType[sink_rule["type"]],
                function_name="danger.sink",
                pattern=sink_rule["pattern"],
                arguments=["input"],
            )
        ]

    def extract_sanitizers(self, ast, file_path: Path, rules):
        return []

    def track_dataflow(self, ast, file_path: Path, source, sinks, sanitizers, max_depth=5):
        return [
            DataFlowPath(
                source=source,
                sink=sinks[0],
                intermediate_steps=[],
                sanitizers=list(sanitizers),
                metadata={"language": self._language},
            )
        ]


def make_detector(rule_engine: RuleEngine, plugin: FakeLanguagePlugin) -> VulnerabilityDetector:
    """Build a detector with an isolated registry and one fake plugin."""
    detector = VulnerabilityDetector(rule_engine)
    registry = PluginRegistry()
    registry.register(plugin)
    detector.registry = registry
    return detector


def test_detector_uses_custom_rules_end_to_end(tmp_path):
    """Custom --rules files should propagate through the detector unchanged."""
    custom_rules = tmp_path / "custom-javascript.yaml"
    custom_rules.write_text(
        "\n".join(
            [
                "sources:",
                '  - pattern: "ctx.input"',
                '    type: "HTTP_PARAM"',
                "sinks:",
                "  sqli:",
                '    - pattern: "customSink("',
                '      type: "SQL_INJECTION"',
                '      severity: "LOW"',
                "sanitizers: []",
            ]
        ),
        encoding="utf-8",
    )
    target = tmp_path / "sample.js"
    target.write_text("const placeholder = true;", encoding="utf-8")

    plugin = FakeLanguagePlugin(language="javascript", extension="js")
    detector = make_detector(RuleEngine(custom_rules), plugin)

    vulnerabilities = detector.analyze_file(target)

    assert vulnerabilities
    assert plugin.last_rules["sources"][0]["pattern"] == "ctx.input"
    assert next(iter(plugin.last_rules["sinks"].values()))[0]["pattern"] == "customSink("
    assert vulnerabilities[0].severity == Severity.LOW


def test_detector_loads_builtin_rules_for_plugin_language(tmp_path):
    """Default scans should switch to the plugin language instead of staying on Python rules."""
    target = tmp_path / "sample.js"
    target.write_text("const placeholder = true;", encoding="utf-8")

    plugin = FakeLanguagePlugin(language="javascript", extension="js")
    detector = make_detector(RuleEngine(language="python"), plugin)

    vulnerabilities = detector.analyze_file(target)

    assert vulnerabilities
    source_patterns = [rule["pattern"] for rule in plugin.last_rules["sources"]]
    sink_patterns = [
        rule["pattern"]
        for category_rules in plugin.last_rules["sinks"].values()
        for rule in category_rules
    ]

    assert "req.query" in source_patterns
    assert ".query(" in sink_patterns
    assert "request.args.get" not in source_patterns


class FakeTreeNode:
    """Minimal Tree-sitter-like node for detector unit tests."""

    def __init__(self, node_type, text="", start_point=(0, 0), children=None, fields=None):
        self.type = node_type
        self.text = text.encode("utf-8")
        self.start_point = start_point
        self.children = children or []
        self._fields = fields or {}

    def child_by_field_name(self, name):
        return self._fields.get(name)


class FakeTree:
    """Container matching the ``tree.root_node`` shape used by the detector."""

    def __init__(self, root_node):
        self.root_node = root_node


def test_cross_file_source_synthesis_only_uses_resolved_imports(tmp_path):
    """Unimported same-name helpers elsewhere in the repo must not create sources."""
    target = tmp_path / "app.py"
    target.write_text("file_rows = list(reader)\n", encoding="utf-8")

    noise = tmp_path / "noise.py"
    noise.write_text(
        "\n".join(
            [
                "def list(value):",
                "    return input()",
            ]
        ),
        encoding="utf-8",
    )

    lhs = FakeTreeNode("identifier", "file_rows", start_point=(0, 0))
    func = FakeTreeNode("identifier", "list", start_point=(0, 12))
    rhs = FakeTreeNode(
        "call",
        "list(reader)",
        start_point=(0, 12),
        children=[func],
        fields={"function": func},
    )
    assignment = FakeTreeNode(
        "assignment",
        "file_rows = list(reader)",
        start_point=(0, 0),
        children=[lhs, FakeTreeNode("=", "="), rhs],
    )
    fake_ast = FakeTree(FakeTreeNode("module", children=[assignment]))

    detector = make_detector(RuleEngine(language="python"), FakeLanguagePlugin("python", "py"))
    synthetic_sources = detector._extract_cross_file_sources(
        ast=fake_ast,
        file_path=target,
        import_map={},
        func_index=SimpleNamespace(get=lambda name: SimpleNamespace(file_path=str(noise))),
        source_rules=[{"pattern": "input(", "type": "USER_INPUT"}],
    )

    assert synthetic_sources == []
