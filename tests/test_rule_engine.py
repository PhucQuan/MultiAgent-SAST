"""
Unit tests for aegis_sast.analysis.rule_engine.RuleEngine
"""

import pytest
from pathlib import Path
from aegis_sast.analysis.rule_engine import RuleEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def python_engine():
    return RuleEngine(language="python")


@pytest.fixture
def javascript_engine():
    return RuleEngine(language="javascript")


@pytest.fixture
def java_engine():
    return RuleEngine(language="java")


@pytest.fixture
def php_engine():
    return RuleEngine(language="php")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRuleEngineInit:
    def test_python_rules_load(self, python_engine):
        rules = python_engine.get_rules()
        assert rules, "Python rules should not be empty"

    def test_javascript_rules_load(self, javascript_engine):
        rules = javascript_engine.get_rules()
        assert rules, "JavaScript rules should not be empty"

    def test_java_rules_load(self, java_engine):
        rules = java_engine.get_rules()
        assert rules, "Java rules should not be empty"

    def test_php_rules_load(self, php_engine):
        rules = php_engine.get_rules()
        assert rules, "PHP rules should not be empty"

    def test_fallback_to_python_on_unknown_language(self):
        engine = RuleEngine(language="cobol")
        rules = engine.get_rules()
        # Should fall back gracefully (either empty or python rules)
        assert isinstance(rules, dict)

    def test_extra_rules_paths_merge_overlay_into_builtin_rules(self, tmp_path):
        overlay_rules = tmp_path / "overlay.yaml"
        overlay_rules.write_text(
            "\n".join(
                [
                    "sources:",
                    '  - pattern: "request.headers.get"',
                    '    type: "HTTP_HEADER"',
                    '    severity: "HIGH"',
                    "sinks:",
                    "  rce:",
                    '    - pattern: "subprocess.check_output("',
                    '      type: "COMMAND_INJECTION"',
                    '      severity: "CRITICAL"',
                    '      description: "Overlay command sink"',
                    "sanitizers:",
                    '  - pattern: "safe_join("',
                    '    mitigates: ["PATH_TRAVERSAL"]',
                    '    description: "Overlay path guard"',
                    "safe_patterns:",
                    '  - "pathlib.Path.resolve()"',
                ]
            ),
            encoding="utf-8",
        )

        engine = RuleEngine(language="python", extra_rules_paths=[overlay_rules])
        rules = engine.get_rules()

        source_patterns = [entry["pattern"] for entry in rules["sources"]]
        rce_patterns = [entry["pattern"] for entry in rules["sinks"]["rce"]]
        sanitizer_patterns = [entry["pattern"] for entry in rules["sanitizers"]]

        assert "request.args.get" in source_patterns
        assert "request.headers.get" in source_patterns
        assert "os.system(" in rce_patterns
        assert "subprocess.check_output(" in rce_patterns
        assert "safe_join(" in sanitizer_patterns
        assert "pathlib.Path.resolve()" in rules["safe_patterns"]

    def test_extra_rules_paths_do_not_duplicate_existing_patterns(self, tmp_path):
        overlay_rules = tmp_path / "overlay.yaml"
        overlay_rules.write_text(
            "\n".join(
                [
                    "sources:",
                    '  - pattern: "request.args.get"',
                    '    type: "HTTP_PARAM"',
                    '    severity: "HIGH"',
                    "sinks:",
                    "  rce:",
                    '    - pattern: "os.system("',
                    '      type: "COMMAND_INJECTION"',
                    '      severity: "CRITICAL"',
                    '      description: "Duplicate overlay sink"',
                    "sanitizers:",
                    '  - pattern: "shlex.quote("',
                    '    mitigates: ["COMMAND_INJECTION"]',
                    '    description: "Duplicate overlay sanitizer"',
                ]
            ),
            encoding="utf-8",
        )

        engine = RuleEngine(language="python", extra_rules_paths=[overlay_rules])
        rules = engine.get_rules()

        source_patterns = [entry["pattern"] for entry in rules["sources"]]
        rce_patterns = [entry["pattern"] for entry in rules["sinks"]["rce"]]
        sanitizer_patterns = [entry["pattern"] for entry in rules["sanitizers"]]

        assert source_patterns.count("request.args.get") == 1
        assert rce_patterns.count("os.system(") == 1
        assert sanitizer_patterns.count("shlex.quote(") == 1


class TestRuleEngineSources:
    def test_python_has_http_sources(self, python_engine):
        sources = python_engine.get_sources()
        assert len(sources) > 0, "Should have at least one source"
        patterns = [s.get("pattern", "") for s in sources]
        # request.args.get is a canonical Flask source
        assert any("args" in p or "request" in p for p in patterns), (
            f"Expected HTTP param source, got: {patterns}"
        )

    def test_sources_have_required_fields(self, python_engine):
        for src in python_engine.get_sources():
            assert "pattern" in src, f"Source missing 'pattern' field: {src}"
            assert "type" in src, f"Source missing 'type' field: {src}"


class TestRuleEngineSinks:
    def test_python_has_sqli_sink(self, python_engine):
        sinks = python_engine.get_sinks()
        assert "sqli" in sinks or any(
            "execute" in str(v) for v in sinks.values()
        ), "Should have SQL injection sink"

    def test_python_has_rce_sink(self, python_engine):
        sinks = python_engine.get_sinks()
        all_patterns = [
            rule.get("pattern", "")
            for rules_list in sinks.values()
            for rule in rules_list
        ]
        assert any("os.system" in p or "exec" in p for p in all_patterns), (
            f"Should have command execution sink, got: {all_patterns}"
        )

    def test_javascript_has_exec_sink(self, javascript_engine):
        sinks = javascript_engine.get_sinks()
        all_patterns = [
            rule.get("pattern", "")
            for rules_list in sinks.values()
            for rule in rules_list
        ]
        assert any("exec" in p.lower() for p in all_patterns), (
            "JavaScript should have exec sink"
        )

    def test_sinks_have_severity_field(self, python_engine):
        sinks = python_engine.get_sinks()
        for category, rules_list in sinks.items():
            for rule in rules_list:
                assert "severity" in rule, (
                    f"Sink rule missing 'severity': {rule}"
                )
                assert rule["severity"].upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"), (
                    f"Invalid severity value: {rule['severity']}"
                )


class TestRuleEngineSanitizers:
    def test_python_has_sanitizers(self, python_engine):
        sanitizers = python_engine.get_sanitizers()
        assert len(sanitizers) > 0, "Should have at least one sanitizer"

    def test_sanitizers_have_pattern(self, python_engine):
        for san in python_engine.get_sanitizers():
            assert "pattern" in san, f"Sanitizer missing 'pattern': {san}"
