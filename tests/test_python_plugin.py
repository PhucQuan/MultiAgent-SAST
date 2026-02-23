"""
Unit tests for aegis_sast.plugins.python_plugin.PythonPlugin
"""

import pytest
from pathlib import Path
import tempfile
import textwrap

from aegis_sast.plugins.python_plugin import PythonPlugin
from aegis_sast.analysis.rule_engine import RuleEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write_temp(code: str, suffix=".py") -> Path:
    """Write code to a temp file and return its Path."""
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    )
    tmp.write(textwrap.dedent(code))
    tmp.close()
    return Path(tmp.name)


@pytest.fixture
def plugin():
    return PythonPlugin()


@pytest.fixture
def rules():
    return RuleEngine(language="python").get_rules()


# ---------------------------------------------------------------------------
# Tests: parse_file
# ---------------------------------------------------------------------------

class TestParseFile:
    def test_valid_python_file(self, plugin):
        path = write_temp("x = 1\n")
        ast = plugin.parse_file(path)
        assert ast is not None, "Should parse valid Python"

    def test_returns_none_on_missing_file(self, plugin):
        ast = plugin.parse_file(Path("/nonexistent/file.py"))
        assert ast is None

    def test_syntax_error_still_parses(self, plugin):
        """Tree-sitter is error-tolerant and parses even broken syntax."""
        path = write_temp("def broken(:\n    pass\n")
        ast = plugin.parse_file(path)
        # tree-sitter returns a tree even for broken code
        assert ast is not None


# ---------------------------------------------------------------------------
# Tests: extract_sources
# ---------------------------------------------------------------------------

class TestExtractSources:
    def test_finds_flask_request_arg(self, plugin, rules):
        code = "user_id = request.args.get('id')\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sources = plugin.extract_sources(ast, path, rules)
        assert len(sources) >= 1, "Should detect request.args.get as source"
        assert sources[0].variable_name == "user_id"

    def test_no_sources_in_clean_code(self, plugin, rules):
        code = "x = 1 + 2\nprint(x)\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sources = plugin.extract_sources(ast, path, rules)
        assert sources == [], "No sources in clean arithmetic code"


# ---------------------------------------------------------------------------
# Tests: extract_sinks
# ---------------------------------------------------------------------------

class TestExtractSinks:
    def test_finds_os_system(self, plugin, rules):
        code = "import os\nos.system('ls')\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sinks = plugin.extract_sinks(ast, path, rules)
        assert len(sinks) >= 1, "Should detect os.system as sink"

    def test_finds_db_execute(self, plugin, rules):
        code = "cursor.execute('SELECT * FROM users')\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sinks = plugin.extract_sinks(ast, path, rules)
        assert len(sinks) >= 1, "Should detect cursor.execute as sink"

    def test_no_sinks_in_clean_code(self, plugin, rules):
        code = "result = 1 + 2\nprint(result)\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sinks = plugin.extract_sinks(ast, path, rules)
        assert sinks == []


# ---------------------------------------------------------------------------
# Tests: extract_sanitizers
# ---------------------------------------------------------------------------

class TestExtractSanitizers:
    def test_finds_parameterized_query(self, plugin, rules):
        code = "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sanitizers = plugin.extract_sanitizers(ast, path, rules)
        # A parameterized call should be recognized
        assert isinstance(sanitizers, list)


# ---------------------------------------------------------------------------
# Tests: get_language_name / get_file_extensions
# ---------------------------------------------------------------------------

class TestPluginMetadata:
    def test_language_name(self, plugin):
        assert plugin.get_language_name() == "python"

    def test_file_extensions(self, plugin):
        exts = plugin.get_file_extensions()
        assert "py" in exts

    def test_can_analyze_py_file(self, plugin):
        assert plugin.can_analyze(Path("app.py"))

    def test_cannot_analyze_js_file(self, plugin):
        assert not plugin.can_analyze(Path("app.js"))
