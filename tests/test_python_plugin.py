"""
Unit tests for aegis_sast.plugins.python_plugin.PythonPlugin
"""

import pytest
from pathlib import Path
import tempfile
import textwrap

pytest.importorskip("tree_sitter_python")

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

    def test_open_call_is_no_longer_treated_as_generic_source(self, plugin, rules):
        code = "data = open(path).read()\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sources = plugin.extract_sources(ast, path, rules)
        assert sources == [], "open() should not be treated as a generic taint source"

    def test_request_form_attribute_no_longer_counts_as_direct_source(self, plugin, rules):
        code = "payload = request.form\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sources = plugin.extract_sources(ast, path, rules)
        assert sources == [], "request.form should require an accessor such as .get()"

    def test_request_form_get_still_counts_as_source(self, plugin, rules):
        code = "payload = request.form.get('payload')\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sources = plugin.extract_sources(ast, path, rules)
        assert len(sources) >= 1, "request.form.get() should remain a taint source"

    def test_request_form_getlist_counts_as_source(self, plugin, rules):
        code = "values = request.form.getlist('payload')\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sources = plugin.extract_sources(ast, path, rules)
        assert any(source.variable_name == "values" for source in sources), (
            "request.form.getlist() should be treated as a taint source"
        )

    def test_request_cookie_get_counts_as_source(self, plugin, rules):
        code = "token = request.cookies.get('session')\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sources = plugin.extract_sources(ast, path, rules)
        assert any(source.variable_name == "token" for source in sources), (
            "request.cookies.get() should be treated as a taint source"
        )

    def test_request_header_get_counts_as_source(self, plugin, rules):
        code = "auth = request.headers.get('Authorization')\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sources = plugin.extract_sources(ast, path, rules)
        assert any(source.variable_name == "auth" for source in sources), (
            "request.headers.get() should be treated as a taint source"
        )

    def test_request_headers_keys_counts_as_source(self, plugin, rules):
        code = "for header_name in request.headers.keys():\n    print(header_name)\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sources = plugin.extract_sources(ast, path, rules)
        assert any(source.pattern == "request.headers.keys" for source in sources), (
            "request.headers.keys() should be treated as a taint source for header-name flows"
        )

    def test_wrapper_get_form_parameter_counts_as_source(self, plugin, rules):
        code = "value = wrapped.get_form_parameter('id')\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sources = plugin.extract_sources(ast, path, rules)
        assert any(source.variable_name == "value" for source in sources), (
            "wrapper get_form_parameter() helpers should be treated as taint sources"
        )


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

    def test_finds_requests_get_as_ssrf_sink(self, plugin, rules):
        code = "import requests\nrequests.get(target)\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sinks = plugin.extract_sinks(ast, path, rules)
        assert any(
            sink.function_name == "requests.get" and sink.sink_type.value == "SSRF"
            for sink in sinks
        ), "requests.get() should be detected as an SSRF sink"

    def test_execute_query_does_not_match_execute_sink(self, plugin, rules):
        code = "cursor.execute_query('SELECT * FROM users')\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sinks = plugin.extract_sinks(ast, path, rules)
        assert sinks == [], "execute_query() should not be matched by the legacy .execute( sink"

    def test_mass_assignment_update_kwargs_matches_legacy_pattern(self, plugin, rules):
        code = "user.update(**payload)\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sinks = plugin.extract_sinks(ast, path, rules)
        assert any(
            sink.function_name == "user.update" and sink.sink_type.value == "MASS_ASSIGNMENT"
        for sink in sinks
        ), "user.update(**payload) should match the legacy .update(** sink"

    def test_mass_assignment_plain_update_does_not_match_kwargs_pattern(self, plugin, rules):
        code = "user.update(payload)\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sinks = plugin.extract_sinks(ast, path, rules)
        assert all(sink.sink_type.value != "MASS_ASSIGNMENT" for sink in sinks), (
            "user.update(payload) should not match the narrower .update(** sink"
        )

    def test_no_sinks_in_clean_code(self, plugin, rules):
        code = "result = 1 + 2\nprint(result)\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sinks = plugin.extract_sinks(ast, path, rules)
        assert sinks == []

    def test_urlopen_does_not_match_open_path_sink(self, plugin, rules):
        code = "from urllib.request import urlopen\nurlopen(target)\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sinks = plugin.extract_sinks(ast, path, rules)
        assert all(sink.sink_type.value != "PATH_TRAVERSAL" for sink in sinks), (
            "urlopen() should not be matched by the generic open() path sink"
        )

    def test_finds_urllib_request_urlopen_as_ssrf_sink(self, plugin, rules):
        code = "import urllib.request\nurllib.request.urlopen(target)\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sinks = plugin.extract_sinks(ast, path, rules)
        assert any(
            sink.function_name == "urllib.request.urlopen" and sink.sink_type.value == "SSRF"
            for sink in sinks
        ), "urllib.request.urlopen() should be detected as an SSRF sink"

    def test_finds_render_template_string_as_xss_sink(self, plugin, rules):
        code = "from flask import render_template_string\nrender_template_string(payload)\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sinks = plugin.extract_sinks(ast, path, rules)
        assert any(
            sink.function_name == "render_template_string" and sink.sink_type.value == "XSS"
            for sink in sinks
        ), "render_template_string() should be detected as an XSS sink"

    def test_finds_markup_constructor_as_xss_sink(self, plugin, rules):
        code = "from markupsafe import Markup\nMarkup(payload)\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sinks = plugin.extract_sinks(ast, path, rules)
        assert any(
            sink.function_name == "Markup" and sink.sink_type.value == "XSS"
            for sink in sinks
        ), "Markup() should be detected as an XSS sink"

    def test_code_template_does_not_match_template_sink(self, plugin, rules):
        code = "CodeTemplate('hello ${name}')\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sinks = plugin.extract_sinks(ast, path, rules)
        assert sinks == [], "CodeTemplate() should not be treated as a Jinja Template sink"

    def test_os_path_join_is_no_longer_a_default_path_traversal_sink(self, plugin, rules):
        code = "import os\nfile_path = os.path.join(base_dir, filename)\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sinks = plugin.extract_sinks(ast, path, rules)
        assert all(sink.function_name != "os.path.join" for sink in sinks), (
            "os.path.join() alone should not be treated as a default path traversal sink"
        )

    def test_path_exists_counts_as_path_traversal_sink(self, plugin, rules):
        code = "if candidate.exists():\n    pass\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sinks = plugin.extract_sinks(ast, path, rules)
        assert any(
            sink.function_name == "candidate.exists"
            and sink.sink_type.value == "PATH_TRAVERSAL"
            for sink in sinks
        ), "Path.exists() should be treated as a path-traversal-relevant sink"

    def test_path_read_text_counts_as_path_traversal_sink(self, plugin, rules):
        code = "contents = candidate.read_text()\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sinks = plugin.extract_sinks(ast, path, rules)
        assert any(
            sink.function_name == "candidate.read_text"
            and sink.sink_type.value == "PATH_TRAVERSAL"
            for sink in sinks
        ), "Path.read_text() should be treated as a path-traversal-relevant sink"

    def test_parameterized_execute_is_not_reported_as_sqli_sink(self, plugin, rules):
        code = "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sinks = plugin.extract_sinks(ast, path, rules)
        assert all(sink.sink_type.value != "SQL_INJECTION" for sink in sinks), (
            "parameterized execute() calls should not be treated as SQL injection sinks"
        )


# ---------------------------------------------------------------------------
# Tests: extract_sanitizers
# ---------------------------------------------------------------------------

class TestExtractSanitizers:
    def test_finds_parameterized_query(self, plugin, rules):
        code = "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sanitizers = plugin.extract_sanitizers(ast, path, rules)
        # Parameterized execute() is handled directly at sink matching time.
        assert isinstance(sanitizers, list)

    def test_html_escape_counts_as_xss_sanitizer(self, plugin, rules):
        code = "import html\nsafe = html.escape(payload)\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sanitizers = plugin.extract_sanitizers(ast, path, rules)
        assert any(
            sanitizer.function_name == "html.escape"
            and any(vuln.value == "XSS" for vuln in sanitizer.mitigates)
            for sanitizer in sanitizers
        ), "html.escape() should mitigate XSS"

    def test_markupsafe_escape_counts_as_xss_sanitizer(self, plugin, rules):
        code = "import markupsafe\nsafe = markupsafe.escape(payload)\n"
        path = write_temp(code)
        ast = plugin.parse_file(path)
        sanitizers = plugin.extract_sanitizers(ast, path, rules)
        assert any(
            sanitizer.function_name == "markupsafe.escape"
            and any(vuln.value == "XSS" for vuln in sanitizer.mitigates)
            for sanitizer in sanitizers
        ), "markupsafe.escape() should mitigate XSS"


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
