"""
End-to-end taint analysis tests using VulnerabilityDetector.
"""

import pytest
import tempfile
from pathlib import Path
import textwrap

pytest.importorskip("tree_sitter_python")

from aegis_sast.analysis.rule_engine import RuleEngine
from aegis_sast.analysis.vulnerability_detector import VulnerabilityDetector
from aegis_sast.core.registry import get_registry
from aegis_sast.plugins.python_plugin import PythonPlugin
from aegis_sast.core.models import Severity


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def make_detector():
    registry = get_registry()
    try:
        registry.register(PythonPlugin())
    except ValueError:
        pass
    rule_engine = RuleEngine(language="python")
    return VulnerabilityDetector(rule_engine)


def write_temp_dir(files: dict) -> Path:
    """
    Create a temp directory containing the given files.

    files = {"app.py": "code...", "utils.py": "code..."}
    """
    tmp_dir = Path(tempfile.mkdtemp())
    for name, content in files.items():
        (tmp_dir / name).write_text(textwrap.dedent(content), encoding="utf-8")
    return tmp_dir


def write_temp_file(code: str, suffix=".py") -> Path:
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    )
    tmp.write(textwrap.dedent(code))
    tmp.close()
    return Path(tmp.name)


# ---------------------------------------------------------------------------
# Tests: single-file taint
# ---------------------------------------------------------------------------

class TestSingleFileTaint:
    def test_detects_sqli(self):
        code = """\
            from flask import request
            import sqlite3

            def search():
                name = request.args.get('name')
                conn = sqlite3.connect('db')
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE name='" + name + "'")
        """
        path = write_temp_file(code)
        detector = make_detector()
        vulns = detector.analyze_file(path)
        types = [v.vuln_type.value for v in vulns]
        assert any("SQL" in t for t in types), (
            f"Expected SQL_INJECTION, got: {types}"
        )

    def test_detects_rce(self):
        code = """\
            import os
            from flask import request

            def run():
                cmd = request.args.get('cmd')
                os.system(cmd)
        """
        path = write_temp_file(code)
        detector = make_detector()
        vulns = detector.analyze_file(path)
        types = [v.vuln_type.value for v in vulns]
        assert any("COMMAND" in t or "CODE" in t for t in types), (
            f"Expected COMMAND_INJECTION, got: {types}"
        )

    def test_no_findings_on_safe_code(self):
        code = """\
            def add(a, b):
                return a + b

            result = add(1, 2)
            print(result)
        """
        path = write_temp_file(code)
        detector = make_detector()
        vulns = detector.analyze_file(path)
        assert vulns == [], f"Expected no findings, got: {vulns}"

    def test_parameterized_sql_query_is_not_reported(self):
        code = """\
            from flask import request

            def search(cursor):
                name = request.args.get('name')
                query = "SELECT * FROM users WHERE name = ?"
                cursor.execute(query, (name,))
        """
        path = write_temp_file(code)
        detector = make_detector()
        vulns = detector.analyze_file(path)
        assert all("SQL" not in v.vuln_type.value for v in vulns), (
            f"Parameterized execute() should not be reported as SQLi: {vulns}"
        )

    def test_detects_path_traversal_from_request_form_getlist_into_read_text(self):
        code = """\
            from flask import request
            import pathlib

            def read_file():
                values = request.form.getlist('file')
                name = values[0] if values else ''
                base = pathlib.Path('/tmp')
                target = base / name
                return target.read_text()
        """
        path = write_temp_file(code)
        detector = make_detector()
        vulns = detector.analyze_file(path)
        types = [v.vuln_type.value for v in vulns]
        assert any("PATH" in t for t in types), (
            f"Expected PATH_TRAVERSAL from getlist()->Path.read_text(), got: {types}"
        )

    def test_detects_path_traversal_from_request_header_names(self):
        code = """\
            from flask import request

            def read_file():
                param = ''
                for name in request.headers.keys():
                    param = name
                    break
                open(param, 'rb')
        """
        path = write_temp_file(code)
        detector = make_detector()
        vulns = detector.analyze_file(path)
        types = [v.vuln_type.value for v in vulns]
        assert any("PATH" in t for t in types), (
            f"Expected PATH_TRAVERSAL from request.headers.keys(), got: {types}"
        )

    def test_detects_path_traversal_from_request_query_string_manual_parse(self):
        code = """\
            from flask import request
            import urllib.parse

            def read_file():
                query_string = request.query_string.decode('utf-8')
                param_loc = query_string.find('file=')
                if param_loc == -1:
                    return 'missing'
                name = query_string[param_loc + len('file='):]
                amp_loc = name.find('&')
                if amp_loc != -1:
                    name = name[:amp_loc]
                name = urllib.parse.unquote_plus(name)
                open(name, 'rb')
        """
        tmp_dir = write_temp_dir({"app.py": code})
        path = tmp_dir / "app.py"
        detector = make_detector()
        vulns = detector.analyze_file(path, project_root=tmp_dir)
        types = [v.vuln_type.value for v in vulns]
        assert any("PATH" in t for t in types), (
            f"Expected PATH_TRAVERSAL from request.query_string manual parse, got: {types}"
        )

    def test_detects_nested_path_read_text_inside_multiline_statement(self):
        code = """\
            from flask import request
            import pathlib

            def read_file():
                name = request.args.get('file')
                base = pathlib.Path('/tmp')
                target = base / name
                response = (
                    f"Preview: "
                    f"{target.read_text()[:100]}"
                )
                return response
        """
        tmp_dir = write_temp_dir({"app.py": code})
        path = tmp_dir / "app.py"
        detector = make_detector()
        vulns = detector.analyze_file(path, project_root=tmp_dir)
        types = [v.vuln_type.value for v in vulns]
        assert any("PATH" in t for t in types), (
            f"Expected nested Path.read_text() sink to be detected, got: {types}"
        )

    def test_detects_path_traversal_across_match_case_assignment(self):
        code = """\
            from flask import request

            def read_file():
                param = request.headers.get('file')
                guess = 'A'
                match guess:
                    case 'A':
                        bar = param
                    case 'B':
                        bar = 'safe.txt'
                    case _:
                        bar = 'fallback.txt'
                open(bar, 'rb')
        """
        path = write_temp_file(code)
        detector = make_detector()
        vulns = detector.analyze_file(path)
        types = [v.vuln_type.value for v in vulns]
        assert any("PATH" in t for t in types), (
            f"Expected PATH_TRAVERSAL across match/case assignment, got: {types}"
        )

    def test_suppresses_path_traversal_when_constant_ifexp_resolves_safe_branch(self):
        code = """\
            from flask import request

            def read_file():
                name = request.args.get('file')
                num = 106
                target = 'safe.txt' if 7 * 18 + num > 200 else name
                open(target, 'rb')
        """
        path = write_temp_file(code)
        detector = make_detector()
        vulns = detector.analyze_file(path)
        assert all("PATH" not in v.vuln_type.value for v in vulns), (
            f"Constant-safe branch should not be reported as PATH_TRAVERSAL: {vulns}"
        )

    def test_suppresses_path_traversal_after_parent_dir_guard(self):
        code = """\
            from flask import request

            def read_file():
                name = request.args.get('file')
                if '../' in name:
                    return 'blocked'
                open(name, 'rb')
        """
        path = write_temp_file(code)
        detector = make_detector()
        vulns = detector.analyze_file(path)
        assert all("PATH" not in v.vuln_type.value for v in vulns), (
            f"Early-return parent-dir guard should suppress PATH_TRAVERSAL: {vulns}"
        )

    def test_suppresses_path_traversal_when_config_reads_safe_option(self):
        code = """\
            import configparser
            from flask import request

            def read_file():
                name = request.form.get('file')
                conf = configparser.ConfigParser()
                conf.add_section('demo')
                conf.set('demo', 'safe', 'notes.txt')
                conf.set('demo', 'user', name)
                target = conf.get('demo', 'safe')
                open(target, 'rb')
        """
        path = write_temp_file(code)
        detector = make_detector()
        vulns = detector.analyze_file(path)
        assert all("PATH" not in v.vuln_type.value for v in vulns), (
            f"Reading a safe ConfigParser option should not be reported: {vulns}"
        )

    def test_suppresses_path_traversal_when_list_slot_stays_safe(self):
        code = """\
            from flask import request

            def read_file():
                name = request.form.get('file')
                target = 'fallback.txt'
                if name:
                    bucket = []
                    bucket.append('safe.txt')
                    bucket.append(name)
                    bucket.append('later.txt')
                    bucket.pop(0)
                    target = bucket[1]
                open(target, 'rb')
        """
        path = write_temp_file(code)
        detector = make_detector()
        vulns = detector.analyze_file(path)
        assert all("PATH" not in v.vuln_type.value for v in vulns), (
            f"Reading a safe list slot should not be reported: {vulns}"
        )

    def test_suppresses_path_traversal_when_constant_match_selects_safe_case(self):
        code = """\
            from flask import request

            def read_file():
                name = request.headers.get('file')
                options = 'ABC'
                guess = options[1]
                match guess:
                    case 'A':
                        target = name
                    case 'B':
                        target = 'safe.txt'
                    case _:
                        target = 'fallback.txt'
                open(target, 'rb')
        """
        path = write_temp_file(code)
        detector = make_detector()
        vulns = detector.analyze_file(path)
        assert all("PATH" not in v.vuln_type.value for v in vulns), (
            f"Constant match safe branch should not be reported: {vulns}"
        )

    def test_suppresses_deserialization_when_constant_ifexp_resolves_safe_branch(self):
        code = """\
            from flask import request
            import yaml

            def load_payload():
                param = request.args.get('payload')
                num = 106
                bar = 'safe-text' if 7 * 18 + num > 200 else param
                yaml.load(bar, Loader=yaml.Loader)
        """
        tmp_dir = write_temp_dir({"app.py": code})
        path = tmp_dir / "app.py"
        detector = make_detector()
        vulns = detector.analyze_file(path, project_root=tmp_dir)
        assert all("DESERIALIZATION" not in v.vuln_type.value for v in vulns), (
            f"Constant-safe ifexp branch should not be reported as deserialization: {vulns}"
        )

    def test_keeps_deserialization_when_constant_ifexp_resolves_tainted_branch(self):
        code = """\
            from flask import request
            import base64
            import pickle

            def load_payload():
                param = request.headers.get('payload')
                num = 106
                bar = 'never-used' if 7 * 18 - num > 200 else param
                pickle.loads(base64.urlsafe_b64decode(bar))
        """
        tmp_dir = write_temp_dir({"app.py": code})
        path = tmp_dir / "app.py"
        detector = make_detector()
        vulns = detector.analyze_file(path, project_root=tmp_dir)
        types = [v.vuln_type.value for v in vulns]
        assert any("DESERIALIZATION" in t for t in types), (
            f"Tainted ifexp branch should still be reported as deserialization, got: {types}"
        )

    def test_suppresses_deserialization_when_constant_match_selects_safe_case(self):
        code = """\
            from flask import request
            import yaml

            def load_payload():
                param = request.headers.get('payload')
                possible = 'ABC'
                guess = possible[1]
                match guess:
                    case 'A':
                        bar = param
                    case 'B':
                        bar = 'bob'
                    case 'C' | 'D':
                        bar = param
                    case _:
                        bar = 'fallback'
                yaml.load(bar, Loader=yaml.Loader)
        """
        tmp_dir = write_temp_dir({"app.py": code})
        path = tmp_dir / "app.py"
        detector = make_detector()
        vulns = detector.analyze_file(path, project_root=tmp_dir)
        assert all("DESERIALIZATION" not in v.vuln_type.value for v in vulns), (
            f"Constant match safe branch should not be reported as deserialization: {vulns}"
        )

    def test_suppresses_deserialization_when_safe_dict_lookup_overwrites_bar(self):
        code = """\
            from flask import request
            import base64
            import pickle

            def load_payload():
                param = request.form.get('payload')
                mapping = {}
                mapping['keyA-demo'] = 'safe-value'
                mapping['keyB-demo'] = param
                bar = mapping['keyB-demo']
                bar = mapping['keyA-demo']
                pickle.loads(base64.urlsafe_b64decode(bar))
        """
        tmp_dir = write_temp_dir({"app.py": code})
        path = tmp_dir / "app.py"
        detector = make_detector()
        vulns = detector.analyze_file(path, project_root=tmp_dir)
        assert all("DESERIALIZATION" not in v.vuln_type.value for v in vulns), (
            f"Safe dict overwrite should not be reported as deserialization: {vulns}"
        )

    def test_suppresses_deserialization_when_safe_list_slot_is_selected(self):
        code = """\
            from flask import request
            import base64
            import pickle

            def load_payload():
                param = request.args.get('payload')
                bar = 'fallback'
                if param:
                    items = []
                    items.append('safe')
                    items.append(param)
                    items.append('moresafe')
                    items.pop(0)
                    bar = items[1]
                pickle.loads(base64.urlsafe_b64decode(bar))
        """
        tmp_dir = write_temp_dir({"app.py": code})
        path = tmp_dir / "app.py"
        detector = make_detector()
        vulns = detector.analyze_file(path, project_root=tmp_dir)
        assert all("DESERIALIZATION" not in v.vuln_type.value for v in vulns), (
            f"Safe list selection should not be reported as deserialization: {vulns}"
        )

    def test_suppresses_deserialization_when_constant_if_branch_selects_safe_value(self):
        code = """\
            from flask import request
            import yaml

            def load_payload():
                param = request.headers.get('payload')
                num = 86
                if 7 * 42 - num > 200:
                    bar = 'This_should_always_happen'
                else:
                    bar = param
                yaml.load(bar, Loader=yaml.Loader)
        """
        tmp_dir = write_temp_dir({"app.py": code})
        path = tmp_dir / "app.py"
        detector = make_detector()
        vulns = detector.analyze_file(path, project_root=tmp_dir)
        assert all("DESERIALIZATION" not in v.vuln_type.value for v in vulns), (
            f"Constant if safe branch should not be reported as deserialization: {vulns}"
        )

    def test_suppresses_command_injection_when_safe_dict_lookup_overwrites_bar(self):
        code = """\
            from flask import request
            import subprocess

            def run_command():
                param = request.form.get('cmd')
                mapping = {}
                mapping['keyA-demo'] = 'a-Value'
                mapping['keyB-demo'] = param
                bar = 'safe!'
                bar = mapping['keyB-demo']
                bar = mapping['keyA-demo']
                arg_str = 'sh -c '
                arg_str += f"echo {bar}"
                subprocess.run(arg_str, shell=True)
        """
        tmp_dir = write_temp_dir({"app.py": code})
        path = tmp_dir / "app.py"
        detector = make_detector()
        vulns = detector.analyze_file(path, project_root=tmp_dir)
        assert all("COMMAND" not in v.vuln_type.value for v in vulns), (
            f"Safe dict overwrite should not be reported as command injection: {vulns}"
        )

    def test_suppresses_command_injection_when_config_reads_safe_option(self):
        code = """\
            import configparser
            from flask import request
            import subprocess

            def run_command():
                param = request.headers.get('cmd')
                conf = configparser.ConfigParser()
                conf.add_section('demo')
                conf.set('demo', 'safe', 'a_Value')
                conf.set('demo', 'user', param)
                bar = conf.get('demo', 'safe')
                arg_str = 'sh -c '
                arg_str += f"echo {bar}"
                subprocess.run(arg_str, shell=True)
        """
        tmp_dir = write_temp_dir({"app.py": code})
        path = tmp_dir / "app.py"
        detector = make_detector()
        vulns = detector.analyze_file(path, project_root=tmp_dir)
        assert all("COMMAND" not in v.vuln_type.value for v in vulns), (
            f"Safe ConfigParser option should not be reported as command injection: {vulns}"
        )

    def test_keeps_command_injection_when_config_reads_tainted_option(self):
        code = """\
            import configparser
            from flask import request
            import subprocess

            def run_command():
                param = request.args.get('cmd')
                conf = configparser.ConfigParser()
                conf.add_section('demo')
                conf.set('demo', 'safe', 'a_Value')
                conf.set('demo', 'user', param)
                bar = conf.get('demo', 'user')
                arg_str = 'sh -c '
                arg_str += f"echo {bar}"
                subprocess.run(arg_str, shell=True)
        """
        tmp_dir = write_temp_dir({"app.py": code})
        path = tmp_dir / "app.py"
        detector = make_detector()
        vulns = detector.analyze_file(path, project_root=tmp_dir)
        types = [v.vuln_type.value for v in vulns]
        assert any("COMMAND" in t for t in types), (
            f"Tainted ConfigParser option should still be reported as command injection, got: {types}"
        )

    def test_keeps_path_traversal_when_config_reads_tainted_option(self):
        code = """\
            import configparser
            from flask import request

            def read_file():
                name = request.form.get('file')
                conf = configparser.ConfigParser()
                conf.add_section('demo')
                conf.set('demo', 'user', name)
                target = conf.get('demo', 'user')
                open(target, 'rb')
        """
        path = write_temp_file(code)
        detector = make_detector()
        vulns = detector.analyze_file(path)
        types = [v.vuln_type.value for v in vulns]
        assert any("PATH" in t for t in types), (
            f"Tainted ConfigParser option should still be reported, got: {types}"
        )

    def test_suppresses_path_traversal_when_try_body_reads_safe_config_option(self):
        code = """\
            import configparser
            import os
            from flask import request

            def read_file():
                name = request.form.get('file')
                conf = configparser.ConfigParser()
                conf.add_section('demo')
                conf.set('demo', 'safe', 'notes.txt')
                conf.set('demo', 'user', name)
                try:
                    target = conf.get('demo', 'safe')
                    os.path.exists(target)
                except OSError:
                    return False
        """
        path = write_temp_file(code)
        detector = make_detector()
        vulns = detector.analyze_file(path)
        assert all("PATH" not in v.vuln_type.value for v in vulns), (
            f"Safe ConfigParser option inside try-body should not be reported: {vulns}"
        )

    def test_keeps_path_traversal_when_try_body_reads_tainted_config_option_for_exists(self):
        code = """\
            import configparser
            import os
            from flask import request

            def read_file():
                name = request.form.get('file')
                conf = configparser.ConfigParser()
                conf.add_section('demo')
                conf.set('demo', 'safe', 'notes.txt')
                conf.set('demo', 'user', name)
                try:
                    target = conf.get('demo', 'user')
                    os.path.exists(target)
                except OSError:
                    return False
        """
        path = write_temp_file(code)
        detector = make_detector()
        vulns = detector.analyze_file(path)
        types = [v.vuln_type.value for v in vulns]
        assert any("PATH" in t for t in types), (
            f"Tainted ConfigParser option inside try-body should still be reported, got: {types}"
        )

    def test_xss_with_html_escape_is_detected_but_marked_lower_severity(self):
        code = """\
            from flask import request, render_template_string
            import html

            def show():
                payload = request.args.get('q')
                safe_payload = html.escape(payload)
                return render_template_string(safe_payload)
        """
        path = write_temp_file(code)
        detector = make_detector()
        vulns = detector.analyze_file(path)
        xss = [v for v in vulns if v.vuln_type.value == "XSS"]
        assert xss, f"Expected XSS finding from render_template_string(), got: {vulns}"
        assert xss[0].dataflow.is_sanitized() is True, "html.escape() should sanitize the XSS path"
        assert xss[0].severity == Severity.MEDIUM, (
            f"Sanitized XSS should be lowered to MEDIUM severity, got: {xss[0].severity}"
        )


class TestSeverity:
    def test_sqli_is_critical(self):
        code = """\
            from flask import request
            def search():
                name = request.args.get('q')
                conn = __import__('sqlite3').connect(':memory:')
                conn.execute('SELECT * FROM t WHERE n=' + name)
        """
        path = write_temp_file(code)
        detector = make_detector()
        vulns = detector.analyze_file(path)
        sqli = [v for v in vulns if "SQL" in v.vuln_type.value]
        if sqli:
            assert sqli[0].severity in (Severity.CRITICAL, Severity.HIGH), (
                f"SQLi should be CRITICAL or HIGH, got {sqli[0].severity}"
            )

    def test_path_traversal_is_high_or_above(self):
        code = """\
            from flask import request
            def read_file():
                name = request.args.get('file')
                return open(name).read()
        """
        path = write_temp_file(code)
        detector = make_detector()
        vulns = detector.analyze_file(path)
        pt = [v for v in vulns if "PATH" in v.vuln_type.value]
        if pt:
            assert pt[0].severity in (Severity.CRITICAL, Severity.HIGH), (
                f"Path traversal should be HIGH+, got {pt[0].severity}"
            )
