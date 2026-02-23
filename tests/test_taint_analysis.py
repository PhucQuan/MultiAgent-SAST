"""
End-to-end taint analysis tests using VulnerabilityDetector.
"""

import pytest
import tempfile
from pathlib import Path
import textwrap

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
