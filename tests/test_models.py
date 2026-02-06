"""
Unit tests for core models.

Tests data model classes and their methods.
"""

import pytest
from datetime import datetime

from aegis_sast.core.models import (
    Severity,
    VulnerabilityType,
    CodeLocation,
    TaintSource,
    TaintSink,
    Sanitizer,
    DataFlowPath,
    Vulnerability,
    ScanResult
)


def test_code_location():
    """Test CodeLocation model."""
    loc = CodeLocation(
        file_path="/test/file.py",
        line_number=42,
        column_number=10,
        code_snippet="x = input()"
    )
    
    assert str(loc) == "/test/file.py:42:10"


def test_taint_source():
    """Test TaintSource model."""
    loc = CodeLocation("/test/file.py", 10, 5, "user_input = input()")
    
    source = TaintSource(
        location=loc,
        source_type="USER_INPUT",
        variable_name="user_input",
        pattern="input("
    )
    
    assert "USER_INPUT" in str(source)


def test_sanitizer_effectiveness():
    """Test Sanitizer.is_effective_against()."""
    loc = CodeLocation("/test/file.py", 15, 0, "safe = escape()")
    
    sanitizer = Sanitizer(
        location=loc,
        sanitizer_type="SQL_ESCAPE",
        function_name="escape",
        mitigates=[VulnerabilityType.SQL_INJECTION]
    )
    
    assert sanitizer.is_effective_against(VulnerabilityType.SQL_INJECTION) is True
    assert sanitizer.is_effective_against(VulnerabilityType.COMMAND_INJECTION) is False


def test_dataflow_path_sanitization():
    """Test DataFlowPath.is_sanitized()."""
    source_loc = CodeLocation("/test/file.py", 10, 0, "x = input()")
    sink_loc = CodeLocation("/test/file.py", 20, 0, "execute(query)")
    
    source = TaintSource(source_loc, "USER_INPUT", "x", "input(")
    sink = TaintSink(sink_loc, VulnerabilityType.SQL_INJECTION, "execute", "execute(")
    
    # Without sanitizer
    path1 = DataFlowPath(source=source, sink=sink, sanitizers=[])
    assert path1.is_sanitized() is False
    
    # With ineffective sanitizer
    san_loc = CodeLocation("/test/file.py", 15, 0, "y = html_escape(x)")
    sanitizer = Sanitizer(
        san_loc,
        "HTML_ESCAPE",
        "html_escape",
        mitigates=[VulnerabilityType.CODE_INJECTION]  # Not SQL_INJECTION
    )
    path2 = DataFlowPath(source=source, sink=sink, sanitizers=[sanitizer])
    assert path2.is_sanitized() is False
    
    # With effective sanitizer
    sql_san = Sanitizer(
        san_loc,
        "SQL_ESCAPE",
        "sql_escape",
        mitigates=[VulnerabilityType.SQL_INJECTION]
    )
    path3 = DataFlowPath(source=source, sink=sink, sanitizers=[sql_san])
    assert path3.is_sanitized() is True


def test_vulnerability_to_dict():
    """Test Vulnerability.to_dict()."""
    source_loc = CodeLocation("/test/file.py", 10, 0, "x = input()")
    sink_loc = CodeLocation("/test/file.py", 20, 0, "os.system(x)")
    
    source = TaintSource(source_loc, "USER_INPUT", "x", "input(")
    sink = TaintSink(sink_loc, VulnerabilityType.COMMAND_INJECTION, "os.system", "os.system(")
    
    path = DataFlowPath(source=source, sink=sink)
    
    vuln = Vulnerability(
        id="VULN-001",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        dataflow=path
    )
    
    result = vuln.to_dict()
    
    assert result["id"] == "VULN-001"
    assert result["type"] == "COMMAND_INJECTION"
    assert result["severity"] == "CRITICAL"
    assert result["file"] == "/test/file.py"
    assert result["line"] == 20


def test_scan_result_summary():
    """Test ScanResult summary methods."""
    start = datetime.now()
    
    scan = ScanResult(
        target_path="/test/project",
        start_time=start,
        end_time=datetime.now(),
        files_scanned=10
    )
    
    # Add mock vulnerabilities
    source_loc = CodeLocation("/test/file.py", 10, 0, "x = input()")
    sink_loc = CodeLocation("/test/file.py", 20, 0, "execute(x)")
    source = TaintSource(source_loc, "USER_INPUT", "x", "input(")
    
    # Critical
    sink1 = TaintSink(sink_loc, VulnerabilityType.SQL_INJECTION, "execute", "execute(")
    path1 = DataFlowPath(source=source, sink=sink1)
    vuln1 = Vulnerability("VULN-001", VulnerabilityType.SQL_INJECTION, Severity.CRITICAL, path1)
    
    # High
    sink2 = TaintSink(sink_loc, VulnerabilityType.COMMAND_INJECTION, "system", "system(")
    path2 = DataFlowPath(source=source, sink=sink2)
    vuln2 = Vulnerability("VULN-002", VulnerabilityType.COMMAND_INJECTION, Severity.HIGH, path2)
    
    scan.vulnerabilities = [vuln1, vuln2]
    
    assert scan.total_vulnerabilities == 2
    assert scan.critical_count == 1
    assert scan.high_count == 1
    assert scan.medium_count == 0
    
    summary = scan.get_summary()
    assert summary["total_vulnerabilities"] == 2
    assert summary["by_severity"]["critical"] == 1
    assert summary["by_severity"]["high"] == 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
