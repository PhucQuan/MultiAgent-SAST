"""
Unit tests for Python plugin.

Tests Tree-sitter parsing and taint source/sink extraction.
"""

import pytest
from pathlib import Path

from aegis_sast.plugins.python_plugin import PythonPlugin
from aegis_sast.core.models import VulnerabilityType


@pytest.fixture
def plugin():
    """Create PythonPlugin instance."""
    return PythonPlugin()


@pytest.fixture
def sample_code_path(tmp_path):
    """Create temporary Python file with vulnerable code."""
    code = """
import os
from flask import request

def vulnerable_function():
    user_input = request.args.get('cmd')
    os.system(user_input)
"""
    
    file_path = tmp_path / "test_vuln.py"
    file_path.write_text(code)
    return file_path


def test_plugin_initialization(plugin):
    """Test plugin initializes correctly."""
    assert plugin.get_language_name() == "python"
    assert "py" in plugin.get_file_extensions()


def test_can_analyze_python_file(plugin, sample_code_path):
    """Test plugin recognizes Python files."""
    assert plugin.can_analyze(sample_code_path) is True
    
    # Should not analyze non-Python files
    txt_file = Path("test.txt")
    assert plugin.can_analyze(txt_file) is False


def test_parse_file(plugin, sample_code_path):
    """Test file parsing."""
    ast = plugin.parse_file(sample_code_path)
    assert ast is not None
    assert ast.root_node is not None


def test_extract_sources(plugin, sample_code_path):
    """Test taint source extraction."""
    ast = plugin.parse_file(sample_code_path)
    
    rules = {
        "sources": [
            {"pattern": "request.args.get", "type": "HTTP_PARAM", "severity": "HIGH"}
        ]
    }
    
    sources = plugin.extract_sources(ast, sample_code_path, rules)
    
    assert len(sources) > 0
    assert any(s.source_type == "HTTP_PARAM" for s in sources)


def test_extract_sinks(plugin, sample_code_path):
    """Test taint sink extraction."""
    ast = plugin.parse_file(sample_code_path)
    
    rules = {
        "sinks": {
            "rce": [
                {"pattern": "os.system(", "type": "COMMAND_INJECTION", "severity": "CRITICAL"}
            ]
        }
    }
    
    sinks = plugin.extract_sinks(ast, sample_code_path, rules)
    
    assert len(sinks) > 0
    assert any(s.sink_type == VulnerabilityType.COMMAND_INJECTION for s in sinks)


def test_map_vuln_type(plugin):
    """Test vulnerability type mapping."""
    assert plugin._map_vuln_type("SQL_INJECTION") == VulnerabilityType.SQL_INJECTION
    assert plugin._map_vuln_type("COMMAND_INJECTION") == VulnerabilityType.COMMAND_INJECTION
    assert plugin._map_vuln_type("PATH_TRAVERSAL") == VulnerabilityType.PATH_TRAVERSAL


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
