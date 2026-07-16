"""Tests for SARIF export."""

import json
from datetime import datetime

from aegis_sast.core.models import (
    CodeLocation,
    DataFlowPath,
    ScanResult,
    Severity,
    TaintSink,
    TaintSource,
    Vulnerability,
    VulnerabilityType,
)
from aegis_sast.integrations import SARIFFormatter
from aegis_sast.orchestration import ScanWorkflow


def test_sarif_formatter_exports_result(tmp_path):
    """SARIF export should produce one run with one result."""
    source_loc = CodeLocation("sample.py", 10, 1, "user = input()")
    sink_loc = CodeLocation("sample.py", 20, 1, "os.system(user)")
    source = TaintSource(source_loc, "USER_INPUT", "user", "input(")
    sink = TaintSink(
        sink_loc,
        VulnerabilityType.COMMAND_INJECTION,
        "os.system",
        "os.system(",
    )
    vuln = Vulnerability(
        id="VULN-001",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        dataflow=DataFlowPath(source=source, sink=sink),
    )
    result = ScanResult(
        target_path="sample.py",
        start_time=datetime.now(),
        end_time=datetime.now(),
        vulnerabilities=[vuln],
        files_scanned=1,
    )

    formatter = SARIFFormatter(tmp_path)
    output_path = formatter.export(result, filename="report.sarif")
    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert payload["version"] == "2.1.0"
    assert len(payload["runs"]) == 1
    assert len(payload["runs"][0]["results"]) == 1
    assert payload["runs"][0]["results"][0]["ruleId"] == "COMMAND_INJECTION"


def test_sarif_formatter_includes_workflow_summary_and_agent_reviews(tmp_path):
    """SARIF export should expose workflow summary and node-level reviews."""
    source_loc = CodeLocation("sample.py", 10, 1, "user = request.args.get('cmd')")
    step_loc = CodeLocation("sample.py", 12, 1, "cmd = user")
    sink_loc = CodeLocation("sample.py", 20, 1, "os.system(cmd)")
    source = TaintSource(source_loc, "HTTP_PARAM", "user", "request.args.get")
    sink = TaintSink(
        sink_loc,
        VulnerabilityType.COMMAND_INJECTION,
        "os.system",
        "os.system(",
    )
    vuln = Vulnerability(
        id="VULN-002",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        dataflow=DataFlowPath(source=source, sink=sink, intermediate_steps=[step_loc]),
    )
    result = ScanResult(
        target_path="sample.py",
        start_time=datetime.now(),
        end_time=datetime.now(),
        vulnerabilities=[vuln],
        files_scanned=1,
    )
    workflow_state = ScanWorkflow().run(result)

    formatter = SARIFFormatter(tmp_path)
    output_path = formatter.export(
        result,
        filename="report-with-workflow.sarif",
        triage_records=workflow_state.triage_records,
        workflow_metadata=workflow_state.metadata,
    )
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    run = payload["runs"][0]
    result_item = run["results"][0]

    assert run["properties"]["workflow_summary"]["scan_profile"] == "python-deep"
    assert "agent_reviews" in result_item["properties"]
    assert "judge_review" in result_item["properties"]["agent_reviews"]
