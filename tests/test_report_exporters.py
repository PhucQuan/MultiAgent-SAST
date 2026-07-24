"""Tests for JSON and Markdown report exporters with workflow metadata."""

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
from aegis_sast.orchestration import ScanWorkflow
from aegis_sast.reporting.json_exporter import JSONExporter
from aegis_sast.reporting.markdown_exporter import MarkdownExporter


def _build_scan_result() -> ScanResult:
    """Create a small scan result that exercises workflow metadata export."""
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
        id="VULN-REPORT-1",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        dataflow=DataFlowPath(
            source=source,
            sink=sink,
            intermediate_steps=[step_loc],
            metadata={
                "graph_summary": {
                    "node_count": 6,
                    "cfg_edge_count": 5,
                    "dfg_edge_count": 3,
                },
                "local_callee_summaries": [
                    {
                        "function_name": "get_cmd",
                        "call_site_line": 12,
                        "dependent_parameters": ["user"],
                        "return_count": 1,
                    }
                ],
            },
        ),
    )
    return ScanResult(
        target_path="sample.py",
        start_time=datetime.now(),
        end_time=datetime.now(),
        vulnerabilities=[vuln],
        files_scanned=1,
    )


def test_json_exporter_includes_workflow_summary_and_agent_reviews(tmp_path):
    """JSON report should expose workflow summary and node-level reviews."""
    scan_result = _build_scan_result()
    workflow_state = ScanWorkflow().run(scan_result)

    exporter = JSONExporter(tmp_path)
    output_path = exporter.export(
        scan_result,
        filename="report.json",
        triage_records=workflow_state.triage_records,
        workflow_metadata=workflow_state.metadata,
    )
    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert payload["workflow_summary"]["scan_profile"] == "python-deep"
    assert "auditor_summary" in payload["workflow_summary"]
    assert "agent_reviews" in payload["findings"][0]
    assert "judge_review" in payload["findings"][0]["agent_reviews"]


def test_markdown_exporter_includes_workflow_and_agent_review_sections(tmp_path):
    """Markdown report should render workflow and node review summaries."""
    scan_result = _build_scan_result()
    workflow_state = ScanWorkflow().run(scan_result)

    exporter = MarkdownExporter(tmp_path)
    output_path = exporter.export(
        scan_result,
        filename="report.md",
        triage_records=workflow_state.triage_records,
        workflow_metadata=workflow_state.metadata,
    )
    content = output_path.read_text(encoding="utf-8")

    assert "## Workflow Summary" in content
    assert "**Agent Reviews**" in content
    assert "auditor:" in content
    assert "**Evidence Summary**" in content
    assert "**Graph Summary**" in content
    assert "**Local Helper Summaries**" in content
    assert "get_cmd" in content
