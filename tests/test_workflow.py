"""Tests for the staged workflow-state orchestration layer."""

from datetime import datetime
from pathlib import Path

from aegis_sast.core.models import (
    AIVerification,
    CodeLocation,
    DataFlowPath,
    Sanitizer,
    ScanResult,
    Severity,
    TaintSink,
    TaintSource,
    Vulnerability,
    VulnerabilityType,
)
from aegis_sast.orchestration import ScanWorkflow


def test_scan_workflow_builds_state_with_route_and_triage_summaries():
    """Workflow state should capture both route and triage aggregate data."""
    python_source = TaintSource(
        CodeLocation("app.py", 10, 1, "cmd = request.args.get('cmd')"),
        "HTTP_PARAM",
        "cmd",
        "request.args.get",
    )
    python_sink = TaintSink(
        CodeLocation("app.py", 15, 1, "os.system(cmd)"),
        VulnerabilityType.COMMAND_INJECTION,
        "os.system",
        "os.system(",
    )
    python_vuln = Vulnerability(
        id="VULN-201",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        dataflow=DataFlowPath(
            source=python_source,
            sink=python_sink,
            intermediate_steps=[CodeLocation("app.py", 12, 1, "safe_cmd = cmd")],
        ),
        ai_verification=AIVerification(
            is_vulnerable=True,
            confidence=0.92,
            explanation="User-controlled command reaches shell execution.",
            recommendation="Use a fixed argument array.",
            model_used="test-model",
        ),
    )

    java_source = TaintSource(
        CodeLocation(
            "Controller.java",
            6,
            1,
            "String name = request.getParameter(\"name\");",
        ),
        "HTTP_PARAM",
        "name",
        "request.getParameter",
    )
    java_sink = TaintSink(
        CodeLocation(
            "Controller.java",
            12,
            1,
            "statement.executeQuery(query);",
        ),
        VulnerabilityType.SQL_INJECTION,
        "Statement.executeQuery",
        "executeQuery(",
    )
    sanitizer = Sanitizer(
        CodeLocation(
            "Controller.java",
            10,
            1,
            "PreparedStatement ps = conn.prepareStatement(sql);",
        ),
        "PREPARED_STATEMENT",
        "PreparedStatement",
        mitigates=[VulnerabilityType.SQL_INJECTION],
    )
    java_vuln = Vulnerability(
        id="VULN-202",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.HIGH,
        dataflow=DataFlowPath(
            source=java_source,
            sink=java_sink,
            sanitizers=[sanitizer],
        ),
    )

    result = ScanResult(
        target_path="demo-repo",
        start_time=datetime.now(),
        end_time=datetime.now(),
        vulnerabilities=[python_vuln, java_vuln],
        files_scanned=2,
    )

    state = ScanWorkflow().run(result)

    assert state.repo_profile is not None
    assert state.repo_profile.scan_profile == "polyglot-python-priority"
    assert state.repo_profile.detected_languages == ["java", "python"]
    assert state.metadata["triage_summary"]["confirmed"] == 1
    assert state.metadata["triage_summary"]["suppressed"] == 1
    assert state.metadata["route_summary"]["direct-judge"] == 1
    assert state.metadata["route_summary"]["skeptic-review"] == 1
    assert state.metadata["skeptic_summary"]["executed"] == 1
    assert state.traces[0].node_name == "repo_intake"
    assert state.traces[5].node_name == "skeptic_validator"
    assert len(state.traces) == 8


def test_scan_workflow_promotes_strong_sqli_to_likely(tmp_path):
    """Workflow should promote strong unmitigated SQLi findings to likely."""
    target = Path(tmp_path) / "app.py"
    target.write_text(
        "\n".join(
            [
                "import sqlite3",
                "user_id = request.args.get('id')",
                "query = \"SELECT * FROM users WHERE id = '\" + user_id + \"'\"",
                "cursor.execute(query)",
            ]
        ),
        encoding="utf-8",
    )

    source = TaintSource(
        CodeLocation(str(target), 2, 1, "user_id = request.args.get('id')"),
        "HTTP_PARAM",
        "user_id",
        "request.args.get",
    )
    sink = TaintSink(
        CodeLocation(str(target), 4, 1, "cursor.execute(query)"),
        VulnerabilityType.SQL_INJECTION,
        "cursor.execute",
        ".execute(",
    )
    vulnerability = Vulnerability(
        id="VULN-203",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        dataflow=DataFlowPath(source=source, sink=sink),
    )
    result = ScanResult(
        target_path=str(target),
        start_time=datetime.now(),
        end_time=datetime.now(),
        vulnerabilities=[vulnerability],
        files_scanned=1,
    )

    state = ScanWorkflow().run(result)

    assert state.metadata["triage_summary"]["likely"] == 1
    assert state.metadata["skeptic_summary"]["executed"] == 1
    assert state.triage_records[0].decision.status.value == "likely"
    assert state.triage_records[0].decision.confidence >= 0.72
