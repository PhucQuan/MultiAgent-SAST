"""Tests for the knowledge-assisted triage engine."""

from aegis_sast.core.models import (
    AIVerification,
    CodeLocation,
    DataFlowPath,
    Sanitizer,
    Severity,
    TaintSink,
    TaintSource,
    Vulnerability,
    VulnerabilityType,
)
from aegis_sast.triage import TriageEngine


def test_triage_engine_marks_strong_unsanitized_flow_as_confirmed():
    """High-confidence AI and unsanitized evidence should stay confirmed."""
    source_loc = CodeLocation("app.py", 10, 1, "user = request.args.get('cmd')")
    step_loc = CodeLocation("app.py", 12, 1, "cmd = user")
    sink_loc = CodeLocation("app.py", 20, 1, "os.system(cmd)")
    source = TaintSource(source_loc, "HTTP_PARAM", "user", "request.args.get")
    sink = TaintSink(
        sink_loc,
        VulnerabilityType.COMMAND_INJECTION,
        "os.system",
        "os.system(",
    )
    vuln = Vulnerability(
        id="VULN-100",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        dataflow=DataFlowPath(source=source, sink=sink, intermediate_steps=[step_loc]),
        ai_verification=AIVerification(
            is_vulnerable=True,
            confidence=0.93,
            explanation="Untrusted data reaches a shell sink.",
            recommendation="Use a fixed command array.",
            model_used="test-model",
        ),
    )

    record = TriageEngine().triage_vulnerability(vuln)

    assert record.decision.status.value == "confirmed"
    assert "generic-command-injection" in record.decision.metadata["knowledge_card_ids"]
    assert record.decision.metadata["triage_input_schema"] == "aegis-triage-input-v1"
    assert record.finding.metadata["workflow_route"]["steps"][-2] == "judge"
    assert "generic-command-injection" in record.finding.metadata["triage"]["knowledge_card_ids"]
    assert record.finding.metadata["triage"]["workflow_route"]["steps"][-2] == "judge"
    assert record.finding.metadata["triage"]["workflow_route"]["metadata"]["path_length"] == 3
    assert record.finding.to_triage_input()["evidence"]["summary"]["path_length"] == 3
    assert "path_length=3" in record.decision.evidence_notes
    assert "workflow-route:direct-judge" in record.decision.reason_codes
    assert "knowledge-card-match" in record.decision.reason_codes
    assert record.decision.manual_review_required is False


def test_triage_engine_suppresses_sanitized_low_confidence_flow():
    """Sanitized, weaker findings should be suppressed conservatively."""
    source_loc = CodeLocation("app.py", 5, 1, "name = request.args.get('name')")
    sink_loc = CodeLocation("app.py", 15, 1, "cursor.execute(query, params)")
    sanitizer_loc = CodeLocation("app.py", 12, 1, "cursor.execute(query, params)")
    source = TaintSource(source_loc, "HTTP_PARAM", "name", "request.args.get")
    sink = TaintSink(
        sink_loc,
        VulnerabilityType.SQL_INJECTION,
        "execute",
        "execute(",
    )
    sanitizer = Sanitizer(
        sanitizer_loc,
        "PARAMETERIZED_QUERY",
        "execute",
        mitigates=[VulnerabilityType.SQL_INJECTION],
    )
    vuln = Vulnerability(
        id="VULN-101",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.HIGH,
        dataflow=DataFlowPath(source=source, sink=sink, sanitizers=[sanitizer]),
    )

    record = TriageEngine().triage_vulnerability(vuln)

    assert record.decision.status.value == "suppressed"
    assert record.decision.confidence <= 0.5
    assert "generic-sqli" in record.decision.metadata["knowledge_card_ids"]
    assert record.decision.metadata["triage_input_schema"] == "aegis-triage-input-v1"
    assert record.finding.metadata["triage"]["reviewer"] == "triage-engine-v1"
    assert record.finding.metadata["triage"]["workflow_route"]["metadata"]["path_length"] == 3
    assert "sanitizers=1" in record.decision.evidence_notes
    assert "effective-sanitizer" in record.decision.reason_codes
    assert record.decision.manual_review_required is True
