"""Tests for locked AI triage input and final decision schemas."""

import pytest
from pydantic import ValidationError

from aegis_sast.triage.schema import (
    AITriageInput,
    BenchmarkMetadata,
    EvidenceBundle,
    NormalizedFinding,
    SanitizerInfo,
    SourceLocation,
    TriageDecision,
)


def _location(file_path: str = "app.py") -> SourceLocation:
    return SourceLocation(
        file_path=file_path,
        line_number=10,
        column_number=4,
        code_snippet="sink(user_input)",
    )


def _finding(language: str) -> NormalizedFinding:
    source = _location(f"src/source.{language}")
    sink = _location(f"src/sink.{language}")
    sanitizer = SanitizerInfo(
        present=False,
        effective=False,
        notes=["No sanitizer on deterministic source-to-sink path."],
    )
    return NormalizedFinding(
        finding_id=f"{language}-001",
        language=language,
        vuln_type="COMMAND_INJECTION",
        severity="HIGH",
        confidence=0.82,
        source_location=source,
        sink_location=sink,
        evidence_snippets=["user input reaches command sink"],
        data_flow_path=[source, sink],
        sanitizer_info=sanitizer,
        cross_file=False,
        call_chain_depth=1,
        rule_id="cmd-injection-user-input",
    )


def test_ai_triage_input_accepts_supported_languages_with_same_schema():
    """Python, JavaScript, Java, and PHP must share one AI input schema."""
    for language in ("python", "javascript", "java", "php"):
        finding = _finding(language)
        payload = AITriageInput(
            finding=finding,
            evidence=finding.to_evidence_bundle(),
            benchmark=BenchmarkMetadata(
                benchmark_id="synthetic-v1",
                dataset_name="unit",
                case_id=f"{language}-001",
                expected_status="likely",
                language=language,
            ),
        )

        assert payload.finding.language == language
        assert payload.evidence.source_location == finding.source_location
        assert payload.model_dump()["finding"]["rule_id"] == "cmd-injection-user-input"


def test_missing_required_finding_field_raises_clear_validation_error():
    """Required normalized finding fields should fail before any agent runs."""
    data = _finding("python").model_dump()
    data.pop("finding_id")

    with pytest.raises(ValidationError) as error:
        NormalizedFinding.model_validate(data)

    assert "finding_id" in str(error.value)
    assert "Field required" in str(error.value)


def test_triage_decision_is_structured_and_status_locked():
    """Final triage decisions must use the four agreed terminal statuses."""
    decision = TriageDecision(
        status="confirmed",
        confidence=0.91,
        vulnerability_explanation="Evidence includes a valid source-to-sink path.",
        remediation_note="Use a safe API and validate untrusted input.",
        supporting_evidence=["source app.py:10 reaches sink app.py:20"],
        limitations=[],
    )

    assert decision.status.value == "confirmed"
    assert decision.to_dict()["status"] == "confirmed"

    with pytest.raises(ValidationError) as error:
        TriageDecision(
            status="false-positive",
            confidence=0.2,
            vulnerability_explanation="Invalid status should not pass.",
            remediation_note="N/A",
        )

    assert "status" in str(error.value)


def test_ai_input_forbids_unstructured_repository_context():
    """AI payloads must not smuggle repo paths or AST parsing requests."""
    finding = _finding("python").model_dump()
    finding["repository_path"] = "/tmp/repo"

    with pytest.raises(ValidationError) as error:
        NormalizedFinding.model_validate(finding)

    assert "repository_path" in str(error.value)
    assert "Extra inputs are not permitted" in str(error.value)
