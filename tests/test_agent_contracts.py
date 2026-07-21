"""Tests for structured AI agent contracts and workflow state."""

import pytest
from pydantic import BaseModel, ValidationError

from aegis_sast.orchestration.contracts import (
    AuditorResult,
    AuditorReview,
    JudgeReview,
    SkepticResult,
)
from aegis_sast.orchestration.state import AgentWorkflowState
from aegis_sast.triage.schema import (
    AITriageInput,
    EvidenceBundle,
    NormalizedFinding,
    SanitizerInfo,
    SourceLocation,
    TriageDecision,
)


def _location() -> SourceLocation:
    return SourceLocation(
        file_path="app.py",
        line_number=1,
        column_number=0,
        code_snippet="user = request.args.get('cmd')",
    )


def _ai_input() -> AITriageInput:
    source = _location()
    sink = SourceLocation(
        file_path="app.py",
        line_number=2,
        column_number=0,
        code_snippet="os.system(user)",
    )
    sanitizer = SanitizerInfo(present=False, effective=False)
    finding = NormalizedFinding(
        finding_id="F-001",
        language="python",
        vuln_type="COMMAND_INJECTION",
        severity="HIGH",
        confidence=0.8,
        source_location=source,
        sink_location=sink,
        evidence_snippets=["request cmd reaches os.system"],
        data_flow_path=[source, sink],
        sanitizer_info=sanitizer,
        cross_file=False,
        call_chain_depth=1,
        rule_id="python-command-injection",
    )
    return AITriageInput(
        finding=finding,
        evidence=EvidenceBundle(
            source_location=source,
            sink_location=sink,
            evidence_snippets=finding.evidence_snippets,
            data_flow_path=finding.data_flow_path,
            sanitizer_info=sanitizer,
            cross_file=False,
            call_chain_depth=1,
        ),
    )


def test_agent_node_outputs_are_pydantic_contracts():
    auditor = AuditorResult(
        is_exploitable=True,
        confidence=0.86,
        evidence_strength="strong",
        sanitizer_effective=False,
        reasoning_summary="Source-to-sink path is complete.",
        missing_evidence=[],
    )
    skeptic = SkepticResult(
        objections=[],
        false_positive_indicators=[],
        sanitizer_found=False,
        dead_code_suspected=False,
        recommended_status="likely",
        confidence=0.74,
    )
    judge = TriageDecision(
        status="likely",
        confidence=0.78,
        vulnerability_explanation="The path is exploitable but lacks runtime proof.",
        remediation_note="Avoid shell execution with untrusted input.",
        supporting_evidence=["app.py:1 -> app.py:2"],
        limitations=["No runtime reachability proof."],
    )

    assert isinstance(auditor, BaseModel)
    assert isinstance(skeptic, BaseModel)
    assert isinstance(judge, BaseModel)
    assert judge.to_dict()["status"] == "likely"


def test_agent_contracts_reject_free_text_or_extra_fields():
    with pytest.raises(ValidationError) as error:
        AuditorResult.model_validate(
            {
                "is_exploitable": True,
                "confidence": 0.9,
                "evidence_strength": "strong",
                "sanitizer_effective": False,
                "reasoning_summary": "Valid structured summary.",
                "missing_evidence": [],
                "raw_text": "unstructured model prose",
            }
        )

    assert "raw_text" in str(error.value)
    assert "Extra inputs are not permitted" in str(error.value)


def test_workflow_review_backfills_required_auditor_contract_fields():
    review = AuditorReview(
        finding_id="F-001",
        route_id="skeptic-review",
        route_steps=["auditor", "skeptic", "judge"],
        evidence_score=0.79,
        summary="Auditor reviewed deterministic evidence.",
    )

    assert review.is_exploitable is True
    assert review.confidence == pytest.approx(0.79)
    assert review.evidence_strength == "strong"
    assert review.to_dict()["route_id"] == "skeptic-review"


def test_agent_workflow_state_only_accepts_normalized_ai_inputs():
    state = AgentWorkflowState(triage_inputs=[_ai_input()])

    assert state.triage_inputs[0].finding.finding_id == "F-001"

    with pytest.raises(ValidationError) as error:
        AgentWorkflowState.model_validate({"triage_inputs": [{"repository_path": "."}]})

    assert "finding" in str(error.value)
    assert "evidence" in str(error.value)


def test_judge_review_is_structured_output():
    review = JudgeReview(
        finding_id="F-001",
        final_status="confirmed",
        final_confidence=0.93,
        summary="Judge confirmed the deterministic path.",
    )

    assert isinstance(review, BaseModel)
    assert review.to_dict()["final_status"] == "confirmed"
