"""Test Task 3 — schema, đặc biệt quy tắc reasoning-trước-verdict."""

import pytest
from pydantic import ValidationError

from ai.schemas.finding import Language, NormalizedFinding
from ai.schemas.state import GraphState
from ai.schemas.verdict import AgentVerdict, JudgeDecision, TriageState
from conftest import make_finding


def test_reasoning_precedes_verdict_in_agent_verdict():
    fields = list(AgentVerdict.model_fields)
    assert fields.index("reasoning") < fields.index("exploitable")
    assert fields.index("reasoning") < fields.index("confidence")


def test_reasoning_precedes_triage_state_in_judge_decision():
    fields = list(JudgeDecision.model_fields)
    assert fields.index("reasoning") < fields.index("triage_state")


def test_json_schema_property_order_keeps_reasoning_first():
    """Thứ tự trong JSON schema mới là thứ tự LLM sinh token."""
    for schema in (AgentVerdict, JudgeDecision):
        props = list(schema.model_json_schema()["properties"])
        assert props[0] == "reasoning"


def test_confidence_bounds_enforced():
    with pytest.raises(ValidationError):
        AgentVerdict(reasoning="x", exploitable=True, confidence=1.5)


def test_triage_state_values():
    assert {s.value for s in TriageState} == {
        "confirmed",
        "likely",
        "needs-review",
        "suppressed",
    }


def test_finding_roundtrip():
    f = make_finding(language=Language.JAVASCRIPT, cwe="CWE-78")
    restored = NormalizedFinding.model_validate_json(f.model_dump_json())
    assert restored == f


def test_graph_state_defaults():
    state = GraphState(finding=make_finding())
    assert state.debate_round == 0
    assert state.llm_failed is False
    assert state.skeptic_mode == "neutral"
    assert state.triage_state is None
