"""End-to-end tests for the AI-only normalized workflow."""

from pathlib import Path

from aegis_sast.ai.fixtures import load_ai_fixture_directory
from aegis_sast.orchestration.ai_workflow import AITriageWorkflow
from aegis_sast.orchestration.contracts import PlannerInput
from aegis_sast.orchestration.ai_nodes import PlannerAgentNode


FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "ai_findings"


def _fixtures():
    items = []
    for language in ("python", "javascript", "java", "php"):
        items.extend(load_ai_fixture_directory(FIXTURE_ROOT / language))
    return items


def test_planner_routes_high_confidence_complete_evidence_directly_to_judge():
    fixture = load_ai_fixture_directory(FIXTURE_ROOT / "python")[0]
    plan = PlannerAgentNode().plan(PlannerInput(triage_input=fixture))

    assert plan.should_use_skeptic is False
    assert "CWE-78" in plan.required_knowledge


def test_planner_routes_sanitizer_dead_path_and_missing_evidence_to_skeptic():
    fixtures = _fixtures()
    plans = {
        fixture.finding.finding_id: PlannerAgentNode().plan(PlannerInput(triage_input=fixture))
        for fixture in fixtures
    }

    assert plans["JS-SQLI-001"].should_use_skeptic is True
    assert "sanitizer-present" in plans["JS-SQLI-001"].route_hints
    assert plans["JAVA-PATH-001"].should_use_skeptic is True
    assert "dead-path" in plans["JAVA-PATH-001"].route_hints
    assert plans["PHP-XSS-001"].should_use_skeptic is True
    assert plans["PHP-XSS-001"].evidence_gaps


def test_ai_workflow_runs_four_languages_without_api_calls():
    state = AITriageWorkflow().run_batch(_fixtures())
    decisions = {decision["finding_id"]: decision for decision in state.metadata["decisions"]}
    summary = state.metadata["execution_summary"]

    assert state.errors == []
    assert decisions["PY-CMD-001"]["status"] == "confirmed"
    assert decisions["JS-SQLI-001"]["status"] == "suppressed"
    assert decisions["JAVA-PATH-001"]["status"] == "suppressed"
    assert decisions["PHP-XSS-001"]["status"] == "needs-review"
    assert summary["total_findings"] == 4
    assert summary["confirmed_count"] == 1
    assert summary["suppressed_count"] == 2
    assert summary["needs_review_count"] == 1
    assert any("skeptic_validator" in route for route in summary["route_distribution"])


def test_ai_workflow_attaches_report_enrichment_and_knowledge_card():
    decision = AITriageWorkflow().run_one(load_ai_fixture_directory(FIXTURE_ROOT / "python")[0])

    assert decision.metadata["knowledge_card_id"] == "cwe-78-command-injection"
    assert decision.metadata["report_enrichment"]["finding_id"] == "PY-CMD-001"
    assert decision.metadata["planner"]["should_use_skeptic"] is False
