"""Tests for node prompt boundaries."""

from aegis_sast.ai.prompts import (
    get_auditor_prompt,
    get_judge_structured_prompt,
    get_planner_prompt,
    get_reporter_prompt,
    get_skeptic_prompt,
)
from tests.test_agent_contracts import _ai_input


def test_node_prompts_use_observed_evidence_sections_and_forbid_repo_reads():
    fixture = _ai_input()
    prompts = [
        get_planner_prompt(fixture),
        get_auditor_prompt(fixture, "knowledge summary"),
        get_skeptic_prompt(fixture, "auditor summary"),
        get_judge_structured_prompt(fixture, ["planner", "auditor", "judge"]),
        get_reporter_prompt(fixture, '{"status":"likely"}'),
    ]

    for prompt in prompts:
        assert "Observed evidence" in prompt
        assert "Inference" in prompt
        assert "Missing evidence" in prompt
        assert "Final assessment" in prompt
        assert "repository" in prompt.lower() or "repo" in prompt.lower()


def test_planner_prompt_does_not_ask_for_final_status():
    prompt = get_planner_prompt(_ai_input())

    assert "Do not decide final status" in prompt
    assert "PlannerResult" in prompt
