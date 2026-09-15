"""Test Task 6 — prompt template."""

from ai.prompts.auditor import build_auditor_prompt
from ai.prompts.hypothesis_builder import build_hypothesis_prompt
from ai.prompts.judge import SENSITIVE_CWES, build_judge_prompt
from ai.prompts.skeptic import build_skeptic_prompt


def test_hypothesis_prompt_forbids_pruning():
    msgs = build_hypothesis_prompt('{"finding_id": "x"}')
    assert msgs[0]["role"] == "system"
    assert "KHÔNG được lọc/pruning" in msgs[0]["content"]
    assert '{"finding_id": "x"}' in msgs[1]["content"]


def test_auditor_prompt_embeds_cards_and_rules():
    cards = [{"cwe": "CWE-89", "fp_indicators": ["đã prepare"]}]
    msgs = build_auditor_prompt("{}", "{}", cards)
    assert "reasoning ĐẶT TRƯỚC verdict" in msgs[0]["content"]
    assert "fp_indicators" in msgs[1]["content"]
    assert "đã prepare" in msgs[1]["content"]


def test_auditor_prompt_includes_tool_results():
    msgs = build_auditor_prompt(
        "{}",
        "{}",
        [],
        prior_tool_results=[
            {"name": "get_callers", "args": {"function_name": "q"}, "result": "[]"}
        ],
    )
    assert "get_callers" in msgs[1]["content"]


def test_skeptic_modes_use_different_system_prompts():
    neutral = build_skeptic_prompt("{}", "{}", "{}", [], mode="neutral")
    adversarial = build_skeptic_prompt("{}", "{}", "{}", [], mode="adversarial")
    assert "TRUNG LẬP" in neutral[0]["content"]
    assert "false-positive hunter" in adversarial[0]["content"]
    assert "Q1" in adversarial[0]["content"]
    assert neutral[0]["content"] != adversarial[0]["content"]


def test_judge_prompt_flags_policies():
    msgs = build_judge_prompt(
        "{}", "{}", None, llm_failed=True, debate_hard_stopped=True, cwe="CWE-327"
    )
    body = msgs[1]["content"]
    assert "fail-open" in body
    assert "hard-stop" in body
    assert "anti-over-suppression" in body


def test_judge_prompt_without_special_policy():
    msgs = build_judge_prompt(
        "{}", "{}", None, llm_failed=False, debate_hard_stopped=False, cwe="CWE-89"
    )
    assert "(không có policy đặc biệt)" in msgs[1]["content"]


def test_judge_prompt_omits_skeptic_section_when_absent():
    msgs = build_judge_prompt("{}", "{}", None, False, False, "CWE-89")
    assert "Skeptic verdict" not in msgs[1]["content"]
    with_skeptic = build_judge_prompt("{}", "{}", '{"x": 1}', False, False, "CWE-89")
    assert "Skeptic verdict" in with_skeptic[1]["content"]


def test_sensitive_cwe_set_matches_guide():
    assert SENSITIVE_CWES == {
        "CWE-327",
        "CWE-328",
        "CWE-501",
        "CWE-798",
        "CWE-311",
        "CWE-522",
        "CWE-863",
        "CWE-862",
    }
