"""Chạy thử end-to-end với NVIDIA NIM thật (theo mục 13 của build guide).

    python -m ai.e2e_demo

Cần `NVIDIA_API_KEY` trong `.env`. Script này GỌI API THẬT và tốn credit —
test tự động trong `ai/tests/` đều dùng LLM giả, không chạm mạng.
"""

from ai.graph.build import run_triage
from ai.llm.nvidia_client import llm_client
from ai.schemas.finding import (
    DataFlowStep,
    EvidenceBundle,
    Language,
    Location,
    NormalizedFinding,
)

finding = NormalizedFinding(
    finding_id="test-001",
    vuln_type="SQL_INJECTION",
    cwe="CWE-89",
    language=Language.PHP,
    severity="high",
    confidence=0.7,
    evidence=EvidenceBundle(
        source=Location(
            file="app.php", line=10, code_slice="$name = $_POST['name']; //potential"
        ),
        sink=Location(
            file="app.php",
            line=20,
            code_slice='mysqli_query($conn, "SELECT * FROM users WHERE name = \'$name\'"); //potential',
        ),
        data_flow_path=[
            DataFlowStep(file="app.php", line=10, kind="source", code="$_POST['name']"),
            DataFlowStep(file="app.php", line=20, kind="sink", code="mysqli_query(...)"),
        ],
        evidence_quality=0.8,
    ),
)


def main() -> None:
    final = run_triage(finding)

    print(f"Triage: {final.triage_state}")
    print(f"Debate rounds: {final.debate_round}")
    print(f"LLM failed: {final.llm_failed}")
    print(f"Skeptic mode: {final.skeptic_mode}")
    print(f"Tool calls: {len(final.tool_calls_made)}")
    if final.judge_decision:
        print(f"Reasoning: {final.judge_decision.reasoning}")
        print(f"Policy: {final.judge_decision.policy_applied}")
    print(f"Usage: {llm_client.get_usage_summary()}")


if __name__ == "__main__":
    main()
