"""Test ghi quỹ đạo triage."""

from __future__ import annotations

import json

from ai.observability.trajectory import (
    build_trajectory,
    extract_state_features,
    write_trajectory,
)
from ai.schemas.state import GraphState, ValidatorAssessment
from ai.schemas.verdict import TriageState
from conftest import judge_decision, make_finding, verdict


def _state() -> GraphState:
    state = GraphState(
        finding=make_finding(severity="high"),
        run_id="run-1",
        commit_sha="a42e9df",
        auditor_verdict=verdict(exploitable=True, confidence=0.8),
        skeptic_verdict=verdict(exploitable=False, confidence=0.6),
        judge_decision=judge_decision(TriageState.NEEDS_REVIEW),
        triage_state=TriageState.NEEDS_REVIEW,
        tool_calls_used=2,
        debate_round=1,
    )
    state.completed_actions = [
        {
            "action": "get_dataflow_path",
            "arguments": {"file": "app.php", "line": 20},
            "success": True,
            "elapsed_ms": 12,
            "artifact_id": "ev_001",
            "source": "heuristic_policy",
        },
        {
            "action": "get_sanitizer_trace",
            "arguments": {"file": "app.php", "line": 20},
            "success": False,
            "elapsed_ms": 3,
            "error": "backend chưa được gắn",
            "source": "heuristic_policy",
        },
    ]
    state.policy_events = ["eligibility:eligible", "planned:get_dataflow_path"]
    return state


def test_initial_features_contain_only_pre_investigation_signals():
    """Đặc trưng khởi điểm không được chứa thứ chỉ biết sau khi tốn chi phí.

    Lẫn vào đây một đặc trưng hậu nghiệm sẽ khiến mô hình huấn luyện sau này
    rò rỉ thông tin tương lai và cho kết quả đẹp giả tạo.
    """
    features = extract_state_features(_state())

    assert set(features) == {
        "cwe",
        "severity",
        "language",
        "vuln_type",
        "taint_path_length",
        "cross_file_hops",
        "has_known_sanitizer",
        "scanner_confidence",
        "evidence_quality",
        "priority_score",
    }
    assert "verdict" not in features
    assert "triage_state" not in features


def test_trajectory_records_tool_and_llm_actions():
    """Lượt gọi LLM cũng là action — bỏ ra thì mô hình chi phí sai hoàn toàn."""
    trajectory = build_trajectory(_state())
    actions = [s.action for s in trajectory.steps]

    assert actions == [
        "GET_DATAFLOW_PATH",
        "GET_SANITIZER_TRACE",
        "ASK_AUDITOR",
        "ASK_SKEPTIC",
        "ASK_JUDGE",
    ]
    assert trajectory.steps[0].result_features["produced_evidence"] is True
    assert trajectory.steps[1].result_features["produced_evidence"] is False


def test_trajectory_label_source_defaults_to_model_not_ground_truth():
    """Nhãn mặc định phải nói rõ là do mô hình sinh, không phải đáp án thật.

    Huấn luyện trên nhãn của chính mô hình sẽ khuếch đại thiên kiến của nó,
    nên nguồn nhãn phải hiện diện trong dữ liệu chứ không nằm trong trí nhớ
    của người chạy benchmark.
    """
    trajectory = build_trajectory(_state())
    assert trajectory.label_source == "model_verdict"
    assert trajectory.terminal_label == "needs-review"

    with_truth = build_trajectory(
        _state(), label_source="benchmark_ground_truth", terminal_label="true_positive"
    )
    assert with_truth.label_source == "benchmark_ground_truth"
    assert with_truth.terminal_label == "true_positive"


def test_cost_summary_is_complete():
    trajectory = build_trajectory(_state())
    cost = trajectory.cost_summary

    assert cost["tool_calls_used"] == 2
    assert cost["debate_rounds"] == 1
    assert cost["llm_failed"] is False


def test_write_trajectory_appends_jsonl(tmp_path):
    path = tmp_path / "traj" / "run.jsonl"
    write_trajectory(build_trajectory(_state()), path)
    write_trajectory(build_trajectory(_state()), path)

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    record = json.loads(lines[0])
    assert record["commit_sha"] == "a42e9df"
    assert record["policy_events"][0] == "eligibility:eligible"


def test_trajectory_survives_state_without_llm_verdicts():
    """Finding bị gate loại sớm vẫn phải có quỹ đạo, dù không gọi LLM lần nào."""
    state = GraphState(
        finding=make_finding(severity="low"),
        triage_state=TriageState.NEEDS_REVIEW,
        validator_assessment=ValidatorAssessment(),
    )
    state.policy_events = ["eligibility:severity_below_medium"]

    trajectory = build_trajectory(state)
    assert trajectory.steps == []
    assert trajectory.cost_summary["tool_calls_used"] == 0
    assert trajectory.terminal_label == "needs-review"
