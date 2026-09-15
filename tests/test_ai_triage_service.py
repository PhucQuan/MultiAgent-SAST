"""Test façade AITriageService — ranh giới giữa Core SAST và tầng AI.

Không test nào ở đây gọi ra mạng: graph được thay bằng một stub trả về
GraphState dựng sẵn. Điều đang kiểm chứng là hợp đồng của façade — gate chạy
trước, provenance luôn có mặt, và cờ `applies_to_output` phản ánh đúng mode —
chứ không phải chất lượng suy luận của mô hình.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegis_sast.ai.api import (  # noqa: E402
    AITriageService,
    TriageRequest,
    TriageStatus,
    available_gateways,
    get_gateway,
)

pytest.importorskip("langgraph", reason="tầng AI là tuỳ chọn")

from ai import config as config_module  # noqa: E402
from ai.schemas.state import GraphState, ValidatorAssessment  # noqa: E402
from ai.schemas.verdict import JudgeDecision, TriageState  # noqa: E402


FINDING = {
    "finding_id": "f-001",
    "vuln_type": "SQL_INJECTION",
    "cwe": "CWE-89",
    "language": "python",
    "severity": "high",
    "confidence": 0.7,
    "evidence": {
        "source": {"file": "app.py", "line": 10, "code_slice": "request.args"},
        "sink": {"file": "app.py", "line": 20, "code_slice": "cur.execute"},
        "data_flow_path": [
            {"file": "app.py", "line": 10, "kind": "source", "code": "request.args"},
            {"file": "app.py", "line": 20, "kind": "sink", "code": "cur.execute"},
        ],
        "sanitizers_seen": [],
        "evidence_quality": 0.8,
    },
}


@pytest.fixture(autouse=True)
def _reset():
    config_module.reset_settings()
    yield
    config_module.reset_settings()


class _StubGraph:
    """Graph giả: trả về state dựng sẵn, đếm số lần được gọi."""

    def __init__(self, state_factory):
        self._factory = state_factory
        self.invocations = 0

    def invoke(self, state):
        self.invocations += 1
        return self._factory(state).model_dump()


def _confirmed_state(state: GraphState) -> GraphState:
    out = state.model_copy(deep=True)
    out.evidence.add(
        artifact_type="dataflow_path",
        producer="validator/get_dataflow_path",
        payload={"reaches_sink": True},
        file_path="app.py",
        line_start=20,
    )
    out.validator_assessment = ValidatorAssessment(
        dataflow_confirmed=True, evidence_ids=["ev_001"]
    )
    out.judge_decision = JudgeDecision(
        reasoning="Input tới sink, không có sanitizer.",
        correctness_score=0.9,
        severity_score=0.9,
        exploitability_score=0.9,
        triage_state=TriageState.CONFIRMED,
        confidence=0.88,
    )
    out.triage_state = TriageState.CONFIRMED
    out.policy_events = ["eligibility:eligible"]
    return out


def _request(**overrides) -> TriageRequest:
    payload = {
        "finding_id": "f-001",
        "commit_sha": "a42e9df",
        "normalized_finding": FINDING,
    }
    payload.update(overrides)
    return TriageRequest(**payload)


def test_verdict_carries_full_provenance(monkeypatch):
    """Verdict phải nói được nó đến từ prompt/graph/policy phiên bản nào."""
    monkeypatch.setenv("AEGIS_AI_MODE", "active")
    config_module.reset_settings()

    service = AITriageService(graph=_StubGraph(_confirmed_state), run_id="run-1")
    verdict = service.triage(_request())

    assert verdict.status is TriageStatus.TRUE_POSITIVE
    assert verdict.prompt_version
    assert verdict.graph_version
    assert verdict.policy_version
    assert verdict.evidence_ids == ["ev_001"]
    assert verdict.evidence[0].content_hash.startswith("sha256:")
    assert verdict.applies_to_output is True


def test_shadow_mode_produces_verdict_but_does_not_apply(monkeypatch):
    """Shadow: vẫn chạy và vẫn ghi lại, nhưng không được đổi output chính."""
    monkeypatch.setenv("AEGIS_AI_MODE", "shadow")
    config_module.reset_settings()

    service = AITriageService(graph=_StubGraph(_confirmed_state))
    verdict = service.triage(_request())

    assert verdict.status is TriageStatus.TRUE_POSITIVE
    assert verdict.applies_to_output is False
    assert verdict.ai_mode == "shadow"


def test_disabled_mode_never_invokes_graph(monkeypatch):
    """Mode disabled không được chạm tới graph, dù chỉ một lần."""
    monkeypatch.setenv("AEGIS_AI_MODE", "disabled")
    config_module.reset_settings()

    graph = _StubGraph(_confirmed_state)
    service = AITriageService(graph=graph)
    verdict = service.triage(_request())

    assert graph.invocations == 0
    assert verdict.status is TriageStatus.NEEDS_HUMAN_REVIEW
    assert verdict.applies_to_output is False
    assert any("ai_mode_disabled" in e for e in verdict.policy_events)


def test_scan_budget_is_shared_across_findings(monkeypatch):
    """Ngân sách tính cho cả lần quét, không phải cho từng finding."""
    monkeypatch.setenv("AEGIS_AI_MODE", "active")
    monkeypatch.setenv("AEGIS_MAX_LLM_FINDINGS_PER_SCAN", "2")
    monkeypatch.setenv("AEGIS_MAX_LLM_FINDINGS_PER_FILE", "10")
    config_module.reset_settings()

    graph = _StubGraph(_confirmed_state)
    service = AITriageService(graph=graph)

    for i in range(4):
        service.triage(_request(finding_id=f"f-{i}"))

    assert graph.invocations == 2
    assert service.scan_budget_used == 2

    service.reset_budget()
    service.triage(_request(finding_id="f-new"))
    assert graph.invocations == 3


def test_malformed_finding_does_not_crash_the_scan(monkeypatch):
    monkeypatch.setenv("AEGIS_AI_MODE", "active")
    config_module.reset_settings()

    service = AITriageService(graph=_StubGraph(_confirmed_state))
    verdict = service.triage(_request(normalized_finding={"finding_id": "broken"}))

    assert verdict.status is TriageStatus.INSUFFICIENT_EVIDENCE
    assert "không hợp schema" in verdict.rationale


def test_graph_failure_becomes_insufficient_evidence(monkeypatch):
    """Graph nổ thì finding ở lại báo cáo, không biến mất."""
    monkeypatch.setenv("AEGIS_AI_MODE", "active")
    config_module.reset_settings()

    class _Exploding:
        def invoke(self, state):
            raise RuntimeError("provider sập")

    service = AITriageService(graph=_Exploding())
    verdict = service.triage(_request())

    assert verdict.status is TriageStatus.INSUFFICIENT_EVIDENCE
    assert verdict.applies_to_output is False


def test_false_positive_without_evidence_is_downgraded(monkeypatch):
    """FP không trích được bằng chứng nào là mâu thuẫn nội tại — hạ cấp."""
    monkeypatch.setenv("AEGIS_AI_MODE", "active")
    config_module.reset_settings()

    def _empty_suppressed(state: GraphState) -> GraphState:
        out = state.model_copy(deep=True)
        out.triage_state = TriageState.SUPPRESSED
        return out

    service = AITriageService(graph=_StubGraph(_empty_suppressed))
    verdict = service.triage(_request())

    assert verdict.status is TriageStatus.INSUFFICIENT_EVIDENCE
    assert verdict.safe_suppression is False


def test_trajectory_is_written_when_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_AI_MODE", "shadow")
    config_module.reset_settings()

    path = tmp_path / "traj.jsonl"
    service = AITriageService(graph=_StubGraph(_confirmed_state), trajectory_path=path)
    service.triage(_request())

    assert path.exists()
    assert "f-001" in path.read_text(encoding="utf-8")


# --- gateway -------------------------------------------------------------
def test_mock_gateway_is_available_and_default():
    assert "mock" in available_gateways()
    gateway = get_gateway("mock")
    assert gateway.name == "mock"


def test_unknown_provider_is_rejected_not_silently_defaulted():
    """Lỗi chính tả trong config phải nổ, không được lặng lẽ đổi provider."""
    with pytest.raises(ValueError, match="provider không hỗ trợ"):
        get_gateway("nvidai_nim")


def test_all_gateways_expose_the_same_interface():
    for name in available_gateways():
        gateway = get_gateway(name)
        assert hasattr(gateway, "complete_json")
        assert gateway.name
