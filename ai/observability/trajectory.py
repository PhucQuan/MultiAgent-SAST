"""Ghi quỹ đạo triage để chuẩn bị contextual bandit / offline RL.

Chưa có policy học máy nào ở đây, và đó là chủ ý: chính sách hiện tại là
rule-based. Nhưng dữ liệu để huấn luyện một chính sách tốt hơn chỉ tồn tại
nếu được ghi ngay từ bây giờ — không thể dựng lại quỹ đạo của những lần chạy
đã qua. Vì vậy mỗi lượt triage đều xuất ra một bản ghi state - action - cost -
outcome, kể cả khi không ai định huấn luyện gì.

Bài toán về sau: với một finding, chọn action tiếp theo để đạt verdict đúng
với chi phí thấp nhất, mà không làm giảm recall của nhóm High/Critical. Ràng
buộc thứ hai mới là phần khó — một chính sách tối ưu thuần chi phí sẽ học cách
không bao giờ điều tra, vì không điều tra thì không tốn gì.

Quỹ đạo được ghi dạng JSONL để nối thêm được giữa các lần chạy và đọc lại
từng dòng mà không phải nạp cả tệp.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..policies.eligibility import priority_score
from ..schemas.state import GraphState


@dataclass
class TrajectoryStep:
    """Một bước trong quỹ đạo: đã làm gì, thu được gì, tốn bao nhiêu."""

    t: int
    action: str
    action_source: str
    result_features: dict = field(default_factory=dict)
    cost: dict = field(default_factory=dict)


@dataclass
class Trajectory:
    """Toàn bộ quỹ đạo của một finding."""

    episode_id: str
    finding_id: str
    commit_sha: str
    run_id: str
    recorded_at: str
    initial_state_features: dict
    steps: list[TrajectoryStep]
    terminal_label: str
    label_source: str
    policy_events: list[str]
    cost_summary: dict

    def to_dict(self) -> dict:
        return {
            **{k: v for k, v in asdict(self).items() if k != "steps"},
            "steps": [asdict(s) for s in self.steps],
        }


def extract_state_features(state: GraphState) -> dict:
    """Đặc trưng của finding trước khi điều tra.

    Chỉ gồm thứ biết được TRƯỚC khi tốn chi phí — nếu lẫn vào đây một đặc
    trưng chỉ có sau khi đã gọi tool thì mô hình huấn luyện sau này sẽ rò rỉ
    thông tin tương lai và cho kết quả đẹp giả tạo.
    """
    finding = state.finding
    ev = finding.evidence
    files = {step.file for step in ev.data_flow_path}
    return {
        "cwe": finding.cwe,
        "severity": finding.severity,
        "language": finding.language.value,
        "vuln_type": finding.vuln_type,
        "taint_path_length": len(ev.data_flow_path),
        "cross_file_hops": max(len(files) - 1, 0),
        "has_known_sanitizer": bool(ev.sanitizers_seen),
        "scanner_confidence": finding.confidence,
        "evidence_quality": ev.evidence_quality,
        "priority_score": round(priority_score(finding), 4),
    }


def build_trajectory(
    state: GraphState,
    *,
    label_source: str = "model_verdict",
    terminal_label: str | None = None,
) -> Trajectory:
    """Dựng quỹ đạo từ state cuối cùng của một lượt triage.

    `label_source` mặc định là `model_verdict`, không phải ground truth. Phân
    biệt này quan trọng: huấn luyện trên nhãn do chính mô hình sinh ra sẽ
    khuếch đại thiên kiến của nó. Khi chạy trên benchmark có đáp án, phía gọi
    truyền `label_source="benchmark_ground_truth"` kèm nhãn thật.
    """
    steps: list[TrajectoryStep] = []

    for i, done in enumerate(state.completed_actions):
        steps.append(
            TrajectoryStep(
                t=i,
                action=done.get("action", "unknown").upper(),
                action_source=done.get("source", "heuristic_policy"),
                result_features={
                    "success": done.get("success", False),
                    "produced_evidence": bool(done.get("artifact_id")),
                    "truncated": done.get("truncated", False),
                },
                cost={"latency_ms": done.get("elapsed_ms", 0), "tokens": 0},
            )
        )

    # Lượt gọi LLM cũng là action, và là action đắt nhất — bỏ chúng ra khỏi
    # quỹ đạo thì mô hình chi phí sẽ sai hoàn toàn.
    for label, verdict in (
        ("ASK_AUDITOR", state.auditor_verdict),
        ("ASK_SKEPTIC", state.skeptic_verdict),
    ):
        if verdict is None:
            continue
        steps.append(
            TrajectoryStep(
                t=len(steps),
                action=label,
                action_source="heuristic_policy",
                result_features={
                    "exploitable": verdict.exploitable,
                    "confidence": verdict.confidence,
                    "citation_count": len(verdict.grounded_citations),
                },
                cost={"latency_ms": 0, "tokens": 0},
            )
        )

    if state.judge_decision is not None:
        steps.append(
            TrajectoryStep(
                t=len(steps),
                action="ASK_JUDGE",
                action_source="heuristic_policy",
                result_features={
                    "triage_state": state.judge_decision.triage_state.value,
                    "confidence": state.judge_decision.confidence,
                },
                cost={"latency_ms": 0, "tokens": 0},
            )
        )

    label = terminal_label or (
        state.triage_state.value if state.triage_state else "unknown"
    )

    return Trajectory(
        episode_id=f"ep_{state.finding.finding_id}",
        finding_id=state.finding.finding_id,
        commit_sha=state.commit_sha,
        run_id=state.run_id,
        recorded_at=datetime.now(timezone.utc).isoformat(),
        initial_state_features=extract_state_features(state),
        steps=steps,
        terminal_label=label,
        label_source=label_source,
        policy_events=list(state.policy_events),
        cost_summary={
            "tool_calls_used": state.tool_calls_used,
            "tokens_used": state.tokens_used,
            "elapsed_ms": state.elapsed_ms,
            "debate_rounds": state.debate_round,
            "evidence_artifacts": len(state.evidence),
            "llm_failed": state.llm_failed,
        },
    )


def write_trajectory(trajectory: Trajectory, path: Path) -> None:
    """Nối một quỹ đạo vào tệp JSONL."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(trajectory.to_dict(), ensure_ascii=False) + "\n")
