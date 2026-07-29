"""Run a local AI triage workflow ablation over mock fixtures."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aegis_sast.ai.fixtures import load_ai_fixture_directory, load_ground_truth
from aegis_sast.orchestration.ai_workflow import AITriageWorkflow


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixtures",
        type=Path,
        default=Path("tests/fixtures/ai_findings"),
        help="Root directory containing AI fixture JSON files.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("benchmarks/ai_ablation_mock_results.jsonl"),
        help="JSONL path for raw decisions.",
    )
    args = parser.parse_args()

    fixtures = []
    for language_dir in ("python", "javascript", "java", "php"):
        fixtures.extend(load_ai_fixture_directory(args.fixtures / language_dir))
    ground_truth = load_ground_truth(args.fixtures / "ground_truth.jsonl")
    state = AITriageWorkflow().run_batch(fixtures)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        for decision in state.metadata["decisions"]:
            finding_id = decision["finding_id"]
            row = {
                "experiment_id": "mock-ai-workflow-v1",
                "finding_id": finding_id,
                "language": _fixture_language(fixtures, finding_id),
                "vuln_type": _fixture_vuln_type(fixtures, finding_id),
                "ground_truth": ground_truth.get(finding_id),
                "predicted_status": decision["status"],
                "route_taken": decision["route_taken"],
                "model_name": decision.get("model_name"),
                "prompt_version": "deterministic-node-v1",
                "knowledge_version": "cwe-cards-v1",
                "token_usage": decision.get("token_usage", {}),
                "latency_ms": decision.get("latency_ms"),
                "error": None,
                "run_index": 0,
            }
            handle.write(json.dumps(row, sort_keys=True) + "\n")

    summary_path = args.out.with_suffix(".summary.json")
    summary_path.write_text(
        json.dumps(state.metadata["execution_summary"], indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(f"Wrote raw results to {args.out}")
    print(f"Wrote summary to {summary_path}")


def _fixture_language(fixtures, finding_id: str) -> str:
    for fixture in fixtures:
        if fixture.finding.finding_id == finding_id:
            return fixture.finding.language
    return "unknown"


def _fixture_vuln_type(fixtures, finding_id: str) -> str:
    for fixture in fixtures:
        if fixture.finding.finding_id == finding_id:
            return fixture.finding.vuln_type
    return "unknown"


if __name__ == "__main__":
    main()
