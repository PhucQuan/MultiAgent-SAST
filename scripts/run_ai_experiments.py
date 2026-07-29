"""Run configured AI experiments over normalized fixtures."""

import argparse
import json
import sys
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aegis_sast.ai.fixtures import load_ai_fixture_directory, load_ground_truth
from aegis_sast.orchestration.ai_workflow import AITriageWorkflow


LANGUAGES = ("python", "javascript", "java", "php")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        required=True,
        help="Experiment config JSON file.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("benchmarks/ai_experiments/results"),
        help="Directory for raw and summary outputs.",
    )
    args = parser.parse_args()

    config = json.loads(args.config.read_text(encoding="utf-8"))
    fixtures_root = Path(config["fixtures"])
    fixtures = _load_fixtures(fixtures_root)
    ground_truth = load_ground_truth(fixtures_root / "ground_truth.jsonl")
    run_count = int(config.get("run_count", 1))

    raw_rows = []
    summaries = []
    workflow = AITriageWorkflow()
    for run_index in range(run_count):
        state = workflow.run_batch(fixtures)
        summaries.append(state.metadata["execution_summary"])
        for decision in state.metadata["decisions"]:
            finding_id = decision["finding_id"]
            raw_rows.append(
                {
                    "experiment_id": config["experiment_id"],
                    "finding_id": finding_id,
                    "language": _fixture_language(fixtures, finding_id),
                    "vuln_type": _fixture_vuln_type(fixtures, finding_id),
                    "ground_truth": ground_truth.get(finding_id),
                    "predicted_status": decision["status"],
                    "route_taken": decision["route_taken"],
                    "model_name": decision.get("model_name"),
                    "prompt_version": config.get("prompt_version"),
                    "knowledge_version": config.get("knowledge_version"),
                    "token_usage": decision.get("token_usage", {}),
                    "latency_ms": decision.get("latency_ms"),
                    "error": None,
                    "run_index": run_index,
                }
            )

    args.out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = args.out_dir / f"{config['experiment_id']}.jsonl"
    with raw_path.open("w", encoding="utf-8") as handle:
        for row in raw_rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")

    summary = _aggregate_summary(config, raw_rows, summaries)
    summary_path = args.out_dir / f"{config['experiment_id']}.summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(f"Wrote raw results to {raw_path}")
    print(f"Wrote summary to {summary_path}")


def _load_fixtures(root: Path):
    fixtures = []
    for language in LANGUAGES:
        fixtures.extend(load_ai_fixture_directory(root / language))
    return fixtures


def _aggregate_summary(config: dict, raw_rows: list[dict], summaries: list[dict]) -> dict:
    status_counts: dict[str, int] = {}
    language_counts: dict[str, dict[str, int]] = {}
    route_counts: dict[str, int] = {}

    for row in raw_rows:
        status = row["predicted_status"]
        status_counts[status] = status_counts.get(status, 0) + 1
        language = row["language"]
        language_counts.setdefault(language, {})
        language_counts[language][status] = language_counts[language].get(status, 0) + 1
        route = " -> ".join(row["route_taken"])
        route_counts[route] = route_counts.get(route, 0) + 1

    return {
        "experiment_id": config["experiment_id"],
        "mode": config.get("mode"),
        "run_count": config.get("run_count", 1),
        "total_rows": len(raw_rows),
        "status_counts": status_counts,
        "language_status_counts": language_counts,
        "route_distribution": route_counts,
        "average_total_latency_ms": (
            mean(summary.get("total_latency_ms", 0.0) for summary in summaries)
            if summaries
            else 0.0
        ),
        "invalid_output_count": sum(
            summary.get("invalid_output_count", 0) for summary in summaries
        ),
        "api_error_count": sum(summary.get("api_error_count", 0) for summary in summaries),
    }


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
