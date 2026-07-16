r"""Run the synthetic Python graph ablation benchmark and export reports.

Usage:
    python .\scripts\benchmark_python_graph_ablation.py
    python .\scripts\benchmark_python_graph_ablation.py --manifest path\to\manifest.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegis_sast.benchmarking import (  # noqa: E402
    PythonGraphAblationBenchmark,
    render_python_graph_ablation_markdown,
)


DEFAULT_MANIFEST = (
    REPO_ROOT
    / "datasets"
    / "synthetic"
    / "python_graph_ablation_v1_2"
    / "manifest.json"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the synthetic Python graph ablation benchmark.",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="Path to the synthetic dataset manifest.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "benchmarks" / "results" / "python_graph_ablation",
        help="Directory to write JSON and Markdown benchmark reports.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    benchmark = PythonGraphAblationBenchmark.from_manifest(args.manifest)
    result = benchmark.run()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = args.output_dir / f"python_graph_ablation_{timestamp}.json"
    markdown_path = args.output_dir / f"python_graph_ablation_{timestamp}.md"

    json_path.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    markdown_path.write_text(
        render_python_graph_ablation_markdown(result),
        encoding="utf-8",
    )

    print(f"[ok] manifest: {args.manifest}")
    for mode in result.modes:
        metrics = mode.metrics
        print(
            "[ok] mode",
            mode.mode,
            {
                "precision": round(metrics.precision, 3),
                "recall": round(metrics.recall, 3),
                "f1": round(metrics.f1, 3),
                "accuracy": round(metrics.accuracy, 3),
                "tp": metrics.tp,
                "fp": metrics.fp,
                "tn": metrics.tn,
                "fn": metrics.fn,
            },
        )
    print(f"[ok] json: {json_path}")
    print(f"[ok] markdown: {markdown_path}")


if __name__ == "__main__":
    main()
