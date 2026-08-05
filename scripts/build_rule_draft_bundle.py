"""Build an AI-ready normalized rule draft from a description and a local seed.

Examples:
  python scripts/build_rule_draft_bundle.py ^
    --description "Sources: request.args.get()\nSinks: subprocess.run(), os.system()" ^
    --seed-input datasets/synthetic/rule_review_v1/seed_inputs/python_command_injection_semgrep_shape.yaml ^
    --output-dir reports/rule_review/python_command_injection_draft ^
    --language python ^
    --family COMMAND_INJECTION
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegis_sast.rule_workbench.service import build_draft_bundle


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Build an AI-ready draft bundle from a natural-language description "
            "and a local reviewed seed snapshot."
        ),
    )
    parser.add_argument(
        "--description",
        help="Natural-language description for the desired rule adaptation.",
    )
    parser.add_argument(
        "--description-file",
        type=Path,
        help="Optional UTF-8 text file containing the natural-language description.",
    )
    parser.add_argument(
        "--seed-input",
        type=Path,
        required=True,
        help="Local seed input (Semgrep-shaped or normalized JSON/YAML) used as the adaptation base.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory to write draft artifacts into.",
    )
    parser.add_argument(
        "--language",
        required=True,
        help="Target language such as python.",
    )
    parser.add_argument(
        "--family",
        required=True,
        help="Target vulnerability family such as COMMAND_INJECTION.",
    )
    parser.add_argument(
        "--profile",
        default="generic",
        help="Validation profile such as python-rule-workbench-v1.",
    )
    parser.add_argument(
        "--normalized-format",
        choices=["json", "yaml"],
        default="json",
        help="Output format for the normalized draft rule.",
    )
    parser.add_argument(
        "--validation-format",
        choices=["text", "json"],
        default="json",
        help="Output format for the validation report.",
    )
    parser.add_argument(
        "--legacy-format",
        choices=["json", "yaml"],
        help="Optional output format for a legacy bridge document.",
    )
    parser.add_argument(
        "--provenance-source",
        default="ai-adapted",
        help="Logical provenance source recorded in the draft rule.",
    )
    parser.add_argument(
        "--snapshot-version",
        default="draft-v1",
        help="Snapshot label recorded in provenance metadata.",
    )
    parser.add_argument(
        "--rule-id",
        help="Optional explicit rule id to use in the draft output.",
    )
    parser.add_argument(
        "--title",
        help="Optional explicit title to use in the draft output.",
    )
    return parser


def resolve_description(args) -> str:
    """Resolve the draft description from inline text or a file."""
    inline_description = (args.description or "").strip()
    file_description = ""
    if args.description_file is not None:
        file_description = args.description_file.read_text(encoding="utf-8").strip()

    description = inline_description or file_description
    if not description:
        raise ValueError("Supply either --description or --description-file.")
    return description


def main(argv: list[str] | None = None) -> int:
    """Run the CLI draft-bundle builder."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        result = build_draft_bundle(
            description=resolve_description(args),
            seed_input_path=args.seed_input,
            output_dir=args.output_dir,
            language=args.language,
            family=args.family,
            profile=args.profile,
            normalized_format=args.normalized_format,
            validation_format=args.validation_format,
            provenance_source=args.provenance_source,
            snapshot_version=args.snapshot_version,
            legacy_format=args.legacy_format,
            rule_id=args.rule_id,
            title=args.title,
        )
    except FileNotFoundError as exc:
        parser.error(str(exc))
    except (RuntimeError, ValueError) as exc:
        print(f"[error] {exc}")
        print("Environment check: python scripts/doctor_env.py")
        print("Install dependencies: pip install -r requirements.txt")
        return 1

    print(f"Draft rule -> {result['draft_path']}")
    print(f"Validation report -> {result['validation_path']}")
    print(f"AI prompt -> {result['prompt_path']}")
    print(f"Seed context -> {result['seed_context_path']}")
    if result["legacy_path"]:
        print(f"Legacy rules -> {result['legacy_path']}")
        print(f"Legacy export report -> {result['legacy_report_path']}")
    print(
        "Draft summary: "
        f"rules={result['rules_checked']}, "
        f"errors={result['error_count']}, "
        f"warnings={result['warning_count']}"
    )
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
