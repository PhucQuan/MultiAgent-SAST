"""Build a prompt-ready codebase context pack for large-repo AI workflows.

Examples:
  python scripts/build_context_pack.py
  python scripts/build_context_pack.py --output reports/context/dashboard_context.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[0]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegis_sast.utils.context_pack import (  # noqa: E402
    build_context_pack,
    context_pack_to_dict,
    render_context_pack_markdown,
)


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser."""
    parser = argparse.ArgumentParser(
        description="Generate a Markdown/JSON context pack for large repo AI work.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root to inspect. Defaults to the current Aegis-SAST repo.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "reports" / "context" / "codebase_context.md",
        help="Markdown output path.",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        default=REPO_ROOT / "reports" / "context" / "codebase_context.json",
        help="JSON output path.",
    )
    parser.add_argument(
        "--hotspots",
        type=int,
        default=12,
        help="How many hotspot files to include.",
    )
    parser.add_argument(
        "--import-hubs",
        type=int,
        default=12,
        help="How many internal Python import hubs to include.",
    )
    return parser


def write_outputs(
    markdown_output: Path,
    json_output: Path,
    *,
    markdown_content: str,
    json_payload: dict[str, object],
) -> None:
    """Write Markdown and JSON outputs to disk."""
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.parent.mkdir(parents=True, exist_ok=True)

    markdown_output.write_text(markdown_content, encoding="utf-8")
    json_output.write_text(
        json.dumps(json_payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    """Run the context-pack generator."""
    parser = build_parser()
    args = parser.parse_args(argv)

    context_pack = build_context_pack(
        args.repo_root,
        hotspot_limit=max(args.hotspots, 0),
        import_hub_limit=max(args.import_hubs, 0),
    )

    markdown_content = render_context_pack_markdown(context_pack)
    json_payload = context_pack_to_dict(context_pack)
    write_outputs(
        args.output,
        args.json_output,
        markdown_content=markdown_content,
        json_payload=json_payload,
    )

    print("Context pack generated")
    print(f"- repo: {args.repo_root}")
    print(f"- markdown: {args.output}")
    print(f"- json: {args.json_output}")
    print(f"- modules: {len(context_pack.module_summaries)}")
    print(f"- entry points: {len(context_pack.entry_points)}")
    print(f"- hotspots: {len(context_pack.hotspots)}")
    print(f"- import hubs: {len(context_pack.import_hubs)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
