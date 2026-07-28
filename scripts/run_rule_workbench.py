"""Run the local Rule Workbench V1 development server."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegis_sast.rule_workbench.webapp import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_WORKSPACE_ROOT,
    serve_rule_workbench,
)


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser."""
    parser = argparse.ArgumentParser(
        description="Run the local Rule Workbench V1 server for reviewed rule bundles.",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help="Host interface to bind the local workbench server to.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="TCP port for the local workbench server.",
    )
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=DEFAULT_WORKSPACE_ROOT,
        help="Project workspace root used for seed inputs and artifact storage.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the workbench server until interrupted."""
    args = build_parser().parse_args(argv)
    serve_rule_workbench(
        host=args.host,
        port=args.port,
        workspace_root=args.workspace_root,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
