"""Utilities for loading AI triage mock-data fixtures."""

import json
from pathlib import Path
from typing import Dict, List, Tuple

from pydantic import ValidationError

from aegis_sast.triage.schema import AITriageInput


class AIFixtureLoadError(ValueError):
    """Raised when one or more AI fixture files fail validation."""


def load_ai_fixture(path: Path) -> AITriageInput:
    """Load one AI triage fixture without ground-truth leakage."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    data.pop("ground_truth", None)
    return AITriageInput.model_validate(data)


def load_ai_fixture_directory(root: Path) -> List[AITriageInput]:
    """Load all JSON AI fixtures below a directory."""
    fixtures: List[AITriageInput] = []
    errors: Dict[str, str] = {}
    for path in sorted(Path(root).rglob("*.json")):
        if path.name == "ground_truth.json":
            continue
        try:
            fixtures.append(load_ai_fixture(path))
        except (json.JSONDecodeError, ValidationError, ValueError) as exc:
            errors[str(path)] = str(exc)

    if errors:
        details = "; ".join(f"{path}: {message}" for path, message in errors.items())
        raise AIFixtureLoadError(details)
    return fixtures


def load_ground_truth(path: Path) -> Dict[str, Dict[str, object]]:
    """Load ground truth from JSONL outside the AI-visible fixture payload."""
    truth: Dict[str, Dict[str, object]] = {}
    target = Path(path)
    if not target.exists():
        return truth

    for line_number, line in enumerate(target.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        finding_id = row.get("finding_id")
        if not finding_id:
            raise AIFixtureLoadError(
                f"{target}:{line_number} is missing finding_id in ground truth"
            )
        truth[finding_id] = row
    return truth


def validate_ai_fixture_batch(root: Path) -> Tuple[List[AITriageInput], Dict[str, int]]:
    """Load fixtures and return a compact field-coverage report."""
    fixtures = load_ai_fixture_directory(root)
    missing_counts = {
        "benchmark_metadata": 0,
        "cwe_id": 0,
        "graph_metadata_notes": 0,
    }
    for fixture in fixtures:
        if fixture.benchmark is None:
            missing_counts["benchmark_metadata"] += 1
        if not fixture.finding.cwe_id:
            missing_counts["cwe_id"] += 1
        if not fixture.finding.graph_metadata.notes:
            missing_counts["graph_metadata_notes"] += 1
    return fixtures, missing_counts
