"""Storage helpers for the reusable rule-workbench backend."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import RuleWorkbenchBundlePaths

try:
    import yaml
except ImportError:  # pragma: no cover - depends on runtime extras
    yaml = None


class RuleWorkbenchStorage:
    """Load and persist JSON/YAML/text artifacts for rule-workbench flows."""

    def load_mapping_document(self, path: Path) -> dict[str, Any]:
        """Load a JSON or YAML mapping document from disk."""
        raw_text = path.read_text(encoding="utf-8")
        suffix = path.suffix.lower()

        if suffix == ".json":
            data = json.loads(raw_text)
        elif suffix in {".yaml", ".yml"}:
            if yaml is None:
                raise RuntimeError("PyYAML is required to load YAML documents.")
            data = yaml.safe_load(raw_text)
        else:
            raise ValueError(f"Unsupported document format: {suffix}")

        if not isinstance(data, dict):
            raise ValueError("Expected a top-level mapping document.")
        return data

    def write_mapping_document(self, document: dict[str, Any], output_path: Path, format_name: str) -> None:
        """Write one mapping document as JSON or YAML."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as handle:
            if format_name == "json":
                json.dump(document, handle, indent=2, ensure_ascii=False)
                handle.write("\n")
                return

            if yaml is None:
                raise RuntimeError("PyYAML is required to write YAML documents.")
            yaml.safe_dump(document, handle, sort_keys=False, allow_unicode=False)

    def write_json_report(self, payload: dict[str, Any], output_path: Path) -> None:
        """Write a JSON report artifact."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def write_text_report(self, content: str, output_path: Path) -> None:
        """Write a plain-text report artifact."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")

    def build_bundle_paths(
        self,
        *,
        input_path: Path,
        output_dir: Path,
        normalized_format: str,
        validation_format: str,
        legacy_format: str | None = None,
    ) -> RuleWorkbenchBundlePaths:
        """Return stable output paths for one review bundle."""
        output_dir.mkdir(parents=True, exist_ok=True)
        stem = input_path.stem
        normalized_path = output_dir / f"{stem}.normalized.{normalized_format}"
        validation_path = output_dir / f"{stem}.validation.{validation_format}"
        legacy_path = None
        legacy_report_path = None
        if legacy_format:
            legacy_path = output_dir / f"{stem}.legacy.{legacy_format}"
            legacy_report_path = output_dir / f"{stem}.legacy.report.json"
        return RuleWorkbenchBundlePaths(
            normalized_path=normalized_path,
            validation_path=validation_path,
            legacy_path=legacy_path,
            legacy_report_path=legacy_report_path,
        )
