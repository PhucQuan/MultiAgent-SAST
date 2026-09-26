"""Build the unified Semgrep OSS Community Baseline rulepack for Python.

This script aggregates curated, battle-tested rules from the Semgrep Community
Registry (refs/rule_sources/semgrep-rules/python) along with checked-in reviewed
sets, validates them against the Aegis normalized schema, and compiles:
1. `rules/reviewed/semgrep_oss_python_baseline.normalized.json`
2. `rules/reviewed/semgrep_oss_python_baseline.legacy.yaml`
3. `rules/reviewed/semgrep_oss_python_baseline.validation.json`
4. `rules/reviewed/semgrep_oss_python_baseline.legacy.report.json`
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegis_sast.rule_workbench.service import (
    RuleWorkbenchService,
    load_normalized_document,
)


def build_semgrep_oss_baseline(
    repo_root: Path = REPO_ROOT,
    language: str = "python",
) -> tuple[Path, Path, int]:
    """Compile and export the unified Semgrep OSS rule baseline."""
    service = RuleWorkbenchService()
    semgrep_python_dir = repo_root / "refs" / "rule_sources" / "semgrep-rules" / language

    if not semgrep_python_dir.exists():
        raise FileNotFoundError(f"Semgrep rules directory not found: {semgrep_python_dir}")

    semgrep_files = sorted(semgrep_python_dir.rglob("*.yaml")) + sorted(semgrep_python_dir.rglob("*.yml"))
    print(f"[*] Discovered {len(semgrep_files)} Semgrep rule files under {semgrep_python_dir}...")

    normalized_docs = []

    # 1. Load checked-in reviewed seeds if present
    core4_path = repo_root / "rules" / "reviewed" / "semgrep_python_core4_reviewed.normalized.json"
    ssrf_path = repo_root / "rules" / "reviewed" / "semgrep_python_ssrf_reviewed.normalized.json"

    if core4_path.exists():
        normalized_docs.append(load_normalized_document(core4_path))
        print(f"[+] Loaded reviewed core4 seed from {core4_path.name}")
    if ssrf_path.exists():
        normalized_docs.append(load_normalized_document(ssrf_path))
        print(f"[+] Loaded reviewed SSRF seed from {ssrf_path.name}")

    # 2. Ingest taint rules from Semgrep community rules
    imported_rules_count = 0
    skipped_docs_count = 0

    for file_path in semgrep_files:
        try:
            raw_doc = service.load_semgrep_document(file_path)
            rel_path = file_path.relative_to(repo_root)
            norm_doc = service.normalize_semgrep_document(
                raw_doc,
                language_filter=language,
                provenance_source="semgrep-community",
                snapshot_version="semgrep-oss-registry-2026",
                source_path=rel_path,
            )
            count = norm_doc.get("rule_count", 0)
            if count > 0:
                normalized_docs.append(norm_doc)
                imported_rules_count += count
            else:
                skipped_docs_count += 1
        except Exception:
            skipped_docs_count += 1

    print(f"[+] Ingested {imported_rules_count} taint rules from {len(semgrep_files)} files ({skipped_docs_count} skipped/non-taint)")

    # 3. Merge and deduplicate
    merged = service.merge_normalized_documents(normalized_docs)
    total_rules = merged["rule_count"]
    print(f"[+] Successfully merged into unified set: {total_rules} rules")

    families = Counter(r.get("family") for r in merged.get("rules", []))
    print("[*] Family breakdown:")
    for family, count in sorted(families.items()):
        print(f"    - {family}: {count} rules")

    # 4. Target output files
    output_dir = repo_root / "rules" / "reviewed"
    output_dir.mkdir(parents=True, exist_ok=True)

    norm_out = output_dir / f"semgrep_oss_{language}_baseline.normalized.json"
    legacy_out = output_dir / f"semgrep_oss_{language}_baseline.legacy.yaml"
    val_out = output_dir / f"semgrep_oss_{language}_baseline.validation.json"
    rep_out = output_dir / f"semgrep_oss_{language}_baseline.legacy.report.json"

    # 5. Write normalized document
    service.write_normalized_document(merged, norm_out, "json")
    print(f"[+] Wrote normalized rules to {norm_out.relative_to(repo_root)}")

    # 6. Validate
    validation_report = service.validate_normalized_document(merged, profile="generic")
    service.write_validation_report(validation_report, format_name="json", output_path=val_out)
    valid_status = validation_report.get("valid", False)
    error_count = len(validation_report.get("errors", []))
    warning_count = len(validation_report.get("warnings", []))
    print(f"[+] Schema validation: valid={valid_status} (errors={error_count}, warnings={warning_count})")

    # 7. Export legacy format for detector engine
    legacy_doc, export_report = service.export_legacy_rules(merged)
    service.write_legacy_document(legacy_doc, legacy_out, "yaml")
    service.write_report(export_report, rep_out)

    sinks_count = sum(len(items) for items in legacy_doc.get("sinks", {}).values())
    sources_count = len(legacy_doc.get("sources", []))
    sanitizers_count = len(legacy_doc.get("sanitizers", []))
    print(f"[+] Exported legacy detector rules to {legacy_out.relative_to(repo_root)}")
    print(f"    - Sources: {sources_count}")
    print(f"    - Sinks: {sinks_count} across {len(legacy_doc.get('sinks', {}))} categories: {list(legacy_doc.get('sinks', {}).keys())}")
    print(f"    - Sanitizers: {sanitizers_count}")

    return norm_out, legacy_out, total_rules


if __name__ == "__main__":
    build_semgrep_oss_baseline()
