"""Checked-in reviewed rule profiles for reproducible detector experiments."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class ReviewedRuleProfile:
    """One repo-owned reviewed rule profile."""

    name: str
    description: str
    language_scope: tuple[str, ...]
    family_scope: tuple[str, ...]
    append_rules_paths: tuple[Path, ...]


_REVIEWED_RULE_PROFILES = {
    "semgrep-python-core4": ReviewedRuleProfile(
        name="semgrep-python-core4",
        description=(
            "Reviewed Semgrep-derived Python overlay for COMMAND_INJECTION, "
            "PATH_TRAVERSAL, INSECURE_DESERIALIZATION, and SQL_INJECTION."
        ),
        language_scope=("python",),
        family_scope=(
            "COMMAND_INJECTION",
            "PATH_TRAVERSAL",
            "INSECURE_DESERIALIZATION",
            "SQL_INJECTION",
        ),
        append_rules_paths=(
            REPO_ROOT / "rules" / "reviewed" / "semgrep_python_core4_reviewed.legacy.yaml",
        ),
    ),
    "semgrep-python-ssrf": ReviewedRuleProfile(
        name="semgrep-python-ssrf",
        description=(
            "Reviewed Semgrep-derived Python SSRF overlay for requests.get and "
            "urllib.request.urlopen."
        ),
        language_scope=("python",),
        family_scope=("SSRF",),
        append_rules_paths=(
            REPO_ROOT / "rules" / "reviewed" / "semgrep_python_ssrf_reviewed.legacy.yaml",
        ),
    ),
}


def reviewed_rule_profile_choices() -> list[str]:
    """Return stable CLI-friendly profile names."""
    return sorted(_REVIEWED_RULE_PROFILES)


def resolve_reviewed_rule_profile(name: str | None) -> ReviewedRuleProfile | None:
    """Resolve one checked-in reviewed rule profile by name."""
    if name is None:
        return None

    normalized = name.strip()
    if not normalized:
        return None

    try:
        return _REVIEWED_RULE_PROFILES[normalized]
    except KeyError as exc:
        raise ValueError(f"Unknown reviewed rule profile: {name}") from exc
