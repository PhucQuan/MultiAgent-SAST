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
    semgrep_config_paths: tuple[Path, ...] = ()


_SEMGREP_OSS_FULL_DIR = REPO_ROOT / "rules" / "semgrep-oss-full"
_SEMGREP_PYTHON_RULES = REPO_ROOT / "rules" / "semgrep" / "python_security.yaml"

def _resolve_default_rules() -> tuple[Path, ...]:
    return (_SEMGREP_PYTHON_RULES,)

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
        append_rules_paths=_resolve_default_rules(),
        semgrep_config_paths=(_SEMGREP_OSS_FULL_DIR,),
    ),
    "semgrep-python-ssrf": ReviewedRuleProfile(
        name="semgrep-python-ssrf",
        description=(
            "Reviewed Semgrep-derived Python SSRF overlay for requests.get and "
            "urllib.request.urlopen."
        ),
        language_scope=("python",),
        family_scope=("SSRF",),
        append_rules_paths=_resolve_default_rules(),
        semgrep_config_paths=(_SEMGREP_OSS_FULL_DIR,),
    ),
    "semgrep-oss-full": ReviewedRuleProfile(
        name="semgrep-oss-full",
        description=(
            "Unified Semgrep OSS Community Baseline covering OWASP Top 10 and CWE Top 25 "
            "(COMMAND_INJECTION, PATH_TRAVERSAL, SQL_INJECTION, INSECURE_DESERIALIZATION, SSRF, CODE_INJECTION)."
        ),
        language_scope=("python",),
        family_scope=(
            "COMMAND_INJECTION",
            "PATH_TRAVERSAL",
            "SQL_INJECTION",
            "INSECURE_DESERIALIZATION",
            "SSRF",
            "CODE_INJECTION",
            "XSS",
        ),
        append_rules_paths=_resolve_default_rules(),
        semgrep_config_paths=(_SEMGREP_OSS_FULL_DIR,),
    ),
    "semgrep-community-python": ReviewedRuleProfile(
        name="semgrep-community-python",
        description="Authoritative Semgrep OSS Community Registry baseline for Python security scans.",
        language_scope=("python",),
        family_scope=(
            "COMMAND_INJECTION",
            "PATH_TRAVERSAL",
            "SQL_INJECTION",
            "INSECURE_DESERIALIZATION",
            "SSRF",
            "CODE_INJECTION",
            "XSS",
        ),
        append_rules_paths=_resolve_default_rules(),
        semgrep_config_paths=(_SEMGREP_OSS_FULL_DIR,),
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
