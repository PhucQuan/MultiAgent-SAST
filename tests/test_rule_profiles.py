"""Tests for checked-in reviewed rule profiles."""

from __future__ import annotations

from aegis_sast.analysis.rule_engine import RuleEngine
from aegis_sast.rule_profiles import (
    resolve_reviewed_rule_profile,
    reviewed_rule_profile_choices,
)


def test_semgrep_python_core4_profile_is_listed_and_resolves():
    assert "semgrep-python-core4" in reviewed_rule_profile_choices()
    assert "semgrep-python-ssrf" in reviewed_rule_profile_choices()

    profile = resolve_reviewed_rule_profile("semgrep-python-core4")

    assert profile is not None
    assert profile.name == "semgrep-python-core4"
    assert profile.language_scope == ("python",)
    assert profile.family_scope == (
        "COMMAND_INJECTION",
        "PATH_TRAVERSAL",
        "INSECURE_DESERIALIZATION",
        "SQL_INJECTION",
    )
    assert all(path.exists() for path in profile.append_rules_paths)


def test_semgrep_python_core4_overlay_merges_into_python_rule_engine():
    profile = resolve_reviewed_rule_profile("semgrep-python-core4")
    assert profile is not None

    engine = RuleEngine(language="python", extra_rules_paths=list(profile.append_rules_paths))
    rules = engine.get_rules()

    path_patterns = [entry["pattern"] for entry in rules["sinks"]["path_traversal"]]
    deserialization_patterns = [
        entry["pattern"] for entry in rules["sinks"]["deserialization"]
    ]
    sqli_patterns = [entry["pattern"] for entry in rules["sinks"]["sqli"]]

    assert "send_file(" in path_patterns
    assert "pickle.load(" in deserialization_patterns
    assert "sqlalchemy.text(" in sqli_patterns


def test_semgrep_python_ssrf_profile_is_listed_and_merges_into_python_rule_engine():
    profile = resolve_reviewed_rule_profile("semgrep-python-ssrf")

    assert profile is not None
    assert profile.name == "semgrep-python-ssrf"
    assert profile.language_scope == ("python",)
    assert profile.family_scope == ("SSRF",)
    assert all(path.exists() for path in profile.append_rules_paths)

    engine = RuleEngine(language="python", extra_rules_paths=list(profile.append_rules_paths))
    rules = engine.get_rules()
    ssrf_patterns = [entry["pattern"] for entry in rules["sinks"]["ssrf"]]

    assert "requests.get(" in ssrf_patterns
    assert "urllib.request.urlopen(" in ssrf_patterns
