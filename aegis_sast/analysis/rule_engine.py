"""
Rule engine for loading and matching security rules.

Handles YAML/JSON rule file parsing and provides rule lookup functionality.
"""

from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

import yaml


class RuleEngine:
    """Manages security rules for vulnerability detection."""

    def __init__(
        self,
        rules_path: Optional[Path] = None,
        language: str = "python",
        extra_rules_paths: Optional[Iterable[Path]] = None,
    ):
        """
        Initialize rule engine.

        Args:
            rules_path: Path to custom rules file (YAML/JSON).
            language: Language name (python/javascript/java/php) for auto rule loading.
            extra_rules_paths: Optional rule files to merge on top of the base rule set.
        """
        self.rules: Dict[str, Any] = {}
        self.rules_path = Path(rules_path) if rules_path else None
        self.language = language
        self.extra_rules_paths = [Path(path) for path in (extra_rules_paths or [])]
        self._language_cache: Dict[str, "RuleEngine"] = {}

        self._initialize_rules()

    def _initialize_rules(self) -> None:
        """Load the effective base rules and apply any overlay rule files."""
        if self.rules_path:
            self.rules = self._read_rules(self.rules_path)
        else:
            self.rules = self._load_builtin_rules(self.language)

        for overlay_path in self.extra_rules_paths:
            overlay_rules = self._read_rules(overlay_path)
            self.rules = self._merge_rule_sets(self.rules, overlay_rules)

    def _load_builtin_rules(self, language: str) -> Dict[str, Any]:
        """Load the built-in rule file for one language with Python fallback."""
        rules_dir = Path(__file__).parent.parent.parent / "rules"
        lang_rules = rules_dir / f"{language}.yaml"
        if lang_rules.exists():
            return self._read_rules(lang_rules)

        default_rules = rules_dir / "python.yaml"
        if default_rules.exists():
            return self._read_rules(default_rules)
        return {}

    def _read_rules(self, rules_path: Path) -> Dict[str, Any]:
        """Read a YAML/JSON rule document without mutating engine state."""
        if not rules_path.exists():
            raise FileNotFoundError(f"Rules file not found: {rules_path}")

        extension = rules_path.suffix.lower()

        try:
            with open(rules_path, "r", encoding="utf-8") as f:
                if extension in [".yaml", ".yml"]:
                    loaded = yaml.safe_load(f)
                elif extension == ".json":
                    loaded = json.load(f)
                else:
                    raise ValueError(f"Unsupported rule file format: {extension}")
        except Exception as e:
            raise RuntimeError(f"Failed to load rules from {rules_path}: {e}") from e

        if loaded is None:
            return {}
        if not isinstance(loaded, dict):
            raise RuntimeError(f"Failed to load rules from {rules_path}: expected a mapping")
        return loaded

    def load_rules(self, rules_path: Path):
        """
        Load rules from YAML or JSON file.

        Args:
            rules_path: Path to rules file
        """
        self.rules = self._read_rules(rules_path)
        self.rules_path = Path(rules_path)

    def get_sources(self) -> list:
        """Get source rules."""
        return self.rules.get("sources", [])

    def get_sinks(self) -> Dict[str, Any]:
        """Get sink rules organized by category."""
        return self.rules.get("sinks", {})

    def get_sanitizers(self) -> list:
        """Get sanitizer rules."""
        return self.rules.get("sanitizers", [])

    def get_safe_patterns(self) -> list:
        """Get safe patterns that don't propagate taint."""
        return self.rules.get("safe_patterns", [])

    def get_rules(self) -> Dict[str, Any]:
        """Get all rules."""
        return self.rules

    def for_language(self, language: str) -> "RuleEngine":
        """
        Resolve the effective rule engine for one language.

        Custom rules are treated as an explicit override contract and are reused
        unchanged for every file. When no custom rules were provided, the engine
        lazily loads and caches built-in rule sets per language so multi-language
        scans respect each plugin's default rules.
        """
        if self.rules_path is not None:
            return self

        normalized = language.strip().lower()
        if normalized == self.language and self.rules:
            return self

        cached = self._language_cache.get(normalized)
        if cached is None:
            cached = RuleEngine(
                language=normalized,
                extra_rules_paths=self.extra_rules_paths,
            )
            self._language_cache[normalized] = cached
        return cached

    @staticmethod
    def _merge_rule_sets(base_rules: Dict[str, Any], overlay_rules: Dict[str, Any]) -> Dict[str, Any]:
        """Merge overlay rules on top of a base rule document with light dedupe."""
        merged = deepcopy(base_rules)

        merged["sources"] = RuleEngine._merge_rule_list(
            base_rules.get("sources", []),
            overlay_rules.get("sources", []),
            identity_fields=("pattern", "type"),
        )
        merged["sanitizers"] = RuleEngine._merge_rule_list(
            base_rules.get("sanitizers", []),
            overlay_rules.get("sanitizers", []),
            identity_fields=("pattern", "mitigates"),
        )
        merged["safe_patterns"] = RuleEngine._merge_string_list(
            base_rules.get("safe_patterns", []),
            overlay_rules.get("safe_patterns", []),
        )
        merged["sinks"] = RuleEngine._merge_sink_rules(
            base_rules.get("sinks", {}),
            overlay_rules.get("sinks", {}),
        )

        for key, value in overlay_rules.items():
            if key in {"sources", "sinks", "sanitizers", "safe_patterns"}:
                continue
            merged[key] = deepcopy(value)

        return merged

    @staticmethod
    def _merge_rule_list(
        base_entries: Any,
        overlay_entries: Any,
        *,
        identity_fields: tuple[str, ...],
    ) -> list:
        """Merge rule-entry lists while suppressing obvious duplicates."""
        merged: list = []
        seen: set[tuple[Any, ...]] = set()

        for entry in list(base_entries or []) + list(overlay_entries or []):
            copied = deepcopy(entry)
            if not isinstance(copied, dict):
                merged.append(copied)
                continue

            identity = tuple(RuleEngine._normalize_identity_part(copied.get(field)) for field in identity_fields)
            if identity in seen:
                continue
            seen.add(identity)
            merged.append(copied)

        return merged

    @staticmethod
    def _merge_string_list(base_entries: Any, overlay_entries: Any) -> list:
        """Merge plain string lists while preserving the first occurrence order."""
        merged: list[str] = []
        seen: set[str] = set()
        for entry in list(base_entries or []) + list(overlay_entries or []):
            if not isinstance(entry, str):
                continue
            if entry in seen:
                continue
            seen.add(entry)
            merged.append(entry)
        return merged

    @staticmethod
    def _merge_sink_rules(base_sinks: Any, overlay_sinks: Any) -> Dict[str, Any]:
        """Merge sink categories and sink entries with stable ordering."""
        merged: Dict[str, Any] = {}
        category_names = []
        for name in list((base_sinks or {}).keys()) + list((overlay_sinks or {}).keys()):
            if name not in category_names:
                category_names.append(name)

        for category in category_names:
            merged[category] = RuleEngine._merge_rule_list(
                (base_sinks or {}).get(category, []),
                (overlay_sinks or {}).get(category, []),
                identity_fields=("pattern", "type"),
            )
        return merged

    @staticmethod
    def _normalize_identity_part(value: Any) -> Any:
        """Convert nested list values into hashable shapes for dedupe keys."""
        if isinstance(value, list):
            return tuple(RuleEngine._normalize_identity_part(item) for item in value)
        if isinstance(value, dict):
            return tuple(
                sorted(
                    (key, RuleEngine._normalize_identity_part(item))
                    for key, item in value.items()
                )
            )
        return value
