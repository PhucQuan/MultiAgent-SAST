"""Helpers for loading YAML-based knowledge cards."""

import json
from pathlib import Path
from typing import Iterable, List, Optional

try:
    import yaml
except ImportError:  # pragma: no cover - exercised in lightweight environments
    yaml = None

from aegis_sast.knowledge.schema import (
    KnowledgeCard,
    KnowledgeLoaderInput,
    KnowledgeLoaderResult,
)


class KnowledgeLoader:
    """Loads and filters knowledge cards for the triage layer."""

    def __init__(self, root: Optional[Path] = None):
        self.root = root or self.default_root()

    @staticmethod
    def default_root() -> Path:
        """Return the built-in knowledge card directory."""
        return Path(__file__).resolve().parent / "library"

    @staticmethod
    def ai_cards_root() -> Path:
        """Return the multilingual AI knowledge card directory."""
        return Path(__file__).resolve().parent / "cards"

    def load_directory(self, directory: Optional[Path] = None) -> List[KnowledgeCard]:
        """Load every YAML or JSON card from a directory."""
        target_dirs = [directory or self.root]
        if directory is None and self.root == self.default_root():
            target_dirs.append(self.ai_cards_root())

        # Always scan YAML files even when PyYAML is unavailable because
        # `_simple_yaml_load()` supports the subset used by built-in cards.
        patterns = ["*.json", "*.yaml", "*.yml"]

        cards_by_id = {}
        seen_paths = set()
        matched_paths = []
        for target_dir in target_dirs:
            if target_dir is None or not target_dir.exists():
                continue
            for pattern in patterns:
                matched_paths.extend(target_dir.rglob(pattern))

        for path in sorted(matched_paths):
            if path in seen_paths:
                continue
            seen_paths.add(path)
            card = self.load_card(path)
            cards_by_id.setdefault(card.card_id, card)

        return list(cards_by_id.values())

    def load_card(self, path: Path) -> KnowledgeCard:
        """Load a single YAML card from disk."""
        raw_text = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".json":
            data = json.loads(raw_text)
        elif yaml is not None:
            try:
                data = yaml.safe_load(raw_text) or {}
            except Exception:
                data = _simple_yaml_load(raw_text)
        else:
            data = _simple_yaml_load(raw_text)
        return KnowledgeCard(
            card_id=data.get("card_id", path.stem),
            title=data.get("title", path.stem),
            language=data.get("language"),
            cwe_id=data.get("cwe_id"),
            owasp_category=data.get("owasp_category"),
            finding_type=data.get("finding_type"),
            description=data.get("description", ""),
            sources=data.get("sources", []),
            sinks=data.get("sinks", []),
            sanitizers=data.get("sanitizers", []),
            false_positive_patterns=data.get("false_positive_patterns", []),
            remediation_notes=data.get("remediation_notes", []),
            languages=data.get("languages", {}),
            evidence_rubric=data.get("evidence_rubric", {}),
            metadata=data.get("metadata", {}),
        )

    def select(
        self,
        *,
        cwe_id: Optional[str] = None,
        vuln_type: Optional[str] = None,
        language: str,
        framework: Optional[str] = None,
        cards: Optional[Iterable[KnowledgeCard]] = None,
    ) -> KnowledgeLoaderResult:
        """Select one card and the smallest useful language/framework section."""
        request = KnowledgeLoaderInput(
            cwe_id=cwe_id,
            vuln_type=vuln_type,
            language=language,
            framework=framework,
        )
        available_cards = list(cards) if cards is not None else self.load_directory()
        matched = self.filter_cards(
            available_cards,
            language=request.language,
            cwe_id=request.cwe_id,
            finding_type=request.vuln_type,
        )
        warnings: List[str] = []
        fallback_used = False

        if not matched and request.cwe_id:
            fallback_used = True
            warnings.append(f"No exact card for {request.cwe_id}; retried by vuln_type.")
            matched = self.filter_cards(
                available_cards,
                language=request.language,
                finding_type=request.vuln_type,
            )

        if not matched and request.vuln_type:
            fallback_used = True
            warnings.append(f"No exact card for {request.vuln_type}; using generic language card.")
            matched = self.filter_cards(available_cards, language=request.language)

        if not matched:
            return KnowledgeLoaderResult(
                card=None,
                fallback_used=True,
                warnings=warnings + [f"No knowledge card matched language={request.language}."],
            )

        card = self._prefer_multilingual_card(matched)
        language_section = card.languages.get(request.language)
        framework_section: List[str] = []
        if language_section and request.framework:
            framework_section = language_section.framework_notes.get(
                request.framework,
                [],
            )
            if not framework_section:
                fallback_used = True
                warnings.append(
                    f"No framework notes for {request.framework}; used language section."
                )
        elif not language_section:
            fallback_used = True
            warnings.append(f"No language section for {request.language}; used card-level fields.")

        return KnowledgeLoaderResult(
            card=card,
            matched_language_section=language_section,
            matched_framework_section=framework_section,
            fallback_used=fallback_used,
            warnings=warnings,
        )

    @staticmethod
    def filter_cards(
        cards: Iterable[KnowledgeCard],
        language: Optional[str] = None,
        cwe_id: Optional[str] = None,
        finding_type: Optional[str] = None,
    ) -> List[KnowledgeCard]:
        """Return cards matching the requested language or weakness hints."""
        results: List[KnowledgeCard] = []
        for card in cards:
            if language and card.language not in (None, language):
                continue
            if cwe_id and card.cwe_id not in (None, cwe_id):
                continue
            if finding_type and card.finding_type not in (None, finding_type):
                continue
            results.append(card)
        return results

    @staticmethod
    def _prefer_multilingual_card(cards: List[KnowledgeCard]) -> KnowledgeCard:
        """Prefer the newer multilingual card when several cards match."""
        return sorted(
            cards,
            key=lambda card: (not bool(card.languages), card.card_id),
        )[0]


def _simple_yaml_load(text: str) -> dict:
    """
    Parse a small YAML subset used by the built-in knowledge cards.

    Supported shapes:
    - top-level mappings
    - nested mappings
    - lists of scalar values
    """
    lines = [
        line.rstrip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    def parse_mapping(start: int, indent: int):
        data = {}
        index = start

        while index < len(lines):
            line = lines[index]
            current_indent = len(line) - len(line.lstrip(" "))
            if current_indent < indent:
                break
            if current_indent != indent:
                index += 1
                continue

            stripped = line.strip()
            key, _, raw_value = stripped.partition(":")
            value = _normalize_scalar(raw_value.strip())

            if value:
                data[key] = value
                index += 1
                continue

            next_index = index + 1
            if next_index >= len(lines):
                data[key] = {}
                index = next_index
                continue

            next_line = lines[next_index]
            next_indent = len(next_line) - len(next_line.lstrip(" "))
            if next_indent <= indent:
                data[key] = {}
                index = next_index
                continue

            if next_line.strip().startswith("- "):
                parsed_list, index = parse_list(next_index, next_indent)
                data[key] = parsed_list
            else:
                parsed_mapping, index = parse_mapping(next_index, next_indent)
                data[key] = parsed_mapping

        return data, index

    def parse_list(start: int, indent: int):
        items = []
        index = start

        while index < len(lines):
            line = lines[index]
            current_indent = len(line) - len(line.lstrip(" "))
            if current_indent < indent:
                break
            if current_indent != indent or not line.strip().startswith("- "):
                break

            item = _normalize_scalar(line.strip()[2:].strip())
            items.append(item)
            index += 1

        return items, index

    parsed, _ = parse_mapping(0, 0)
    return parsed


def _normalize_scalar(value: str) -> str:
    """Normalize scalar values from the fallback YAML parser."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value
