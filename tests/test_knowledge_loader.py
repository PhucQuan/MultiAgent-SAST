"""Tests for built-in knowledge cards."""

from pathlib import Path

import aegis_sast.knowledge.loader as loader_module
from aegis_sast.knowledge import KnowledgeLoader


def test_default_loader_reads_builtin_cards():
    """The built-in knowledge library should load several cards."""
    loader = KnowledgeLoader()
    cards = loader.load_directory()

    assert len(cards) >= 5
    assert any(card.card_id == "python-web-and-db" for card in cards)
    assert any(card.card_id == "javascript-node-express" for card in cards)
    assert any(card.card_id == "java-web-jdbc" for card in cards)


def test_loader_can_filter_by_language_and_finding_type():
    """Language-aware filtering should preserve generic and language-specific cards."""
    loader = KnowledgeLoader()
    cards = loader.load_directory()

    python_sqli = loader.filter_cards(
        cards,
        language="python",
        finding_type="SQL_INJECTION",
    )

    card_ids = {card.card_id for card in python_sqli}
    assert "generic-sqli" in card_ids
    assert "python-web-and-db" in card_ids


def test_loader_reads_yaml_cards_without_pyyaml(tmp_path, monkeypatch):
    """The lightweight fallback parser should still load YAML files."""
    card_path = tmp_path / "custom-card.yaml"
    card_path.write_text(
        "\n".join(
            [
                "card_id: custom-command-card",
                "title: Custom Command Card",
                "language: python",
                "finding_type: COMMAND_INJECTION",
                "sources:",
                "  - request.args.get",
                "sinks:",
                "  - os.system",
                "remediation_notes:",
                "  - use subprocess argument arrays",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(loader_module, "yaml", None)

    loader = KnowledgeLoader(Path(tmp_path))
    cards = loader.load_directory()

    assert len(cards) == 1
    assert cards[0].card_id == "custom-command-card"
    assert cards[0].remediation_notes == ["use subprocess argument arrays"]
