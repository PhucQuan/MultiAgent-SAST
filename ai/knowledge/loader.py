"""Nạp knowledge card từ `ai/knowledge/cards/`."""

import json
from pathlib import Path

from .schema import KnowledgeCard

CARDS_DIR = Path(__file__).parent / "cards"


class KnowledgeLoader:
    def __init__(self, cards_dir: Path | None = None):
        self.cards_dir = cards_dir or CARDS_DIR
        self._cache: dict[tuple[str, str], KnowledgeCard] = {}
        for f in sorted(self.cards_dir.glob("*.json")):
            data = json.loads(f.read_text(encoding="utf-8"))
            card = KnowledgeCard(**data)
            self._cache[(card.cwe, card.language)] = card

    def load(self, cwe: str, language: str, max_cards: int = 2) -> list[KnowledgeCard]:
        """Giới hạn ≤ max_cards để tránh knowledge bias (Vul-RAG best practice)."""
        cards: list[KnowledgeCard] = []
        exact = self._cache.get((cwe, language))
        if exact:
            cards.append(exact)
        if len(cards) < max_cards:
            for (c, l), card in sorted(self._cache.items()):
                if c == cwe and l != language and card not in cards:
                    cards.append(card)
                    if len(cards) >= max_cards:
                        break
        return cards[:max_cards]

    def all_cards(self) -> list[KnowledgeCard]:
        return list(self._cache.values())


knowledge_loader = KnowledgeLoader()
