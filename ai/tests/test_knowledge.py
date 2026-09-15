"""Test Task 4 — 20 knowledge card và loader."""

from ai.knowledge.loader import KnowledgeLoader, knowledge_loader

CWES = ["CWE-89", "CWE-78", "CWE-22", "CWE-502", "CWE-918", "CWE-94", "CWE-601"]
LANGS = ["python", "javascript", "java", "php"]


def test_full_card_matrix_present():
    """7 CWE x 4 ngôn ngữ. CWE-94 và CWE-601 thêm sau vì detector sinh ra
    CODE_INJECTION và OPEN_REDIRECT nhưng guide chỉ liệt kê 5 CWE."""
    cards = knowledge_loader.all_cards()
    assert len(cards) == len(CWES) * len(LANGS) == 28


def test_full_cwe_language_matrix():
    for cwe in CWES:
        for lang in LANGS:
            assert knowledge_loader._cache.get((cwe, lang)) is not None, (cwe, lang)


def test_every_card_has_fp_indicators_and_few_shot():
    for card in knowledge_loader.all_cards():
        assert card.fp_indicators, card.cwe
        assert card.sinks and card.sources and card.sanitizers
        assert 1 <= len(card.few_shot) <= 3
        assert {e.label for e in card.few_shot} <= {"TP", "FP"}


def test_load_returns_exact_language_first():
    cards = knowledge_loader.load("CWE-89", "php", max_cards=2)
    assert cards[0].language == "php"
    assert cards[0].cwe == "CWE-89"


def test_load_respects_max_cards():
    assert len(knowledge_loader.load("CWE-89", "php", max_cards=2)) == 2
    assert len(knowledge_loader.load("CWE-89", "php", max_cards=1)) == 1


def test_load_falls_back_to_other_language_same_cwe():
    cards = knowledge_loader.load("CWE-918", "python", max_cards=2)
    assert [c.cwe for c in cards] == ["CWE-918", "CWE-918"]
    assert cards[1].language != "python"


def test_unknown_cwe_returns_empty():
    assert knowledge_loader.load("CWE-000", "python") == []


def test_loader_is_deterministic():
    a = KnowledgeLoader().load("CWE-22", "java", max_cards=2)
    b = KnowledgeLoader().load("CWE-22", "java", max_cards=2)
    assert [c.language for c in a] == [c.language for c in b]
