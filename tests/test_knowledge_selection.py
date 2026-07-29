"""Tests for multilingual AI knowledge-card selection."""

from aegis_sast.knowledge import KnowledgeLoader


def test_loader_reads_five_priority_multilingual_cwe_cards():
    """The AI knowledge directory should contain the five priority CWE cards."""
    cards = KnowledgeLoader().load_directory()
    cwe_ids = {card.cwe_id for card in cards}

    assert {"CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-918"}.issubset(cwe_ids)


def test_loader_selects_language_and_framework_section():
    """Selection should avoid sending an entire card when a language section is enough."""
    result = KnowledgeLoader().select(
        cwe_id="CWE-89",
        vuln_type="SQL_INJECTION",
        language="python",
        framework="flask",
    )

    assert result.card_id == "cwe-89-sqli"
    assert result.matched_language_section is not None
    assert "request.args" in result.matched_language_section.sources
    assert result.matched_framework_section == ["Treat request values as untrusted."]
    assert result.fallback_used is False


def test_loader_supports_twenty_cwe_language_combinations():
    """Five priority CWEs should each have sections for four supported languages."""
    loader = KnowledgeLoader()
    cases = [
        ("CWE-89", "SQL_INJECTION"),
        ("CWE-78", "COMMAND_INJECTION"),
        ("CWE-22", "PATH_TRAVERSAL"),
        ("CWE-79", "XSS"),
        ("CWE-918", "SSRF"),
    ]
    languages = ("python", "javascript", "java", "php")

    for cwe_id, vuln_type in cases:
        for language in languages:
            result = loader.select(
                cwe_id=cwe_id,
                vuln_type=vuln_type,
                language=language,
            )

            assert result.card is not None
            assert result.card.cwe_id == cwe_id
            assert result.matched_language_section is not None
            assert result.matched_language_section.sinks


def test_loader_marks_framework_fallback_when_framework_is_unknown():
    result = KnowledgeLoader().select(
        cwe_id="CWE-918",
        vuln_type="SSRF",
        language="java",
        framework="unknown-framework",
    )

    assert result.card_id == "cwe-918-ssrf"
    assert result.fallback_used is True
    assert "unknown-framework" in result.warnings[0]


def test_loader_returns_empty_result_for_unsupported_cwe():
    result = KnowledgeLoader().select(
        cwe_id="CWE-999",
        vuln_type="UNSUPPORTED",
        language="python",
    )

    assert result.card is not None
    assert result.fallback_used is True
    assert result.matched_language_section is None or result.card.cwe_id != "CWE-999"
