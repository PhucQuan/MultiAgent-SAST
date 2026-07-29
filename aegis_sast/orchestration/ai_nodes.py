"""AI-layer nodes that operate only on normalized triage inputs."""

from typing import Optional

from aegis_sast.knowledge import KnowledgeLoader
from aegis_sast.orchestration.contracts import (
    AuditorInput,
    AuditorResult,
    JudgeInput,
    KnowledgeLoaderNodeInput,
    KnowledgeLoaderNodeResult,
    PlannerInput,
    PlannerResult,
    ReportEnrichment,
    ReporterInput,
    SkepticInput,
    SkepticResult,
)
from aegis_sast.triage.schema import AITriageInput, TriageDecision


class PlannerAgentNode:
    """Plan the AI route without making a final triage decision."""

    def plan(self, planner_input: PlannerInput) -> PlannerResult:
        triage_input = planner_input.triage_input
        finding = triage_input.finding
        evidence = triage_input.evidence
        gaps = []
        route_hints = []

        if len(evidence.data_flow_path) < 2:
            gaps.append("data_flow_path has fewer than two locations")
        if not evidence.evidence_snippets:
            gaps.append("evidence_snippets missing")
        if evidence.graph_metadata.dead_path_suspected:
            route_hints.append("dead-path")
        if evidence.sanitizer_info.present:
            route_hints.append("sanitizer-present")
        if finding.confidence < 0.7:
            route_hints.append("low-confidence")
        if finding.cross_file:
            route_hints.append("cross-file")
        if finding.graph_metadata.unsupported_framework:
            route_hints.append("unsupported-framework")

        should_use_skeptic = bool(route_hints or gaps or finding.confidence < 0.85)
        return PlannerResult(
            finding_id=finding.finding_id,
            route_hints=route_hints,
            required_knowledge=[value for value in (finding.cwe_id, finding.vuln_type) if value],
            evidence_gaps=gaps,
            should_use_skeptic=should_use_skeptic,
            reasoning_summary=(
                "Planner requires skeptic validation."
                if should_use_skeptic
                else "Planner can route directly to judge."
            ),
        )


class KnowledgeLoaderAgentNode:
    """Load the smallest useful knowledge section."""

    def __init__(self, loader: Optional[KnowledgeLoader] = None):
        self.loader = loader or KnowledgeLoader()

    def load(self, node_input: KnowledgeLoaderNodeInput) -> KnowledgeLoaderNodeResult:
        finding = node_input.triage_input.finding
        framework = _first_framework_hint(finding.graph_metadata.notes)
        selection = self.loader.select(
            cwe_id=finding.cwe_id,
            vuln_type=finding.vuln_type,
            language=finding.language,
            framework=framework,
        )
        return KnowledgeLoaderNodeResult(
            finding_id=finding.finding_id,
            selection=selection,
            warnings=selection.warnings,
        )


class AuditorAgentNode:
    """Audit deterministic evidence quality."""

    def audit(self, node_input: AuditorInput) -> AuditorResult:
        evidence = node_input.triage_input.evidence
        finding = node_input.triage_input.finding
        missing = list(node_input.plan.evidence_gaps)
        if node_input.knowledge.selection.card is None:
            missing.append("knowledge card missing")

        sanitizer_effective = evidence.sanitizer_info.present and evidence.sanitizer_info.effective
        has_complete_path = len(evidence.data_flow_path) >= 2
        is_exploitable = (
            has_complete_path
            and not sanitizer_effective
            and not evidence.graph_metadata.dead_path_suspected
        )
        confidence = finding.confidence
        if not has_complete_path:
            confidence = min(confidence, 0.5)
        if sanitizer_effective or evidence.graph_metadata.dead_path_suspected:
            confidence = min(confidence, 0.4)

        return AuditorResult(
            is_exploitable=is_exploitable,
            confidence=max(0.0, min(confidence, 1.0)),
            evidence_strength=(
                "strong"
                if has_complete_path and confidence >= 0.8
                else "moderate" if has_complete_path else "weak"
            ),
            sanitizer_effective=sanitizer_effective,
            reasoning_summary="Auditor evaluated source, sink, path completeness, and sanitizer evidence.",
            missing_evidence=missing,
        )


class SkepticAgentNode:
    """Look for false-positive and reachability indicators."""

    def review(self, node_input: SkepticInput) -> SkepticResult:
        evidence = node_input.triage_input.evidence
        indicators = []
        objections = []
        recommended_status = "needs-review"
        confidence = 0.55

        if evidence.sanitizer_info.effective:
            indicators.append("effective sanitizer present")
            recommended_status = "suppressed"
            confidence = 0.85
        if evidence.graph_metadata.dead_path_suspected:
            indicators.append("dead path suspected")
            recommended_status = "suppressed"
            confidence = 0.75
        if node_input.auditor_result.missing_evidence:
            objections.extend(node_input.auditor_result.missing_evidence)
            recommended_status = "needs-review"
            confidence = min(confidence, 0.6)

        return SkepticResult(
            objections=objections,
            false_positive_indicators=indicators,
            sanitizer_found=evidence.sanitizer_info.present,
            dead_code_suspected=evidence.graph_metadata.dead_path_suspected,
            recommended_status=recommended_status,
            confidence=confidence,
        )


class JudgeAgentNode:
    """Finalize triage from auditor and optional skeptic outputs."""

    def decide(self, node_input: JudgeInput) -> TriageDecision:
        finding = node_input.triage_input.finding
        auditor = node_input.auditor_result
        skeptic = node_input.skeptic_result

        limitations = list(auditor.missing_evidence)
        supporting = list(node_input.triage_input.evidence.evidence_snippets)
        status = "needs-review"
        confidence = min(auditor.confidence, finding.confidence)

        if skeptic and skeptic.recommended_status.value == "suppressed":
            status = "suppressed"
            confidence = skeptic.confidence
            limitations.extend(skeptic.objections)
            supporting.extend(skeptic.false_positive_indicators)
        elif auditor.is_exploitable and auditor.confidence >= 0.85:
            status = "confirmed"
            confidence = auditor.confidence
        elif auditor.is_exploitable and auditor.confidence >= 0.65:
            status = "likely"
            confidence = auditor.confidence
        elif skeptic and skeptic.objections:
            status = "needs-review"
            confidence = min(confidence, skeptic.confidence)

        return TriageDecision(
            finding_id=finding.finding_id,
            status=status,
            confidence=confidence,
            vulnerability_explanation=(
                f"{finding.vuln_type} triage for {finding.language} based on normalized evidence."
            ),
            remediation_note=_default_remediation(finding.language, finding.vuln_type),
            supporting_evidence=supporting,
            limitations=limitations,
            route_taken=node_input.route_taken,
            model_name="deterministic-ai-node",
        )


class ReporterAgentNode:
    """Create report enrichment from a final decision."""

    def enrich(self, node_input: ReporterInput) -> ReportEnrichment:
        decision = node_input.decision
        return ReportEnrichment(
            finding_id=node_input.triage_input.finding.finding_id,
            explanation=decision.vulnerability_explanation,
            remediation_note=decision.remediation_note,
            supporting_evidence=decision.supporting_evidence,
            limitations=decision.limitations,
            route_taken=decision.route_taken,
        )


def _first_framework_hint(notes: list[str]) -> Optional[str]:
    """Extract a framework hint from graph notes when one is present."""
    for note in notes:
        if note.startswith("framework="):
            return note.split("=", 1)[1]
    return None


def _default_remediation(language: str, vuln_type: str) -> str:
    """Return compact language-aware remediation text."""
    if vuln_type == "SQL_INJECTION":
        return f"Use parameterized queries in {language}."
    if vuln_type == "COMMAND_INJECTION":
        return f"Avoid shell interpretation and use fixed argument arrays in {language}."
    if vuln_type == "PATH_TRAVERSAL":
        return f"Canonicalize paths and enforce an allowed base directory in {language}."
    if vuln_type == "XSS":
        return f"Use context-aware output encoding in {language}."
    if vuln_type == "SSRF":
        return f"Allowlist destinations and block private network ranges in {language}."
    return f"Apply a language-appropriate fix in {language}."
