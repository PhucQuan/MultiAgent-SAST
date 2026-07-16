"""SARIF export for GitHub code scanning and CI-oriented workflows."""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from aegis_sast.core.models import CodeLocation, ScanResult, Severity, Vulnerability
from aegis_sast.triage.schema import TriageRecord


class SARIFFormatter:
    """Exports scan results in SARIF v2.1.0 format."""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(
        self,
        scan_result: ScanResult,
        filename: str = None,
        triage_records: Optional[List[TriageRecord]] = None,
        workflow_metadata: Optional[Dict[str, object]] = None,
    ) -> Path:
        """Write the SARIF report to disk and return the output path."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"aegis_sast_report_{timestamp}.sarif"

        output_path = self.output_dir / filename
        report = self._build_report(scan_result, triage_records, workflow_metadata)
        with open(output_path, "w", encoding="utf-8") as file_handle:
            json.dump(report, file_handle, indent=2, ensure_ascii=False)
        return output_path

    def _build_report(
        self,
        scan_result: ScanResult,
        triage_records: Optional[List[TriageRecord]],
        workflow_metadata: Optional[Dict[str, object]],
    ) -> Dict[str, object]:
        rules = self._build_rules(scan_result.vulnerabilities, triage_records)
        results = self._build_results(scan_result.vulnerabilities, triage_records)

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Aegis-SAST",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/PhucQuan/aegis-sast",
                            "rules": rules,
                        }
                    },
                    "automationDetails": {"id": "aegis-sast/manual-scan"},
                    "properties": {
                        "workflow_summary": self._build_workflow_summary(
                            workflow_metadata or {}
                        )
                    },
                    "results": results,
                }
            ],
        }

    def _build_rules(
        self,
        vulnerabilities: List[Vulnerability],
        triage_records: Optional[List[TriageRecord]],
    ) -> List[Dict[str, object]]:
        by_rule: Dict[str, Dict[str, object]] = {}
        findings = (
            [record.finding for record in triage_records]
            if triage_records
            else [vuln.to_normalized_finding() for vuln in vulnerabilities]
        )

        for finding in findings:
            if finding.rule_id in by_rule:
                continue
            by_rule[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.vulnerability_type,
                "shortDescription": {
                    "text": finding.vulnerability_type.replace("_", " ").title()
                },
                "fullDescription": {"text": finding.message},
                "properties": {
                    "tags": [
                        "security",
                        finding.language or "unknown-language",
                        finding.vulnerability_type.lower(),
                    ],
                    "problem.severity": finding.severity.value.lower(),
                    "security-severity": self._security_severity(finding.severity),
                },
            }

        return list(by_rule.values())

    def _build_results(
        self,
        vulnerabilities: List[Vulnerability],
        triage_records: Optional[List[TriageRecord]],
    ) -> List[Dict[str, object]]:
        if triage_records:
            return [self._build_triage_result(record) for record in triage_records]
        return [self._build_result(vuln) for vuln in vulnerabilities]

    def _build_result(self, vuln: Vulnerability) -> Dict[str, object]:
        finding = vuln.to_normalized_finding()
        sink = vuln.dataflow.sink.location

        result: Dict[str, object] = {
            "ruleId": finding.rule_id,
            "level": self._sarif_level(finding.severity),
            "message": {"text": finding.message},
            "locations": [self._sarif_location(sink, "Sink location")],
            "partialFingerprints": {
                "primaryLocationLineHash": (
                    f"{finding.rule_id}:{finding.file_path}:{finding.line_number}"
                )
            },
            "properties": {
                "severity": finding.severity.value,
                "triage_status": finding.triage_status.value,
                "confidence": finding.confidence,
                "language": finding.language,
                "recommendation": finding.recommendation,
                "tags": [
                    finding.vulnerability_type,
                    finding.language or "unknown-language",
                ],
            },
        }

        thread_flow = self._build_thread_flow_from_vulnerability(vuln)
        if thread_flow:
            result["codeFlows"] = [{"threadFlows": [{"locations": thread_flow}]}]

        return result

    def _build_triage_result(self, record: TriageRecord) -> Dict[str, object]:
        finding = record.finding
        sink = finding.evidence.sink

        result: Dict[str, object] = {
            "ruleId": finding.rule_id,
            "level": self._sarif_level(finding.severity),
            "message": {"text": finding.explanation or finding.message},
            "locations": [self._sarif_location(sink, "Sink location")],
            "partialFingerprints": {
                "primaryLocationLineHash": (
                    f"{finding.rule_id}:{finding.file_path}:{finding.line_number}"
                )
            },
            "properties": {
                "severity": finding.severity.value,
                "triage_status": record.decision.status.value,
                "confidence": record.decision.confidence,
                "language": finding.language,
                "recommendation": record.decision.recommendation,
                "knowledge_cards": record.decision.metadata.get("knowledge_card_ids", []),
                "agent_reviews": self._build_agent_reviews(record),
                "tags": [
                    finding.vulnerability_type,
                    finding.language or "unknown-language",
                ],
            },
        }

        thread_flow = self._build_thread_flow_from_record(record)
        if thread_flow:
            result["codeFlows"] = [{"threadFlows": [{"locations": thread_flow}]}]

        return result

    def _build_thread_flow_from_vulnerability(
        self,
        vuln: Vulnerability,
    ) -> List[Dict[str, object]]:
        locations: List[Dict[str, object]] = []
        locations.append(self._thread_flow_location(vuln.dataflow.source.location, "source"))
        for step in vuln.dataflow.intermediate_steps:
            locations.append(self._thread_flow_location(step, "intermediate"))
        for sanitizer in vuln.dataflow.sanitizers:
            locations.append(
                self._thread_flow_location(
                    sanitizer.location,
                    f"sanitizer:{sanitizer.function_name}",
                )
            )
        locations.append(self._thread_flow_location(vuln.dataflow.sink.location, "sink"))
        return locations

    def _build_thread_flow_from_record(
        self,
        record: TriageRecord,
    ) -> List[Dict[str, object]]:
        finding = record.finding
        locations: List[Dict[str, object]] = []
        locations.append(self._thread_flow_location(finding.evidence.source, "source"))
        for step in finding.evidence.intermediate_steps:
            locations.append(self._thread_flow_location(step, "intermediate"))
        for sanitizer in finding.evidence.sanitizers:
            locations.append(
                self._thread_flow_location(
                    sanitizer.location,
                    f"sanitizer:{sanitizer.function_name}",
                )
            )
        locations.append(self._thread_flow_location(finding.evidence.sink, "sink"))
        return locations

    @staticmethod
    def _sarif_location(location: CodeLocation, label: str) -> Dict[str, object]:
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": location.file_path},
                "region": {
                    "startLine": location.line_number,
                    "startColumn": max(location.column_number, 1),
                    "snippet": {"text": location.code_snippet},
                },
            },
            "message": {"text": label},
        }

    @staticmethod
    def _thread_flow_location(location: CodeLocation, label: str) -> Dict[str, object]:
        return {
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": location.file_path},
                    "region": {
                        "startLine": location.line_number,
                        "startColumn": max(location.column_number, 1),
                        "snippet": {"text": location.code_snippet},
                    },
                }
            },
            "message": {"text": label},
        }

    @staticmethod
    def _sarif_level(severity: Severity) -> str:
        if severity in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if severity == Severity.MEDIUM:
            return "warning"
        return "note"

    @staticmethod
    def _security_severity(severity: Severity) -> str:
        return {
            Severity.CRITICAL: "9.5",
            Severity.HIGH: "8.0",
            Severity.MEDIUM: "5.5",
            Severity.LOW: "3.0",
            Severity.INFO: "1.0",
            Severity.UNKNOWN: "0.0",
        }.get(severity, "0.0")

    @staticmethod
    def _build_agent_reviews(record: TriageRecord) -> Dict[str, object]:
        """Extract node-level workflow reviews from finding metadata."""
        metadata = record.finding.metadata
        return {
            "auditor_review": metadata.get("auditor_review"),
            "skeptic_review": metadata.get("skeptic_review"),
            "judge_review": metadata.get("judge_review"),
        }

    @staticmethod
    def _build_workflow_summary(workflow_metadata: Dict[str, object]) -> Dict[str, object]:
        """Keep the most relevant workflow metadata inside the SARIF run."""
        keys = [
            "scan_profile",
            "framework_hints",
            "knowledge_card_count",
            "triage_summary",
            "route_summary",
            "auditor_summary",
            "skeptic_summary",
            "judge_summary",
        ]
        return {
            key: workflow_metadata[key]
            for key in keys
            if key in workflow_metadata
        }
