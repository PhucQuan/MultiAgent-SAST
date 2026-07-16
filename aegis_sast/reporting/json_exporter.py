"""JSON exporter for machine-readable vulnerability and triage reports."""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from aegis_sast.core.models import ScanResult, Vulnerability
from aegis_sast.triage.schema import TriageRecord


class JSONExporter:
    """Exports vulnerability reports in JSON format."""

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
        """Export scan results to a JSON report file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"aegis_sast_report_{timestamp}.json"

        output_path = self.output_dir / filename

        report = {
            "scan_metadata": {
                "tool": "aegis-sast",
                "version": "1.0.0",
                "timestamp": scan_result.start_time.isoformat(),
                "target": scan_result.target_path,
                "duration_seconds": scan_result.duration,
                "files_scanned": scan_result.files_scanned,
            },
            "findings": self._build_findings(scan_result, triage_records),
            "summary": scan_result.get_summary(),
            "errors": scan_result.errors,
        }

        if triage_records:
            report["triage_summary"] = self._build_triage_summary(triage_records)
        if workflow_metadata:
            report["workflow_summary"] = self._build_workflow_summary(workflow_metadata)

        with open(output_path, "w", encoding="utf-8") as file_handle:
            json.dump(report, file_handle, indent=2, ensure_ascii=False)

        return output_path

    def _build_findings(
        self,
        scan_result: ScanResult,
        triage_records: Optional[List[TriageRecord]],
    ) -> List[dict]:
        """Build the findings payload, optionally using triage records."""
        if triage_records:
            return [self._triage_record_to_dict(record) for record in triage_records]
        return [self._vulnerability_to_dict(vuln) for vuln in scan_result.vulnerabilities]

    @staticmethod
    def _vulnerability_to_dict(vuln: Vulnerability) -> dict:
        """Convert a vulnerability object to a dictionary."""
        return vuln.to_dict()

    @staticmethod
    def _triage_record_to_dict(record: TriageRecord) -> dict:
        """Convert a triage record to a JSON-friendly dictionary."""
        payload = record.finding.to_dict()
        payload["triage_decision"] = record.decision.to_dict()
        payload["agent_reviews"] = JSONExporter._build_agent_reviews(record)
        return payload

    @staticmethod
    def _build_triage_summary(triage_records: List[TriageRecord]) -> dict:
        """Count triage decisions by final status."""
        summary = {}
        for record in triage_records:
            status = record.decision.status.value
            summary[status] = summary.get(status, 0) + 1
        return summary

    @staticmethod
    def _build_agent_reviews(record: TriageRecord) -> dict:
        """Extract node-level workflow reviews from finding metadata."""
        metadata = record.finding.metadata
        return {
            "auditor_review": metadata.get("auditor_review"),
            "skeptic_review": metadata.get("skeptic_review"),
            "judge_review": metadata.get("judge_review"),
        }

    @staticmethod
    def _build_workflow_summary(workflow_metadata: Dict[str, object]) -> dict:
        """Keep the most relevant workflow metadata for report consumers."""
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
