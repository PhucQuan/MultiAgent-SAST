"""
JSON exporter for machine-readable vulnerability reports.

Exports scan results in JSON format for CI/CD integration.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List

from aegis_sast.core.models import ScanResult, Vulnerability


class JSONExporter:
    """Exports vulnerability reports in JSON format."""
    
    def __init__(self, output_dir: Path):
        """
        Initialize JSON exporter.
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def export(self, scan_result: ScanResult, filename: str = None) -> Path:
        """
        Export scan results to JSON file.
        
        Args:
            scan_result: ScanResult object
            filename: Optional custom filename
            
        Returns:
            Path to exported file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"aegis_sast_report_{timestamp}.json"
        
        output_path = self.output_dir / filename
        
        # Build JSON structure
        report = {
            "scan_metadata": {
                "tool": "aegis-sast",
                "version": "1.0.0",
                "timestamp": scan_result.start_time.isoformat(),
                "target": scan_result.target_path,
                "duration_seconds": scan_result.duration,
                "files_scanned": scan_result.files_scanned
            },
            "findings": [
                self._vulnerability_to_dict(vuln)
                for vuln in scan_result.vulnerabilities
            ],
            "summary": scan_result.get_summary(),
            "errors": scan_result.errors
        }
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return output_path
    
    def _vulnerability_to_dict(self, vuln: Vulnerability) -> dict:
        """Convert Vulnerability object to dictionary."""
        return vuln.to_dict()
