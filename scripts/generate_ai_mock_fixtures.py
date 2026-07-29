"""Generate a synthetic 25-case AI fixture dataset."""

import argparse
import json
from pathlib import Path


LANGUAGE_EXT = {
    "python": "py",
    "javascript": "js",
    "java": "java",
    "php": "php",
}

CASES = [
    ("python", "COMMAND_INJECTION", "CWE-78", True, "confirmed", False, False, 0.9),
    ("python", "SQL_INJECTION", "CWE-89", True, "confirmed", False, False, 0.88),
    ("python", "PATH_TRAVERSAL", "CWE-22", False, "suppressed", True, False, 0.62),
    ("python", "SSRF", "CWE-918", True, "likely", False, False, 0.72),
    ("python", "XSS", "CWE-79", None, "needs-review", False, False, 0.48),
    ("python", "COMMAND_INJECTION", "CWE-78", False, "suppressed", False, True, 0.55),
    ("javascript", "SQL_INJECTION", "CWE-89", False, "suppressed", True, False, 0.66),
    ("javascript", "COMMAND_INJECTION", "CWE-78", True, "confirmed", False, False, 0.89),
    ("javascript", "PATH_TRAVERSAL", "CWE-22", True, "likely", False, False, 0.76),
    ("javascript", "SSRF", "CWE-918", None, "needs-review", False, False, 0.51),
    ("javascript", "XSS", "CWE-79", False, "suppressed", True, False, 0.61),
    ("javascript", "OPEN_REDIRECT", "CWE-601", None, "needs-review", False, False, 0.44),
    ("java", "SQL_INJECTION", "CWE-89", True, "confirmed", False, False, 0.91),
    ("java", "COMMAND_INJECTION", "CWE-78", False, "suppressed", True, False, 0.65),
    ("java", "PATH_TRAVERSAL", "CWE-22", False, "suppressed", False, True, 0.54),
    ("java", "SSRF", "CWE-918", True, "likely", False, False, 0.73),
    ("java", "XSS", "CWE-79", None, "needs-review", False, False, 0.5),
    ("java", "SQL_INJECTION", "CWE-89", False, "suppressed", True, False, 0.58),
    ("php", "XSS", "CWE-79", True, "confirmed", False, False, 0.86),
    ("php", "SQL_INJECTION", "CWE-89", False, "suppressed", True, False, 0.64),
    ("php", "COMMAND_INJECTION", "CWE-78", True, "likely", False, False, 0.75),
    ("php", "PATH_TRAVERSAL", "CWE-22", False, "suppressed", False, True, 0.57),
    ("php", "SSRF", "CWE-918", None, "needs-review", False, False, 0.47),
    ("php", "XSS", "CWE-79", False, "suppressed", True, False, 0.6),
    ("php", "UNSUPPORTED", "CWE-999", None, "needs-review", False, False, 0.42),
]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    truth_rows = []
    for index, case in enumerate(CASES, 1):
        language, vuln_type, cwe_id, truth, expected, sanitizer, dead_path, confidence = case
        finding_id = f"SYN-{index:03d}"
        payload = _build_payload(
            finding_id=finding_id,
            language=language,
            vuln_type=vuln_type,
            cwe_id=cwe_id,
            expected=expected,
            sanitizer=sanitizer,
            dead_path=dead_path,
            confidence=confidence,
        )
        language_dir = args.out / language
        language_dir.mkdir(parents=True, exist_ok=True)
        (language_dir / f"{finding_id.lower()}.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        truth_rows.append(
            {
                "finding_id": finding_id,
                "ground_truth_vuln": truth,
                "expected_status": expected,
            }
        )

    (args.out / "ground_truth.jsonl").write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in truth_rows) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {len(CASES)} synthetic AI fixtures to {args.out}")


def _build_payload(
    *,
    finding_id: str,
    language: str,
    vuln_type: str,
    cwe_id: str,
    expected: str,
    sanitizer: bool,
    dead_path: bool,
    confidence: float,
) -> dict:
    ext = LANGUAGE_EXT[language]
    source = {
        "file_path": f"src/{finding_id.lower()}.{ext}",
        "line_number": 10,
        "column_number": 2,
        "code_snippet": "user_value = request_input",
    }
    sink = {
        "file_path": f"src/{finding_id.lower()}.{ext}",
        "line_number": 14,
        "column_number": 2,
        "code_snippet": f"dangerous_sink(user_value)  # {vuln_type}",
    }
    data_flow_path = [source, sink] if expected != "needs-review" else [source]
    sanitizer_info = {
        "present": sanitizer,
        "effective": sanitizer,
        "sanitizer_type": "SYNTHETIC_SAFE_PATTERN" if sanitizer else None,
        "function_name": "safe_api" if sanitizer else None,
        "notes": ["Synthetic sanitizer evidence."] if sanitizer else ["No sanitizer evidence."],
    }
    graph_metadata = {
        "cfg_edge_count": 2,
        "dfg_edge_count": 1 if len(data_flow_path) >= 2 else 0,
        "dead_path_suspected": dead_path,
        "unsupported_framework": vuln_type == "UNSUPPORTED",
        "notes": ["Synthetic fixture generated for AI workflow tests."],
    }
    finding = {
        "finding_id": finding_id,
        "rule_id": f"synthetic-{vuln_type.lower()}",
        "language": language,
        "vuln_type": vuln_type,
        "cwe_id": cwe_id,
        "severity": "HIGH" if expected in {"confirmed", "likely"} else "MEDIUM",
        "confidence": confidence,
        "source_location": source,
        "sink_location": sink,
        "evidence_snippets": [f"Synthetic {vuln_type} evidence for {language}."],
        "data_flow_path": data_flow_path,
        "sanitizer_info": sanitizer_info,
        "graph_metadata": graph_metadata,
        "cross_file": finding_id.endswith("004"),
        "call_chain_depth": 1,
    }
    evidence = {
        "finding_id": finding_id,
        "source_location": source,
        "sink_location": sink,
        "evidence_snippets": finding["evidence_snippets"],
        "data_flow_path": data_flow_path,
        "sanitizer_info": sanitizer_info,
        "graph_metadata": graph_metadata,
        "cross_file": finding["cross_file"],
        "call_chain_depth": finding["call_chain_depth"],
    }
    return {
        "finding": finding,
        "evidence": evidence,
        "benchmark": {
            "benchmark_id": "synthetic-ai-fixtures-v1",
            "dataset_name": "synthetic-ai-findings-25",
            "case_id": finding_id,
            "expected_status": expected,
            "language": language,
        },
    }


if __name__ == "__main__":
    main()
