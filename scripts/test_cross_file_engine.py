"""Test CrossFileTaintEngine on examples/cross_file_rce."""
from pathlib import Path
from aegis_sast.analysis.cross_file_taint import CrossFileTaintEngine

project_root = Path("examples/cross_file_rce").resolve()
engine = CrossFileTaintEngine(project_root)
findings = engine.analyze_project()

print(f"\nCrossFileTaintEngine found {len(findings)} inter-procedural findings:\n")
for idx, f in enumerate(findings, 1):
    print(f"[{idx}] [{f.severity.value}] {f.vulnerability_type} ({f.rule_id})")
    print(f"    Message: {f.message}")
    print(f"    Confidence: {f.confidence:.2f} | Status: {f.triage_status.value}")
    print(f"    Files involved: {f.metadata.get('files_involved')}")
    print(f"    Exploit Path ({len(f.evidence.intermediate_steps) + 2} steps):")
    print(f"      Step 1 (Source): [{f.evidence.source.file_path}:{f.evidence.source.line_number}] {f.evidence.source.code_snippet}")
    for j, s in enumerate(f.evidence.intermediate_steps, 2):
        print(f"      Step {j} (Flow):   [{s.file_path}:{s.line_number}] {s.code_snippet}")
    print(f"      Step {len(f.evidence.intermediate_steps) + 2} (Sink):   [{f.evidence.sink.file_path}:{f.evidence.sink.line_number}] {f.evidence.sink.code_snippet}")
    print()
