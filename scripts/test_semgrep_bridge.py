"""Test upgraded TaintBridge on examples/vulnerable_rce.py."""
from aegis_sast.integrations.semgrep_runner import SemgrepRunner
from aegis_sast.integrations.taint_bridge import TaintBridge

runner = SemgrepRunner()
matches = runner.run("examples/vulnerable_rce.py")
print(f"Total raw Semgrep matches: {len(matches)}")

bridge = TaintBridge()
findings = bridge.bridge_matches(matches)
print(f"Total deduplicated & bridged findings: {len(findings)}\n")

for i, f in enumerate(findings, 1):
    print(f"[{i}] [{f.severity.value}] {f.vulnerability_type} ({f.rule_id})")
    print(f"    Status: {f.triage_status.value} (conf: {f.confidence:.2f})")
    print(f"    Message: {f.message}")
    print(f"    DFG Trace: Success={f.evidence.metadata.get('dfg_trace_success')}")
    print(f"      Step 1 (Source): line {f.evidence.source.line_number}: {f.evidence.source.code_snippet}")
    for j, step in enumerate(f.evidence.intermediate_steps, 1):
        print(f"      Step 2.{j} (Flow):   line {step.line_number}: {step.code_snippet}")
    print(f"      Step 3 (Sink):   line {f.evidence.sink.line_number}: {f.evidence.sink.code_snippet}")
    if f.evidence.sanitizers:
        print(f"      Sanitizers: {[s.function_name for s in f.evidence.sanitizers]}")
    if "alias_rule_ids" in f.metadata:
        print(f"      Aliases: {f.metadata['alias_rule_ids']}")
    print()
