"""Test full workflow with SemgrepRunner + TaintBridge + ScanWorkflow."""
from pathlib import Path
from datetime import datetime

from aegis_sast.core.models import ScanResult
from aegis_sast.integrations.semgrep_adapter import ImportedNormalizedVulnerability
from aegis_sast.integrations.semgrep_runner import SemgrepRunner
from aegis_sast.integrations.taint_bridge import TaintBridge
from aegis_sast.orchestration.state import RepoProfile
from aegis_sast.orchestration.workflow import ScanWorkflow

target = Path("examples/vulnerable_rce.py").resolve()

# 1. Run Semgrep
runner = SemgrepRunner()
matches = runner.run(str(target))
print(f"1. Semgrep found {len(matches)} matches")

# 2. Bridge with DFG
bridge = TaintBridge()
findings = bridge.bridge_matches(matches, project_root=target.parent)
print(f"2. TaintBridge produced {len(findings)} deduplicated normalized findings")

# 3. Create ScanResult
vulnerabilities = [ImportedNormalizedVulnerability(finding=f) for f in findings]
scan_result = ScanResult(
    target_path=str(target),
    start_time=datetime.now(),
    end_time=datetime.now(),
    vulnerabilities=vulnerabilities,
    files_scanned=1,
)

# 4. Run Workflow (Auditor, Skeptic, Judge)
workflow = ScanWorkflow()
repo_profile = RepoProfile(
    target_path=str(target),
    scan_profile="python-deep-analysis",
    detected_languages=["python"],
    framework_hints=["flask"],
    files_scanned=1,
)
state = workflow.run(scan_result, repo_profile=repo_profile)
print(f"3. Workflow produced {len(state.triage_records)} triage records")

triage_summary = {}
for r in state.triage_records:
    status = r.decision.status.value
    triage_summary[status] = triage_summary.get(status, 0) + 1

print(f"   Triage breakdown: {triage_summary}")
for r in state.triage_records[:3]:
    f = r.finding
    d = r.decision
    print(f"\n   Finding: [{f.severity.value}] {f.rule_id}")
    print(f"     Decision: {d.status.value} (conf={d.confidence:.2f}) by {d.reviewer}")
    print(f"     Reason codes: {d.reason_codes}")
    print(f"     Src: {f.evidence.source.code_snippet}")
    print(f"     Sink: {f.evidence.sink.code_snippet}")
