"""Lightweight smoke checks for triage and orchestration without pytest."""

from __future__ import annotations

import sys
import traceback
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegis_sast.core.config import AegisConfig
from aegis_sast.core.models import (
    AIVerification,
    CodeLocation,
    DataFlowPath,
    Sanitizer,
    ScanResult,
    Severity,
    TaintSink,
    TaintSource,
    Vulnerability,
    VulnerabilityType,
)
from aegis_sast.knowledge import KnowledgeLoader
from aegis_sast.orchestration import (
    AuditorNode,
    JudgeNode,
    RepoIntake,
    ScanWorkflow,
    SkepticValidatorNode,
)
from aegis_sast.triage import TriageEngine


def smoke_config() -> None:
    """Validate the stdlib-based config path used by --no-ai runs."""
    config = AegisConfig.from_env()
    assert config.output_dir is not None
    assert isinstance(config.output_formats, list)


def smoke_node_flow() -> None:
    """Validate auditor, skeptic, and judge behavior on one finding."""
    with TemporaryDirectory() as tmp_dir:
        target = Path(tmp_dir) / "service.py"
        target.write_text(
            "\n".join(
                [
                    "import subprocess",
                    "user = request.args.get('cmd')",
                    "result = subprocess.run(['ls', user], shell=False)",
                    "print(result)",
                ]
            ),
            encoding="utf-8",
        )

        vulnerability = Vulnerability(
            id="SMOKE-400",
            vuln_type=VulnerabilityType.COMMAND_INJECTION,
            severity=Severity.HIGH,
            dataflow=DataFlowPath(
                source=TaintSource(
                    CodeLocation(str(target), 2, 1, "user = request.args.get('cmd')"),
                    "HTTP_PARAM",
                    "user",
                    "request.args.get",
                ),
                sink=TaintSink(
                    CodeLocation(
                        str(target),
                        3,
                        1,
                        "result = subprocess.run(['ls', user], shell=False)",
                    ),
                    VulnerabilityType.COMMAND_INJECTION,
                    "subprocess.run",
                    "subprocess.run(",
                ),
            ),
        )

        engine = TriageEngine()
        record = engine.triage_vulnerability(vulnerability)
        cards = KnowledgeLoader().filter_cards(
            engine.cards,
            language="python",
            finding_type="COMMAND_INJECTION",
        )
        repo_profile = RepoIntake().analyze_target(target)

        auditor_review = AuditorNode().review(record, cards, repo_profile)
        skeptic_review = SkepticValidatorNode().review(record, cards, auditor_review)
        final_record, judge_review = JudgeNode().finalize(
            record,
            auditor_review,
            skeptic_review,
        )

        assert auditor_review.context is not None
        assert auditor_review.context.sink_window is not None
        assert skeptic_review.executed is True
        assert skeptic_review.mitigation_signals
        assert final_record.decision.status.value == "suppressed"
        assert judge_review.final_status.value == "suppressed"


def smoke_workflow() -> None:
    """Validate aggregate workflow metadata and routing summaries."""
    with TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        python_file = root / "app.py"
        python_file.write_text(
            "\n".join(
                [
                    "import os",
                    "cmd = request.args.get('cmd')",
                    "safe_cmd = cmd",
                    "os.system(safe_cmd)",
                ]
            ),
            encoding="utf-8",
        )
        java_file = root / "Controller.java"
        java_file.write_text(
            "\n".join(
                [
                    "class Controller {",
                    "  void run(String name) {",
                    "    String query = \"SELECT * FROM users WHERE name = ?\";",
                    "    PreparedStatement ps = conn.prepareStatement(query);",
                    "    ps.setString(1, name);",
                    "  }",
                    "}",
                ]
            ),
            encoding="utf-8",
        )

        python_source = TaintSource(
            CodeLocation(str(python_file), 2, 1, "cmd = request.args.get('cmd')"),
            "HTTP_PARAM",
            "cmd",
            "request.args.get",
        )
        python_sink = TaintSink(
            CodeLocation(str(python_file), 4, 1, "os.system(safe_cmd)"),
            VulnerabilityType.COMMAND_INJECTION,
            "os.system",
            "os.system(",
        )
        python_vulnerability = Vulnerability(
            id="SMOKE-201",
            vuln_type=VulnerabilityType.COMMAND_INJECTION,
            severity=Severity.CRITICAL,
            dataflow=DataFlowPath(
                source=python_source,
                sink=python_sink,
                intermediate_steps=[
                    CodeLocation(str(python_file), 3, 1, "safe_cmd = cmd")
                ],
            ),
            ai_verification=AIVerification(
                is_vulnerable=True,
                confidence=0.92,
                explanation="User-controlled command reaches shell execution.",
                recommendation="Use a fixed argument array.",
                model_used="smoke-model",
            ),
        )

        java_source = TaintSource(
            CodeLocation(
                str(java_file),
                2,
                1,
                "void run(String name) {",
            ),
            "HTTP_PARAM",
            "name",
            "request.getParameter",
        )
        java_sink = TaintSink(
            CodeLocation(str(java_file), 4, 1, "PreparedStatement ps = conn.prepareStatement(query);"),
            VulnerabilityType.SQL_INJECTION,
            "PreparedStatement",
            "prepareStatement(",
        )
        sanitizer = Sanitizer(
            CodeLocation(str(java_file), 5, 1, "ps.setString(1, name);"),
            "PREPARED_STATEMENT",
            "PreparedStatement",
            mitigates=[VulnerabilityType.SQL_INJECTION],
        )
        java_vulnerability = Vulnerability(
            id="SMOKE-202",
            vuln_type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.HIGH,
            dataflow=DataFlowPath(
                source=java_source,
                sink=java_sink,
                sanitizers=[sanitizer],
            ),
        )

        result = ScanResult(
            target_path=str(root),
            start_time=datetime.now(),
            end_time=datetime.now(),
            vulnerabilities=[python_vulnerability, java_vulnerability],
            files_scanned=2,
        )

        state = ScanWorkflow().run(result)

        assert state.repo_profile is not None
        assert state.repo_profile.scan_profile == "polyglot-python-priority"
        assert state.metadata["triage_summary"]["confirmed"] == 1
        assert state.metadata["triage_summary"]["suppressed"] == 1
        assert state.metadata["route_summary"]["direct-judge"] == 1
        assert state.metadata["route_summary"]["skeptic-review"] == 1
        assert state.metadata["skeptic_summary"]["executed"] == 1


def main() -> int:
    """Run all lightweight smoke checks."""
    checks = [
        ("config", smoke_config),
        ("node_flow", smoke_node_flow),
        ("workflow", smoke_workflow),
    ]

    for name, fn in checks:
        try:
            fn()
            print(f"[ok] {name}")
        except Exception:
            print(f"[fail] {name}")
            traceback.print_exc()
            return 1

    print("manual smoke completed successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main())
