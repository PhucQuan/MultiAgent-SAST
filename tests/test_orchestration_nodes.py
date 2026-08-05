"""Tests for deterministic workflow nodes and source context loading."""

from pathlib import Path
from tempfile import TemporaryDirectory

from aegis_sast.core.models import (
    CodeLocation,
    DataFlowPath,
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
    SkepticValidatorNode,
)
from aegis_sast.triage import TriageEngine


def test_nodes_attach_context_and_allow_skeptical_demotion():
    """Auditor and skeptic nodes should attach context and demote mitigated flows."""
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

        vuln = Vulnerability(
            id="VULN-400",
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
        record = engine.triage_vulnerability(vuln)

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
        assert "subprocess.run" in "\n".join(auditor_review.context.sink_window.lines)
        assert skeptic_review.executed is True
        assert skeptic_review.mitigation_signals
        assert final_record.decision.status.value == "suppressed"
        assert judge_review.final_status.value == "suppressed"
        assert final_record.finding.metadata["auditor_review"]["route_id"] == "skeptic-review"
        assert final_record.finding.metadata["triage"]["agent_reviews"]["judge_review"]["final_status"] == "suppressed"
        assert "path_length=2" in auditor_review.notes
        assert "sanitizers=0" in auditor_review.notes


def test_nodes_promote_strong_unmitigated_sqli_to_likely():
    """Judge should promote a strong unsanitized SQLi flow when skeptic finds no mitigation."""
    with TemporaryDirectory() as tmp_dir:
        target = Path(tmp_dir) / "service.py"
        target.write_text(
            "\n".join(
                [
                    "import sqlite3",
                    "user_id = request.args.get('id')",
                    "query = \"SELECT * FROM users WHERE id = '\" + user_id + \"'\"",
                    "cursor.execute(query)",
                ]
            ),
            encoding="utf-8",
        )

        vuln = Vulnerability(
            id="VULN-401",
            vuln_type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            dataflow=DataFlowPath(
                source=TaintSource(
                    CodeLocation(str(target), 2, 1, "user_id = request.args.get('id')"),
                    "HTTP_PARAM",
                    "user_id",
                    "request.args.get",
                ),
                sink=TaintSink(
                    CodeLocation(str(target), 4, 1, "cursor.execute(query)"),
                    VulnerabilityType.SQL_INJECTION,
                    "cursor.execute",
                    ".execute(",
                ),
            ),
        )

        engine = TriageEngine()
        record = engine.triage_vulnerability(vuln)
        cards = KnowledgeLoader().filter_cards(
            engine.cards,
            language="python",
            finding_type="SQL_INJECTION",
        )
        repo_profile = RepoIntake().analyze_target(target)

        auditor_review = AuditorNode().review(record, cards, repo_profile)
        skeptic_review = SkepticValidatorNode().review(record, cards, auditor_review)
        final_record, judge_review = JudgeNode().finalize(
            record,
            auditor_review,
            skeptic_review,
        )

        assert skeptic_review.executed is True
        assert not skeptic_review.mitigation_signals
        assert not skeptic_review.objections
        assert final_record.decision.status.value == "likely"
        assert final_record.decision.confidence >= 0.72
        assert judge_review.metadata["promotion_applied"] is True
        assert "dynamic-sql-construction" in judge_review.metadata["risk_signals"]


def test_nodes_keep_dynamic_prepared_statement_sqli_visible():
    """PreparedStatement should not suppress SQLi when the SQL string is still built dynamically."""
    with TemporaryDirectory() as tmp_dir:
        target = Path(tmp_dir) / "BenchmarkTest00024.java"
        target.write_text(
            "\n".join(
                [
                    "import java.sql.*;",
                    "class BenchmarkTest00024 {",
                    "  void run(HttpServletRequest request, Connection connection) throws Exception {",
                    '    String param = request.getParameter("id");',
                    '    String sql = "SELECT * from USERS where USERNAME=? and PASSWORD=\'" + param + "\'";',
                    "    PreparedStatement statement = connection.prepareStatement(",
                    "        sql,",
                    "        java.sql.ResultSet.TYPE_FORWARD_ONLY,",
                    "        java.sql.ResultSet.CONCUR_READ_ONLY,",
                    "        java.sql.ResultSet.CLOSE_CURSORS_AT_COMMIT);",
                    '    statement.setString(1, "foo");',
                    "    statement.execute();",
                    "  }",
                    "}",
                ]
            ),
            encoding="utf-8",
        )

        vuln = Vulnerability(
            id="VULN-402",
            vuln_type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            dataflow=DataFlowPath(
                source=TaintSource(
                    CodeLocation(str(target), 4, 1, 'String param = request.getParameter("id");'),
                    "HTTP_PARAM",
                    "param",
                    "getParameter(",
                ),
                sink=TaintSink(
                    CodeLocation(str(target), 6, 1, "PreparedStatement statement = connection.prepareStatement("),
                    VulnerabilityType.SQL_INJECTION,
                    "prepareStatement",
                    "prepareStatement(",
                    arguments=[
                        "sql",
                        "java.sql.ResultSet.TYPE_FORWARD_ONLY",
                        "java.sql.ResultSet.CONCUR_READ_ONLY",
                        "java.sql.ResultSet.CLOSE_CURSORS_AT_COMMIT",
                    ],
                ),
                intermediate_steps=[
                    CodeLocation(
                        str(target),
                        5,
                        1,
                        'String sql = "SELECT * from USERS where USERNAME=? and PASSWORD=\'" + param + "\'";',
                    )
                ],
            ),
        )

        engine = TriageEngine()
        record = engine.triage_vulnerability(vuln)
        cards = KnowledgeLoader().filter_cards(
            engine.cards,
            language="java",
            finding_type="SQL_INJECTION",
        )
        repo_profile = RepoIntake().analyze_target(target)

        auditor_review = AuditorNode().review(record, cards, repo_profile)
        skeptic_review = SkepticValidatorNode().review(record, cards, auditor_review)
        final_record, judge_review = JudgeNode().finalize(
            record,
            auditor_review,
            skeptic_review,
        )

        assert skeptic_review.executed is True
        assert not skeptic_review.mitigation_signals
        assert final_record.decision.status.value == "likely"
        assert judge_review.final_status.value == "likely"
