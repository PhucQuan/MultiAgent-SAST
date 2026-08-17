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


def test_nodes_confirm_strong_unmitigated_sqli_when_signals_are_direct():
    """Judge should confirm dynamic SQLi when execution evidence is unambiguous."""
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
        assert final_record.decision.status.value == "confirmed"
        assert final_record.decision.confidence >= 0.88
        assert judge_review.metadata["promotion_applied"] is True
        assert judge_review.metadata["promotion_target"] == "confirmed"
        assert "dynamic-sql-construction" in judge_review.metadata["risk_signals"]


def test_nodes_suppress_open_redirect_when_context_has_target_allowlist():
    """Allowlist-style redirect validation should suppress noisy redirect findings."""
    with TemporaryDirectory() as tmp_dir:
        target = Path(tmp_dir) / "service.py"
        target.write_text(
            "\n".join(
                [
                    "import flask",
                    "import urllib.parse",
                    "target = request.args.get('next')",
                    "bar = target",
                    "url = urllib.parse.urlparse(bar)",
                    "if url.netloc not in ['google.com'] or url.scheme != 'https':",
                    "    return 'Invalid URL.'",
                    "return flask.redirect(bar)",
                ]
            ),
            encoding="utf-8",
        )

        vuln = Vulnerability(
            id="VULN-403",
            vuln_type=VulnerabilityType.OPEN_REDIRECT,
            severity=Severity.MEDIUM,
            dataflow=DataFlowPath(
                source=TaintSource(
                    CodeLocation(str(target), 3, 1, "target = request.args.get('next')"),
                    "HTTP_PARAM",
                    "target",
                    "request.args.get",
                ),
                sink=TaintSink(
                    CodeLocation(str(target), 8, 1, "return flask.redirect(bar)"),
                    VulnerabilityType.OPEN_REDIRECT,
                    "flask.redirect",
                    "redirect(",
                ),
                intermediate_steps=[
                    CodeLocation(str(target), 4, 1, "bar = target"),
                ],
            ),
        )

        engine = TriageEngine()
        record = engine.triage_vulnerability(vuln)
        cards = KnowledgeLoader().filter_cards(
            engine.cards,
            language="python",
            finding_type="OPEN_REDIRECT",
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
        assert skeptic_review.mitigation_signals
        assert final_record.decision.status.value == "suppressed"
        assert judge_review.final_status.value == "suppressed"


def test_nodes_suppress_code_injection_when_exec_is_literal_guarded():
    """Literal-only exec guards should suppress code-injection false positives."""
    with TemporaryDirectory() as tmp_dir:
        target = Path(tmp_dir) / "service.py"
        target.write_text(
            "\n".join(
                [
                    "expr = request.args.get('expr')",
                    "bar = expr",
                    "if not bar.startswith(\"'\") or not bar.endswith(\"'\") or \"'\" in bar[1:-1]:",
                    "    return 'literal only'",
                    "exec(bar)",
                ]
            ),
            encoding="utf-8",
        )

        vuln = Vulnerability(
            id="VULN-404",
            vuln_type=VulnerabilityType.CODE_INJECTION,
            severity=Severity.CRITICAL,
            dataflow=DataFlowPath(
                source=TaintSource(
                    CodeLocation(str(target), 1, 1, "expr = request.args.get('expr')"),
                    "HTTP_PARAM",
                    "expr",
                    "request.args.get",
                ),
                sink=TaintSink(
                    CodeLocation(str(target), 5, 1, "exec(bar)"),
                    VulnerabilityType.CODE_INJECTION,
                    "exec",
                    "exec(",
                ),
                intermediate_steps=[
                    CodeLocation(str(target), 2, 1, "bar = expr"),
                ],
            ),
        )

        engine = TriageEngine()
        record = engine.triage_vulnerability(vuln)
        cards = KnowledgeLoader().filter_cards(
            engine.cards,
            language="python",
            finding_type="CODE_INJECTION",
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
        assert skeptic_review.mitigation_signals
        assert final_record.decision.status.value == "suppressed"
        assert judge_review.final_status.value == "suppressed"


def test_nodes_suppress_command_injection_when_safe_lookup_overwrites_bar():
    """Constant key lookups should suppress shell findings when `bar` is overwritten safely."""
    with TemporaryDirectory() as tmp_dir:
        target = Path(tmp_dir) / "service.py"
        target.write_text(
            "\n".join(
                [
                    "param = request.args.get('cmd')",
                    "mapping = {}",
                    "mapping['keyA-demo'] = 'a-Value'",
                    "mapping['keyB-demo'] = param",
                    "bar = mapping['keyB-demo']",
                    "bar = mapping['keyA-demo']",
                    "arg_str = f\"sh -c echo {bar}\"",
                    "subprocess.run(arg_str, shell=True)",
                ]
            ),
            encoding="utf-8",
        )

        vuln = Vulnerability(
            id="VULN-405",
            vuln_type=VulnerabilityType.COMMAND_INJECTION,
            severity=Severity.CRITICAL,
            dataflow=DataFlowPath(
                source=TaintSource(
                    CodeLocation(str(target), 1, 1, "param = request.args.get('cmd')"),
                    "HTTP_PARAM",
                    "param",
                    "request.args.get",
                ),
                sink=TaintSink(
                    CodeLocation(str(target), 8, 1, "subprocess.run(arg_str, shell=True)"),
                    VulnerabilityType.COMMAND_INJECTION,
                    "subprocess.run",
                    "subprocess.run(",
                ),
                intermediate_steps=[
                    CodeLocation(str(target), 5, 1, "bar = mapping['keyB-demo']"),
                    CodeLocation(str(target), 6, 1, "bar = mapping['keyA-demo']"),
                ],
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

        assert skeptic_review.executed is True
        assert skeptic_review.mitigation_signals
        assert final_record.decision.status.value == "suppressed"
        assert judge_review.final_status.value == "suppressed"


def test_nodes_suppress_deserialization_when_constant_match_branch_is_selected():
    """Constant match/case branches should suppress deserialization noise."""
    with TemporaryDirectory() as tmp_dir:
        target = Path(tmp_dir) / "service.py"
        target.write_text(
            "\n".join(
                [
                    "param = request.headers.get('payload')",
                    "possible = 'ABC'",
                    "guess = possible[1]",
                    "match guess:",
                    "    case 'A':",
                    "        bar = param",
                    "    case 'B':",
                    "        bar = 'bob'",
                    "    case 'C' | 'D':",
                    "        bar = param",
                    "    case _:",
                    "        bar = 'fallback'",
                    "yaml.load(bar, Loader=yaml.Loader)",
                ]
            ),
            encoding="utf-8",
        )

        vuln = Vulnerability(
            id="VULN-406",
            vuln_type=VulnerabilityType.INSECURE_DESERIALIZATION,
            severity=Severity.CRITICAL,
            dataflow=DataFlowPath(
                source=TaintSource(
                    CodeLocation(str(target), 1, 1, "param = request.headers.get('payload')"),
                    "HTTP_HEADER",
                    "param",
                    "request.headers.get",
                ),
                sink=TaintSink(
                    CodeLocation(str(target), 13, 1, "yaml.load(bar, Loader=yaml.Loader)"),
                    VulnerabilityType.INSECURE_DESERIALIZATION,
                    "yaml.load",
                    "yaml.load(",
                ),
                intermediate_steps=[
                    CodeLocation(str(target), 6, 1, "bar = param"),
                    CodeLocation(str(target), 8, 1, "bar = 'bob'"),
                ],
            ),
        )

        engine = TriageEngine()
        record = engine.triage_vulnerability(vuln)
        cards = KnowledgeLoader().filter_cards(
            engine.cards,
            language="python",
            finding_type="INSECURE_DESERIALIZATION",
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
        assert skeptic_review.mitigation_signals
        assert final_record.decision.status.value == "suppressed"
        assert judge_review.final_status.value == "suppressed"


def test_nodes_suppress_deserialization_when_constant_if_branch_is_selected():
    """Constant conditions should suppress deserialization findings when the safe branch wins."""
    with TemporaryDirectory() as tmp_dir:
        target = Path(tmp_dir) / "service.py"
        target.write_text(
            "\n".join(
                [
                    "param = request.headers.get('payload')",
                    "num = 86",
                    "if 7 * 42 - num > 200:",
                    "    bar = 'This_should_always_happen'",
                    "else:",
                    "    bar = param",
                    "yaml.load(bar, Loader=yaml.Loader)",
                ]
            ),
            encoding="utf-8",
        )

        vuln = Vulnerability(
            id="VULN-407",
            vuln_type=VulnerabilityType.INSECURE_DESERIALIZATION,
            severity=Severity.CRITICAL,
            dataflow=DataFlowPath(
                source=TaintSource(
                    CodeLocation(str(target), 1, 1, "param = request.headers.get('payload')"),
                    "HTTP_HEADER",
                    "param",
                    "request.headers.get",
                ),
                sink=TaintSink(
                    CodeLocation(str(target), 7, 1, "yaml.load(bar, Loader=yaml.Loader)"),
                    VulnerabilityType.INSECURE_DESERIALIZATION,
                    "yaml.load",
                    "yaml.load(",
                ),
                intermediate_steps=[
                    CodeLocation(str(target), 4, 1, "bar = 'This_should_always_happen'"),
                ],
            ),
        )

        engine = TriageEngine()
        record = engine.triage_vulnerability(vuln)
        cards = KnowledgeLoader().filter_cards(
            engine.cards,
            language="python",
            finding_type="INSECURE_DESERIALIZATION",
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
        assert skeptic_review.mitigation_signals
        assert final_record.decision.status.value == "suppressed"
        assert judge_review.final_status.value == "suppressed"


def test_nodes_suppress_deserialization_when_list_shift_selects_constant():
    """List mutation should suppress deserialization when the selected element is constant."""
    with TemporaryDirectory() as tmp_dir:
        target = Path(tmp_dir) / "service.py"
        target.write_text(
            "\n".join(
                [
                    "param = request.args.get('payload')",
                    "bar = 'alsosafe'",
                    "if param:",
                    "    lst = []",
                    "    lst.append('safe')",
                    "    lst.append(param)",
                    "    lst.append('moresafe')",
                    "    lst.pop(0)",
                    "    bar = lst[1]",
                    "pickle.loads(base64.urlsafe_b64decode(bar))",
                ]
            ),
            encoding="utf-8",
        )

        vuln = Vulnerability(
            id="VULN-408",
            vuln_type=VulnerabilityType.INSECURE_DESERIALIZATION,
            severity=Severity.CRITICAL,
            dataflow=DataFlowPath(
                source=TaintSource(
                    CodeLocation(str(target), 1, 1, "param = request.args.get('payload')"),
                    "HTTP_PARAM",
                    "param",
                    "request.args.get",
                ),
                sink=TaintSink(
                    CodeLocation(str(target), 10, 1, "pickle.loads(base64.urlsafe_b64decode(bar))"),
                    VulnerabilityType.INSECURE_DESERIALIZATION,
                    "pickle.loads",
                    "pickle.loads(",
                ),
                intermediate_steps=[
                    CodeLocation(str(target), 9, 1, "bar = lst[1]"),
                ],
            ),
        )

        engine = TriageEngine()
        record = engine.triage_vulnerability(vuln)
        cards = KnowledgeLoader().filter_cards(
            engine.cards,
            language="python",
            finding_type="INSECURE_DESERIALIZATION",
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
        assert skeptic_review.mitigation_signals
        assert final_record.decision.status.value == "suppressed"
        assert judge_review.final_status.value == "suppressed"


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
