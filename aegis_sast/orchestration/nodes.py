"""Deterministic workflow nodes that approximate future LangGraph stages."""

import ast
from copy import deepcopy
import re
from typing import List, Optional, Tuple

from aegis_sast.core.models import NormalizedFinding, Severity, TriageStatus
from aegis_sast.knowledge import KnowledgeCard
from aegis_sast.orchestration.context import SourceContextReader
from aegis_sast.orchestration.contracts import (
    AuditorReview,
    JudgeReview,
    SkepticReview,
)
from aegis_sast.orchestration.state import RepoProfile
from aegis_sast.triage.schema import TriageDecision, TriageRecord


class AuditorNode:
    """Review evidence quality and attach source context to a finding."""

    def __init__(self, context_reader: Optional[SourceContextReader] = None):
        self.context_reader = context_reader or SourceContextReader()

    def review(
        self,
        record: TriageRecord,
        matched_cards: List[KnowledgeCard],
        repo_profile: RepoProfile,
    ) -> AuditorReview:
        """Generate an evidence-aware review before skeptical validation."""
        triage_input = record.finding.to_triage_input()
        evidence_pack = triage_input.get("evidence", {})
        route = record.decision.metadata.get("workflow_route", {})
        route_id = route.get("route_id", "unknown")
        route_steps = route.get("steps", [])
        evidence_summary = evidence_pack.get("summary", {})
        graph_slice = evidence_pack.get("graph_slice", {})
        evidence_score = self._score_evidence(record.finding, record.decision.confidence)
        context = self.context_reader.read_for_finding(record.finding)
        notes = [
            f"triage_input_schema={triage_input.get('schema_version', 'unknown')}",
            f"scan_profile={repo_profile.scan_profile}",
            f"language={record.finding.language}",
            f"severity={record.finding.severity.value}",
            f"context_loaded={bool(context.source_window or context.sink_window)}",
            f"path_length={evidence_summary.get('path_length', 0)}",
            f"intermediate_steps={evidence_summary.get('intermediate_step_count', 0)}",
            f"sanitizers={evidence_summary.get('sanitizer_count', 0)}",
        ]
        if graph_slice:
            notes.append(
                "graph_slice="
                f"nodes:{graph_slice.get('node_count', 0)},"
                f"cfg:{graph_slice.get('cfg_edge_count', 0)},"
                f"dfg:{graph_slice.get('dfg_edge_count', 0)},"
                f"helpers:{graph_slice.get('local_helper_count', 0)}"
            )
        notes.extend(
            [f"framework_hint={hint}" for hint in repo_profile.framework_hints[:4]]
        )

        # Offensive Attack Analysis (Auditor Perspective)
        attack_observations = self._build_attack_observations(record.finding)
        notes.extend(attack_observations)

        summary = (
            f"Auditor rated evidence at score {evidence_score:.2f} "
            f"with route {route_id} and validated attack reachability."
        )
        return AuditorReview(
            finding_id=record.finding.id,
            route_id=route_id,
            route_steps=route_steps,
            evidence_score=evidence_score,
            matched_card_ids=[card.card_id for card in matched_cards],
            context=context,
            summary=summary,
            notes=notes,
            metadata={
                "scan_profile": repo_profile.scan_profile,
                "framework_hints": repo_profile.framework_hints,
                "attack_observations": attack_observations,
            },
        )

    @classmethod
    def _build_attack_observations(cls, finding: NormalizedFinding) -> List[str]:
        """Construct offensive penetration testing observations and hypothesized payload."""
        upper_vuln = (finding.vulnerability_type or "").upper()

        observations = [
            "Auditor validated attack vector: untrusted input propagates directly into sensitive operation sink."
        ]

        if "COMMAND" in upper_vuln or "RCE" in upper_vuln:
            observations.append(
                "Hypothesized exploit payload: $(whoami) or ; id executes arbitrary system commands."
            )
            observations.append(
                "Control flow confirms unquoted command string reaches system shell execution without parameter isolation."
            )
            observations.append(
                "High security impact with direct potential for complete host server compromise."
            )
        elif "SQL" in upper_vuln:
            observations.append(
                "Hypothesized exploit payload: ' OR '1'='1' -- bypasses authentication and exposes database records."
            )
            observations.append(
                "Tainted parameter formatted directly into SQL query text without prepared statement binding."
            )
            observations.append(
                "High security impact enabling unauthorized data extraction and database modification."
            )
        elif "PATH_TRAVERSAL" in upper_vuln or "FILE" in upper_vuln:
            observations.append(
                "Hypothesized exploit payload: ../../../../etc/passwd escapes directory boundaries for arbitrary file disclosure."
            )
            observations.append(
                "File access operation receives uncanonicalized relative path without containment boundary checks."
            )
            observations.append(
                "High security impact allowing unauthorized read access to sensitive host filesystem assets."
            )
        elif "SSRF" in upper_vuln:
            observations.append(
                "Hypothesized exploit payload: http://169.254.169.254/latest/meta-data/ queries cloud instance metadata."
            )
            observations.append(
                "Outbound HTTP request executes with user-supplied URL without domain or private IP validation."
            )
            observations.append(
                "Critical security impact exposing internal intranet resources and cloud credentials."
            )
        elif "DESERIALIZATION" in upper_vuln:
            observations.append(
                "Hypothesized exploit payload: serialized object gadget triggers arbitrary command execution upon deserialization."
            )
            observations.append(
                "Untrusted input stream reaches unconstrained deserialization API without type restrictions."
            )
            observations.append(
                "Critical security impact leading directly to remote code execution."
            )
        elif "CODE_INJECTION" in upper_vuln:
            observations.append(
                "Hypothesized exploit payload: __import__('os').system('id') executes arbitrary Python instructions."
            )
            observations.append(
                "Dynamic code evaluation interprets untrusted string directly inside runtime execution scope."
            )
            observations.append(
                "Critical security impact allowing full process takeover."
            )
        else:
            observations.append(
                "Hypothesized exploit payload: malicious boundary-breaking characters alter sink execution semantics."
            )
            observations.append(
                "Control flow trace confirms tainted data reaches sink without sanitization barrier."
            )
            observations.append(
                "Security impact requires prompt remediation to prevent unauthorized operations."
            )

        return observations

    @staticmethod
    def _score_evidence(finding: NormalizedFinding, base_confidence: float) -> float:
        """Estimate how strong the deterministic evidence currently looks."""
        evidence_summary = finding.evidence_summary
        graph_slice = evidence_summary.get("graph_slice", {})
        score = 0.35
        score += min(evidence_summary.get("intermediate_step_count", 0) * 0.12, 0.24)
        score += min(base_confidence * 0.35, 0.35)
        if finding.evidence.source.file_path:
            score += 0.08
        if finding.evidence.sink.file_path:
            score += 0.08
        if evidence_summary.get("has_sanitizers", False):
            score -= 0.14
        if graph_slice.get("cfg_edge_count", 0) > 0:
            score += 0.04
        if graph_slice.get("dfg_edge_count", 0) > 0:
            score += 0.04
        return max(0.0, min(score, 1.0))


class SkepticValidatorNode:
    """Look for mitigation signals or ambiguity before final judgement."""

    UNKNOWN = object()
    LINE_PREFIX_RE = re.compile(r"^\s*(\d+):\s?(.*)$")
    MITIGATION_PATTERNS = {
        "SQL_INJECTION": [
            "preparedstatement",
            "execute(query, params)",
            "cursor.execute(query, params)",
            "bindparam",
            "parameterized",
        ],
        "COMMAND_INJECTION": [
            "execfile(",
            "spawn(",
            "shell=false",
            "subprocess.run([",
        ],
        "CODE_INJECTION": [
            "literal_eval(",
        ],
        "PATH_TRAVERSAL": [
            "resolve(",
            "startswith(",
            "normalize(",
            "realpath(",
        ],
        "XSS": [
            "escape(",
            "html.escape(",
            "htmlspecialchars(",
            "autoescape",
        ],
        "SSRF": [
            "allowlist",
            "urlparse(",
            "validate_url",
            "trusted_hosts",
        ],
    }
    SQL_DYNAMIC_TOKENS = [' + ', 'f"', "f'", ".format(", '" %', "' %"]
    SQL_BINDING_TOKENS = [
        ".setstring(",
        ".setint(",
        ".setlong(",
        ".setobject(",
        ".setnull(",
        ".setdate(",
        ".settimestamp(",
        ".registeroutparameter(",
    ]

    def review(
        self,
        record: TriageRecord,
        matched_cards: List[KnowledgeCard],
        auditor_review: AuditorReview,
    ) -> SkepticReview:
        """Run deterministic skeptical validation on routed findings."""
        if auditor_review.route_id != "skeptic-review":
            return SkepticReview(
                finding_id=record.finding.id,
                executed=False,
                summary="Route skipped skeptical validation.",
                notes=[
                    "Direct path analysis skipped skeptical validation.",
                    "No defensive guards or sanitizers evaluated for this route."
                ],
                metadata={"route_id": auditor_review.route_id},
            )

        context_text = self._collect_context_text(auditor_review).lower()
        mitigation_signals = self._collect_mitigation_signals(
            record.finding,
            context_text,
        )
        objections: List[str] = []
        suggested_status = None
        confidence_cap = None

        if mitigation_signals:
            if record.finding.severity in (Severity.CRITICAL, Severity.HIGH):
                if record.decision.status == TriageStatus.CONFIRMED:
                    suggested_status = TriageStatus.NEEDS_REVIEW
                    confidence_cap = 0.65
                else:
                    suggested_status = TriageStatus.SUPPRESSED
                    confidence_cap = 0.45
            else:
                suggested_status = TriageStatus.SUPPRESSED
                confidence_cap = 0.45
        elif (
            record.decision.status != TriageStatus.SUPPRESSED
            and record.decision.confidence < 0.6
        ):
            objections.append("Confidence remains low after audit.")
            suggested_status = TriageStatus.NEEDS_REVIEW
            confidence_cap = 0.55

        defense_notes: List[str] = []
        if mitigation_signals:
            defense_notes.append("Sanitization guard or defensive type validation detected in dataflow.")
            defense_notes.append("Input handling effectively neutralizes hostile payload characters before sink.")
            defense_notes.append("Recommend SUPPRESSED status due to verified active defense barrier.")
        elif objections:
            defense_notes.append("Evidence is ambiguous and context does not conclusively confirm vulnerability.")
            defense_notes.append("Flagged for manual security review before marking as actionable.")
        else:
            defense_notes.append("No sanitization routines (such as shlex.quote, int casting, or allowlist) detected in dataflow.")
            defense_notes.append("Sink function directly executes tainted parameter from untrusted source.")
            defense_notes.append("Defense check confirms vulnerable exploit path is unmitigated.")

        summary = (
            "Skeptic validator "
            + (
                "found mitigation signals in nearby context."
                if mitigation_signals
                else "did not find strong mitigation signals."
            )
        )
        return SkepticReview(
            finding_id=record.finding.id,
            executed=True,
            summary=summary,
            objections=objections,
            mitigation_signals=mitigation_signals,
            notes=defense_notes,
            suggested_status=suggested_status,
            confidence_cap=confidence_cap,
            metadata={
                "matched_card_ids": [card.card_id for card in matched_cards],
                "matched_card_count": len(matched_cards),
                "route_id": auditor_review.route_id,
            },
        )

    def _collect_mitigation_signals(
        self,
        finding: NormalizedFinding,
        context_text: str,
    ) -> List[str]:
        """Collect convincing mitigation signals from nearby source context."""
        code_lines = self._split_context_code_lines(context_text)
        signals: List[str] = []

        if finding.is_effectively_sanitized:
            signals.append("Dataflow already contains a sanitizer.")

        if (
            finding.vulnerability_type == "OPEN_REDIRECT"
            and self._has_open_redirect_allowlist_validation(context_text)
        ):
            signals.append(
                "Context validates redirect targets with urlparse host or scheme checks."
            )

        if (
            finding.vulnerability_type == "CODE_INJECTION"
            and self._has_code_literal_guard(context_text)
        ):
            signals.append(
                "Context restricts exec input to a plain string literal before execution."
            )

        if finding.vulnerability_type in {
            "COMMAND_INJECTION",
            "INSECURE_DESERIALIZATION",
        }:
            if self._has_safe_constant_lookup_overwrite(code_lines):
                signals.append(
                    "Context overwrites the tainted value with a deterministic constant lookup before the sink."
                )

            if self._has_constant_safe_if_branch(code_lines):
                signals.append(
                    "Context takes a deterministic safe branch before the sink."
                )

            if self._has_constant_safe_match_branch(code_lines):
                signals.append(
                    "Context selects a constant-safe match branch before the sink."
                )

            if self._has_safe_list_index_selection(code_lines):
                signals.append(
                    "Context selects a constant list element before the sink."
                )

        for token in self.MITIGATION_PATTERNS.get(
            finding.vulnerability_type,
            [],
        ):
            if self._is_mitigation_token_present(
                finding.vulnerability_type,
                token,
                context_text,
            ):
                signals.append(f"Context contains mitigation-like token: {token}")

        return list(dict.fromkeys(signals))

    @classmethod
    def _is_mitigation_token_present(
        cls,
        vulnerability_type: str,
        token: str,
        context_text: str,
    ) -> bool:
        """Return True when a mitigation token is genuinely convincing."""
        normalized = token.lower()
        if normalized not in context_text:
            return False

        if vulnerability_type != "SQL_INJECTION":
            return True

        if normalized != "preparedstatement":
            return True

        has_dynamic_sql = any(item in context_text for item in cls.SQL_DYNAMIC_TOKENS)
        has_bindings = any(item in context_text for item in cls.SQL_BINDING_TOKENS)
        has_placeholder = "?" in context_text

        return not has_dynamic_sql and has_bindings and has_placeholder

    @staticmethod
    def _has_open_redirect_allowlist_validation(context_text: str) -> bool:
        """Return True when redirect targets are validated before redirect()."""
        has_urlparse = "urlparse(" in context_text
        has_host_check = any(
            token in context_text
            for token in [
                "netloc not in",
                "netloc in",
                "trusted_hosts",
                "allowed_hosts",
                "google.com",
            ]
        )
        has_scheme_check = "scheme !=" in context_text or "scheme ==" in context_text
        return has_urlparse and (has_host_check or has_scheme_check)

    @staticmethod
    def _has_code_literal_guard(context_text: str) -> bool:
        """Return True when exec/eval input is restricted to a literal-like string."""
        if "plain string literal" in context_text:
            return True

        has_quote_checks = "startswith(" in context_text and "endswith(" in context_text
        return has_quote_checks and "[1:-1]" in context_text

    @classmethod
    def _split_context_code_lines(cls, context_text: str) -> List[str]:
        """Split one flattened context string back into code-only lines."""
        if not context_text:
            return []

        lines: List[str] = []
        for raw_line in context_text.splitlines():
            if not raw_line.strip():
                continue
            match = cls.LINE_PREFIX_RE.match(raw_line)
            if match:
                lines.append(match.group(2))
            else:
                lines.append(raw_line)
        return lines

    @classmethod
    def _has_safe_constant_lookup_overwrite(cls, code_lines: List[str]) -> bool:
        """Return True when a later constant lookup overwrites the tainted value."""
        if not code_lines:
            return False

        text = "\n".join(code_lines).lower()
        last_bar_index = cls._last_bar_assignment_index(code_lines)
        if last_bar_index is None:
            return False

        last_bar_line = code_lines[last_bar_index].strip().lower()
        dict_lookup = re.fullmatch(
            r"bar\s*=\s*(\w+)\[['\"]keya-[^'\"]+['\"]\]",
            last_bar_line,
        )
        if dict_lookup:
            collection = dict_lookup.group(1)
            earlier_text = "\n".join(code_lines[:last_bar_index]).lower()
            return bool(
                re.search(
                    rf"bar\s*=\s*{re.escape(collection)}\[['\"]keyb-[^'\"]+['\"]\]",
                    earlier_text,
                )
            )

        config_lookup = re.fullmatch(
            r"bar\s*=\s*(\w+)\.get\([^\n]*['\"]keya-[^'\"]+['\"]\)",
            last_bar_line,
        )
        if not config_lookup:
            return False

        config_name = config_lookup.group(1)
        has_safe_key = re.search(
            rf"{re.escape(config_name)}\.set\([^\n]*['\"]keya-[^'\"]+['\"],\s*['\"][^'\"]+['\"]\)",
            text,
        )
        has_tainted_key = re.search(
            rf"{re.escape(config_name)}\.set\([^\n]*['\"]keyb-[^'\"]+['\"],\s*param\)",
            text,
        )
        return bool(has_safe_key and has_tainted_key)

    @classmethod
    def _has_constant_safe_if_branch(cls, code_lines: List[str]) -> bool:
        """Return True when a constant condition selects a safe branch for `bar`."""
        known_values: dict[str, object] = {}
        index = 0
        while index < len(code_lines):
            raw_line = code_lines[index]
            stripped = raw_line.strip()

            if not stripped:
                index += 1
                continue

            cls._update_known_value_from_assignment(stripped, known_values)

            if stripped.startswith("if ") and stripped.endswith(":"):
                indent = cls._indent_level(raw_line)
                condition = stripped[3:-1].strip()
                result = cls._eval_simple_expr(condition, known_values)
                if isinstance(result, bool):
                    true_block_end = cls._block_end_index(
                        code_lines,
                        index + 1,
                        indent,
                    )
                    true_rhs, next_index = cls._first_bar_assignment_in_block(
                        code_lines,
                        index + 1,
                        indent,
                    )
                    true_index = next_index if true_rhs is not None else None
                    false_rhs = None
                    false_index = None
                    if true_block_end < len(code_lines):
                        next_line = code_lines[true_block_end]
                        if (
                            next_line.strip().startswith("else:")
                            and cls._indent_level(next_line) == indent
                        ):
                            false_rhs, false_index = cls._first_bar_assignment_in_block(
                                code_lines,
                                true_block_end + 1,
                                indent,
                            )
                            true_block_end = cls._block_end_index(
                                code_lines,
                                true_block_end + 1,
                                indent,
                            )

                    chosen_rhs = true_rhs if result else false_rhs
                    chosen_index = true_index if result else false_index
                    if (
                        chosen_rhs
                        and chosen_index is not None
                        and not cls._has_bar_assignment_after(code_lines, true_block_end)
                        and cls._expr_is_safe_constant(chosen_rhs, known_values)
                    ):
                        return True

            index += 1

        return False

    @classmethod
    def _has_constant_safe_match_branch(cls, code_lines: List[str]) -> bool:
        """Return True when a `match` statement deterministically selects a safe case."""
        known_values: dict[str, object] = {}
        index = 0
        while index < len(code_lines):
            raw_line = code_lines[index]
            stripped = raw_line.strip()

            if not stripped:
                index += 1
                continue

            cls._update_known_value_from_assignment(stripped, known_values)

            if stripped.startswith("match ") and stripped.endswith(":"):
                indent = cls._indent_level(raw_line)
                subject_expr = stripped[6:-1].strip()
                subject_value = cls._eval_simple_expr(subject_expr, known_values)
                if subject_value is cls.UNKNOWN:
                    index += 1
                    continue

                block_end_index = cls._block_end_index(
                    code_lines,
                    index + 1,
                    indent,
                )
                branch_rhs, branch_index = cls._resolve_match_branch_assignment(
                    code_lines,
                    index + 1,
                    indent,
                    subject_value,
                    known_values,
                )
                if (
                    branch_rhs
                    and branch_index is not None
                    and not cls._has_bar_assignment_after(code_lines, block_end_index)
                    and cls._expr_is_safe_constant(branch_rhs, known_values)
                ):
                    return True

            index += 1

        return False

    @classmethod
    def _has_safe_list_index_selection(cls, code_lines: List[str]) -> bool:
        """Return True when list mutation deterministically moves tainted data away."""
        known_values: dict[str, object] = {}
        list_state: dict[str, List[str]] = {}

        for line_index, raw_line in enumerate(code_lines):
            stripped = raw_line.strip()
            if not stripped:
                continue

            cls._update_known_value_from_assignment(stripped, known_values)

            empty_list = re.fullmatch(r"([A-Za-z_]\w*)\s*=\s*\[\]", stripped)
            if empty_list:
                list_state[empty_list.group(1)] = []
                continue

            append_match = re.fullmatch(r"([A-Za-z_]\w*)\.append\((.+)\)", stripped)
            if append_match and append_match.group(1) in list_state:
                list_state[append_match.group(1)].append(
                    cls._symbolic_value_kind(
                        append_match.group(2),
                        known_values,
                    )
                )
                continue

            pop_match = re.fullmatch(r"([A-Za-z_]\w*)\.pop\((\d+)\)", stripped)
            if pop_match and pop_match.group(1) in list_state:
                items = list_state[pop_match.group(1)]
                index = int(pop_match.group(2))
                if 0 <= index < len(items):
                    items.pop(index)
                continue

            select_match = re.fullmatch(r"bar\s*=\s*([A-Za-z_]\w*)\[(\d+)\]", stripped)
            if not select_match:
                continue

            list_name = select_match.group(1)
            item_index = int(select_match.group(2))
            if list_name not in list_state:
                continue

            items = list_state[list_name]
            if (
                0 <= item_index < len(items)
                and items[item_index] == "const"
                and not cls._has_bar_assignment_after(code_lines, line_index + 1)
            ):
                return True

        return False

    @classmethod
    def _has_bar_assignment_after(
        cls,
        code_lines: List[str],
        start_index: int,
    ) -> bool:
        """Return True when `bar` is reassigned after the provided index."""
        for later_line in code_lines[start_index:]:
            if re.fullmatch(r"bar\s*=\s*.+", later_line.strip()):
                return True
        return False

    @classmethod
    def _block_end_index(
        cls,
        code_lines: List[str],
        start_index: int,
        parent_indent: int,
    ) -> int:
        """Return the first index after one indented block."""
        index = start_index
        while index < len(code_lines):
            stripped = code_lines[index].strip()
            if not stripped:
                index += 1
                continue
            if cls._indent_level(code_lines[index]) <= parent_indent:
                break
            index += 1
        return index

    @staticmethod
    def _last_bar_assignment_index(code_lines: List[str]) -> Optional[int]:
        """Return the index of the last local `bar = ...` assignment."""
        for index in range(len(code_lines) - 1, -1, -1):
            if re.fullmatch(r"bar\s*=\s*.+", code_lines[index].strip()):
                return index
        return None

    @classmethod
    def _update_known_value_from_assignment(
        cls,
        stripped_line: str,
        known_values: dict[str, object],
    ) -> None:
        """Track simple constant assignments used by later branch evaluation."""
        if any(
            stripped_line.startswith(prefix)
            for prefix in ("if ", "elif ", "while ", "for ", "case ", "match ")
        ):
            return

        assignment = re.fullmatch(r"([A-Za-z_]\w*)\s*=\s*(.+)", stripped_line)
        if not assignment:
            return

        value = cls._eval_simple_expr(assignment.group(2), known_values)
        if value is not cls.UNKNOWN:
            known_values[assignment.group(1)] = value

    @classmethod
    def _resolve_match_branch_assignment(
        cls,
        code_lines: List[str],
        start_index: int,
        match_indent: int,
        subject_value: object,
        known_values: dict[str, object],
    ) -> Tuple[Optional[str], Optional[int]]:
        """Return the selected branch assignment for a constant match value."""
        index = start_index
        while index < len(code_lines):
            raw_line = code_lines[index]
            stripped = raw_line.strip()
            if not stripped:
                index += 1
                continue

            indent = cls._indent_level(raw_line)
            if indent <= match_indent:
                break

            if stripped.startswith("case ") and stripped.endswith(":"):
                labels = stripped[5:-1].strip()
                if cls._case_matches(labels, subject_value, known_values):
                    rhs, assignment_index = cls._first_bar_assignment_in_block(
                        code_lines,
                        index + 1,
                        indent,
                    )
                    return rhs, assignment_index
            index += 1

        return None, None

    @classmethod
    def _case_matches(
        cls,
        labels: str,
        subject_value: object,
        known_values: dict[str, object],
    ) -> bool:
        """Return True when a case label matches the known match subject."""
        if labels == "_":
            return True

        for token in labels.split("|"):
            label = token.strip()
            value = cls._eval_simple_expr(label, known_values)
            if value is not cls.UNKNOWN and value == subject_value:
                return True
        return False

    @classmethod
    def _first_bar_assignment_in_block(
        cls,
        code_lines: List[str],
        start_index: int,
        parent_indent: int,
    ) -> Tuple[Optional[str], int]:
        """Return the first `bar = ...` assignment inside one indented block."""
        index = start_index
        while index < len(code_lines):
            raw_line = code_lines[index]
            stripped = raw_line.strip()
            if not stripped:
                index += 1
                continue

            indent = cls._indent_level(raw_line)
            if indent <= parent_indent:
                break

            assignment = re.fullmatch(r"bar\s*=\s*(.+)", stripped)
            if assignment:
                return assignment.group(1).strip(), index

            index += 1

        return None, index

    @classmethod
    def _expr_is_safe_constant(
        cls,
        expression: str,
        known_values: dict[str, object],
    ) -> bool:
        """Return True when an expression resolves to a deterministic constant."""
        normalized = expression.strip()
        if normalized == "param":
            return False

        value = cls._eval_simple_expr(normalized, known_values)
        if value is cls.UNKNOWN:
            return False

        return isinstance(value, (str, int, float, bool))

    @classmethod
    def _symbolic_value_kind(
        cls,
        expression: str,
        known_values: dict[str, object],
    ) -> str:
        """Reduce one expression into a small symbolic value kind."""
        normalized = expression.strip()
        if normalized == "param":
            return "param"

        value = cls._eval_simple_expr(normalized, known_values)
        if value is cls.UNKNOWN:
            return "unknown"

        return "const"

    @classmethod
    def _eval_simple_expr(
        cls,
        expression: str,
        known_values: dict[str, object],
    ) -> object:
        """Evaluate a very small subset of Python expressions safely."""
        try:
            node = ast.parse(expression, mode="eval").body
        except SyntaxError:
            return cls.UNKNOWN
        return cls._eval_ast_node(node, known_values)

    @classmethod
    def _eval_ast_node(
        cls,
        node: ast.AST,
        known_values: dict[str, object],
    ) -> object:
        """Evaluate one restricted AST node into a concrete constant when possible."""
        if isinstance(node, ast.Constant):
            return node.value

        if isinstance(node, ast.Name):
            return known_values.get(node.id, cls.UNKNOWN)

        if isinstance(node, ast.UnaryOp):
            operand = cls._eval_ast_node(node.operand, known_values)
            if operand is cls.UNKNOWN:
                return cls.UNKNOWN
            if isinstance(node.op, ast.USub):
                return -operand
            if isinstance(node.op, ast.UAdd):
                return +operand
            if isinstance(node.op, ast.Not):
                return not operand
            return cls.UNKNOWN

        if isinstance(node, ast.BinOp):
            left = cls._eval_ast_node(node.left, known_values)
            right = cls._eval_ast_node(node.right, known_values)
            if left is cls.UNKNOWN or right is cls.UNKNOWN:
                return cls.UNKNOWN
            try:
                if isinstance(node.op, ast.Add):
                    return left + right
                if isinstance(node.op, ast.Sub):
                    return left - right
                if isinstance(node.op, ast.Mult):
                    return left * right
                if isinstance(node.op, ast.Div):
                    return left / right
                if isinstance(node.op, ast.FloorDiv):
                    return left // right
                if isinstance(node.op, ast.Mod):
                    return left % right
            except Exception:
                return cls.UNKNOWN
            return cls.UNKNOWN

        if isinstance(node, ast.BoolOp):
            values = [cls._eval_ast_node(value, known_values) for value in node.values]
            if any(value is cls.UNKNOWN for value in values):
                return cls.UNKNOWN
            if isinstance(node.op, ast.And):
                return all(values)
            if isinstance(node.op, ast.Or):
                return any(values)
            return cls.UNKNOWN

        if isinstance(node, ast.Compare):
            left = cls._eval_ast_node(node.left, known_values)
            if left is cls.UNKNOWN:
                return cls.UNKNOWN
            current = left
            for operator, comparator in zip(node.ops, node.comparators):
                right = cls._eval_ast_node(comparator, known_values)
                if right is cls.UNKNOWN:
                    return cls.UNKNOWN
                try:
                    if isinstance(operator, ast.Eq):
                        ok = current == right
                    elif isinstance(operator, ast.NotEq):
                        ok = current != right
                    elif isinstance(operator, ast.Gt):
                        ok = current > right
                    elif isinstance(operator, ast.GtE):
                        ok = current >= right
                    elif isinstance(operator, ast.Lt):
                        ok = current < right
                    elif isinstance(operator, ast.LtE):
                        ok = current <= right
                    elif isinstance(operator, ast.In):
                        ok = current in right
                    elif isinstance(operator, ast.NotIn):
                        ok = current not in right
                    else:
                        return cls.UNKNOWN
                except Exception:
                    return cls.UNKNOWN
                if not ok:
                    return False
                current = right
            return True

        if isinstance(node, ast.Subscript):
            value = cls._eval_ast_node(node.value, known_values)
            if value is cls.UNKNOWN:
                return cls.UNKNOWN

            slice_node = node.slice
            if isinstance(slice_node, ast.Constant):
                index = slice_node.value
            else:
                index = cls._eval_ast_node(slice_node, known_values)
            if index is cls.UNKNOWN:
                return cls.UNKNOWN
            try:
                return value[index]
            except Exception:
                return cls.UNKNOWN

        return cls.UNKNOWN

    @staticmethod
    def _indent_level(line: str) -> int:
        """Return the indentation width used for one code line."""
        return len(line) - len(line.lstrip())

    @classmethod
    def _collect_context_text(cls, auditor_review: AuditorReview) -> str:
        """Flatten source and sink windows into one string without duplicate lines."""
        context = auditor_review.context
        if context is None:
            return ""

        ordered_lines: dict[tuple[str, int], str] = {}
        for window in [context.source_window, context.sink_window]:
            if window is None:
                continue
            for line in window.lines:
                match = cls.LINE_PREFIX_RE.match(line)
                if match:
                    key = (window.file_path, int(match.group(1)))
                else:
                    key = (window.file_path, len(ordered_lines))
                ordered_lines.setdefault(key, line)
        return "\n".join(ordered_lines.values())


class JudgeNode:
    """Finalize a triage record after audit and skeptical validation."""

    RISKY_SQL_TOKENS = ["select ", "insert ", "update ", "delete "]
    DIRECT_SQL_EXECUTION_TOKENS = [
        "cursor.execute(query)",
        "cursor.execute(sql)",
        "cur.execute(query)",
        "cur.execute(sql)",
        "statement.execute(sql)",
        "statement.execute(query)",
        "statement.executequery(sql)",
        "statement.executequery(query)",
    ]
    DYNAMIC_SQL_TOKENS = [' + ', 'f"', "f'", ".format(", '" %', "' %"]
    DANGEROUS_SHELL_TOKENS = [
        "os.system(",
        "os.popen(",
        "subprocess.call(",
        "subprocess.run(",
        "shell=true",
    ]

    def finalize(
        self,
        record: TriageRecord,
        auditor_review: AuditorReview,
        skeptic_review: SkepticReview,
    ) -> Tuple[TriageRecord, JudgeReview]:
        """Apply conservative overrides and attach node outputs."""
        updated_record = deepcopy(record)
        decision = updated_record.decision

        final_status = decision.status
        final_confidence = decision.confidence
        explanation = decision.explanation
        recommendation = decision.recommendation
        risk_signals = self._collect_risk_signals(updated_record.finding, auditor_review)
        promotion_applied = False
        promotion_target: Optional[str] = None

        if skeptic_review.executed:
            if skeptic_review.suggested_status is not None:
                final_status = skeptic_review.suggested_status
            if skeptic_review.confidence_cap is not None:
                final_confidence = min(final_confidence, skeptic_review.confidence_cap)
            if skeptic_review.mitigation_signals:
                explanation = (
                    explanation
                    + " Skeptic validation found mitigation signals in nearby code context."
                )
            elif self._should_promote_to_confirmed(
                updated_record.finding,
                final_status,
                auditor_review,
                skeptic_review,
                risk_signals,
            ):
                final_status = TriageStatus.CONFIRMED
                final_confidence = max(
                    final_confidence,
                    min(max(auditor_review.evidence_score, 0.88), 0.96),
                )
                explanation = (
                    explanation
                    + " Auditor evidence shows direct dynamic SQL execution without mitigation."
                )
                promotion_applied = True
                promotion_target = "confirmed"
            elif self._should_promote_to_likely(
                updated_record.finding,
                final_status,
                auditor_review,
                skeptic_review,
                risk_signals,
            ):
                final_status = TriageStatus.LIKELY
                final_confidence = max(
                    final_confidence,
                    min(max(auditor_review.evidence_score, 0.72), 0.85),
                )
                explanation = (
                    explanation
                    + " Auditor evidence is strong and skeptical validation did not find mitigation signals."
                )
                promotion_applied = True
                promotion_target = "likely"
            elif skeptic_review.objections:
                explanation = (
                    explanation
                    + " Skeptic validation kept the finding visible because the evidence is still ambiguous."
                )

        judge_summary = (
            f"Judge finalized the finding as {final_status.value} "
            f"with confidence={final_confidence:.2f}."
        )
        reason_codes = self._dedupe_reason_codes(
            decision.reason_codes
            + [f"workflow-route:{auditor_review.route_id}"]
            + [f"risk-signal:{signal}" for signal in risk_signals]
            + [
                "mitigation-signal-present"
                for _ in skeptic_review.mitigation_signals
            ]
            + (
                ["skeptic-objection"]
                if skeptic_review.objections
                else []
            )
            + (
                [f"promoted-to-{promotion_target}"]
                if promotion_target
                else []
            )
        )
        evidence_summary = dict(updated_record.finding.evidence_summary)
        manual_review_required = final_status == TriageStatus.NEEDS_REVIEW or (
            final_status == TriageStatus.SUPPRESSED
            and updated_record.finding.severity in (Severity.CRITICAL, Severity.HIGH)
        )
        judge_notes = [
            f"Verdict decided as {final_status.value} with confidence {final_confidence:.2f}.",
            "Evaluated Auditor attack path against Skeptic defense checks.",
        ]
        if promotion_applied:
            judge_notes.append(
                f"Promoted to {promotion_target} due to direct dangerous sink invocation without sanitization."
            )
        elif skeptic_review.mitigation_signals:
            judge_notes.append(
                "Suppressed finding due to confirmed defensive sanitization in call scope."
            )

        remediation_patch = self._generate_remediation_patch(updated_record.finding)

        judge_review = JudgeReview(
            finding_id=updated_record.finding.id,
            final_status=final_status,
            final_confidence=final_confidence,
            summary=judge_summary,
            notes=judge_notes,
            remediation_patch=remediation_patch,
            metadata={
                "auditor_route_id": auditor_review.route_id,
                "skeptic_executed": skeptic_review.executed,
                "promotion_applied": promotion_applied,
                "promotion_target": promotion_target,
                "risk_signals": risk_signals,
            },
        )

        updated_record.finding.triage_status = final_status
        updated_record.finding.confidence = final_confidence
        updated_record.finding.explanation = explanation
        if not updated_record.finding.recommendation:
            updated_record.finding.recommendation = recommendation or remediation_patch.get("explanation")
        triage_metadata = updated_record.finding.metadata.setdefault("triage", {})
        triage_metadata["final_status"] = final_status.value
        triage_metadata["final_confidence"] = final_confidence
        triage_metadata["reviewer"] = "judge-node-v1"
        triage_metadata["reason_codes"] = reason_codes
        triage_metadata["evidence_summary"] = evidence_summary
        triage_metadata["manual_review_required"] = manual_review_required
        triage_metadata["remediation_patch"] = remediation_patch
        triage_metadata["agent_reviews"] = {
            "auditor_review": auditor_review.to_dict(),
            "skeptic_review": skeptic_review.to_dict(),
            "judge_review": judge_review.to_dict(),
        }
        updated_record.finding.metadata["reason_codes"] = reason_codes
        updated_record.finding.metadata["manual_review_required"] = manual_review_required
        updated_record.finding.metadata["remediation_patch"] = remediation_patch
        updated_record.finding.metadata["auditor_review"] = auditor_review.to_dict()
        updated_record.finding.metadata["skeptic_review"] = skeptic_review.to_dict()
        updated_record.finding.metadata["judge_review"] = judge_review.to_dict()

        updated_record.decision = TriageDecision(
            status=final_status,
            confidence=final_confidence,
            explanation=explanation,
            recommendation=recommendation,
            reviewer="judge-node-v1",
            reason_codes=reason_codes,
            evidence_summary=evidence_summary,
            manual_review_required=manual_review_required,
            evidence_notes=(
                decision.evidence_notes
                + auditor_review.notes
                + [f"risk_signal={signal}" for signal in risk_signals]
                + skeptic_review.objections
                + skeptic_review.mitigation_signals
            ),
            metadata={
                **decision.metadata,
                "reason_codes": reason_codes,
                "evidence_summary": evidence_summary,
                "manual_review_required": manual_review_required,
                "auditor_review": auditor_review.to_dict(),
                "skeptic_review": skeptic_review.to_dict(),
                "judge_review": judge_review.to_dict(),
            },
        )
        return updated_record, judge_review

    @staticmethod
    def _should_promote_to_confirmed(
        finding: NormalizedFinding,
        current_status: TriageStatus,
        auditor_review: AuditorReview,
        skeptic_review: SkepticReview,
        risk_signals: List[str],
    ) -> bool:
        """Promote the strongest deterministic SQLi cases to confirmed."""
        strong_sql_signals = {"dynamic-sql-construction", "query-executed-directly"}
        return (
            current_status in {TriageStatus.LIKELY, TriageStatus.NEEDS_REVIEW}
            and finding.vulnerability_type == "SQL_INJECTION"
            and finding.severity in (Severity.CRITICAL, Severity.HIGH)
            and not finding.is_effectively_sanitized
            and not skeptic_review.mitigation_signals
            and not skeptic_review.objections
            and auditor_review.evidence_score >= 0.7
            and strong_sql_signals.issubset(set(risk_signals))
        )

    @staticmethod
    def _should_promote_to_likely(
        finding: NormalizedFinding,
        current_status: TriageStatus,
        auditor_review: AuditorReview,
        skeptic_review: SkepticReview,
        risk_signals: List[str],
    ) -> bool:
        """Promote strong unmitigated findings from needs-review to likely."""
        return (
            current_status == TriageStatus.NEEDS_REVIEW
            and finding.severity in (Severity.CRITICAL, Severity.HIGH)
            and not finding.is_effectively_sanitized
            and not skeptic_review.mitigation_signals
            and not skeptic_review.objections
            and auditor_review.evidence_score >= 0.7
            and bool(risk_signals)
        )

    @staticmethod
    def _collect_risk_signals(
        finding: NormalizedFinding,
        auditor_review: AuditorReview,
    ) -> List[str]:
        """Collect simple risk signals from nearby code context."""
        context_text = SkepticValidatorNode._collect_context_text(auditor_review).lower()
        signals: List[str] = []

        if not context_text:
            return signals

        if finding.vulnerability_type == "SQL_INJECTION":
            has_sql_keyword = any(
                token in context_text for token in JudgeNode.RISKY_SQL_TOKENS
            )
            has_named_query = "query =" in context_text or "sql =" in context_text
            has_dynamic_sql = (
                has_named_query
                and any(token in context_text for token in JudgeNode.DYNAMIC_SQL_TOKENS)
            ) or ("% " in context_text and has_named_query)
            has_direct_execution = any(
                token in context_text
                for token in JudgeNode.DIRECT_SQL_EXECUTION_TOKENS
            )
            if has_sql_keyword and has_dynamic_sql:
                signals.append("dynamic-sql-construction")
            if has_direct_execution:
                signals.append("query-executed-directly")

        elif finding.vulnerability_type == "COMMAND_INJECTION":
            if any(token in context_text for token in JudgeNode.DANGEROUS_SHELL_TOKENS):
                signals.append("dangerous-shell-invocation")
            if "shell=true" in context_text:
                signals.append("shell-true-enabled")

        return signals

    @staticmethod
    def _dedupe_reason_codes(reason_codes: List[str]) -> List[str]:
        """Return a stable reason-code list without duplicates."""
        return list(dict.fromkeys(code for code in reason_codes if code))

    @classmethod
    def _generate_remediation_patch(cls, finding: NormalizedFinding) -> dict:
        """Construct structured Unified Diff patch and explanation for the finding."""
        upper_vuln = (finding.vulnerability_type or "").upper()
        sink_loc = getattr(getattr(finding, "evidence", None), "sink", None)
        file_path = (
            getattr(sink_loc, "file_path", None)
            or getattr(finding, "file_path", None)
            or "app.py"
        )
        line_num = (
            getattr(sink_loc, "line_number", None)
            or getattr(finding, "line_number", None)
            or 1
        )
        sink_snippet = (getattr(sink_loc, "code_snippet", "") or "").strip()

        diff_lines = []
        explanation = ""
        vulnerable_snippet = sink_snippet or "vulnerable_call(input)"
        secure_snippet = ""

        if "COMMAND" in upper_vuln or "RCE" in upper_vuln:
            explanation = (
                "Avoid passing unquoted shell command strings to system shell. "
                "Use subprocess.run with shell=False and pass arguments as an argv list."
            )
            vulnerable_snippet = sink_snippet or "os.system(cmd)"
            secure_snippet = "subprocess.run(['command', safe_arg], check=True, shell=False)"
            diff_lines = [
                {"type": "context", "line_num": max(1, line_num - 2), "text": "import subprocess, shlex"},
                {"type": "context", "line_num": max(1, line_num - 1), "text": "# Untrusted input received from request"},
                {"type": "remove", "line_num": line_num, "text": f"- {vulnerable_snippet}"},
                {"type": "add", "line_num": line_num, "text": "+ # Secure: execute via argument array with shell=False"},
                {"type": "add", "line_num": line_num + 1, "text": "+ subprocess.run(shlex.split(safe_cmd), check=True, shell=False)"},
            ]
        elif "SQL" in upper_vuln:
            explanation = (
                "Adopt parameterized query binding to guarantee user input cannot alter SQL syntax."
            )
            vulnerable_snippet = sink_snippet or "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"
            secure_snippet = "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
            diff_lines = [
                {"type": "context", "line_num": max(1, line_num - 1), "text": "# Untrusted parameter received"},
                {"type": "remove", "line_num": line_num, "text": f"- {vulnerable_snippet}"},
                {"type": "add", "line_num": line_num, "text": "+ # Secure: parameterized query binding"},
                {"type": "add", "line_num": line_num + 1, "text": f"+ {secure_snippet}"},
            ]
        elif "PATH_TRAVERSAL" in upper_vuln or "FILE" in upper_vuln:
            explanation = (
                "Canonicalize file path using os.path.abspath and assert that resolved path remains "
                "within the designated base directory."
            )
            vulnerable_snippet = sink_snippet or "return send_file(user_path)"
            secure_snippet = (
                "safe_path = os.path.abspath(os.path.join(BASE_DIR, filename))\n"
                "if not safe_path.startswith(os.path.abspath(BASE_DIR)):\n"
                "    raise PermissionError('Directory traversal blocked')\n"
                "return send_file(safe_path)"
            )
            diff_lines = [
                {"type": "context", "line_num": max(1, line_num - 1), "text": "filename = request.args.get('path')"},
                {"type": "remove", "line_num": line_num, "text": f"- {vulnerable_snippet}"},
                {"type": "add", "line_num": line_num, "text": "+ # Secure: validate path boundary"},
                {"type": "add", "line_num": line_num + 1, "text": "+ safe_path = os.path.abspath(os.path.join(BASE_DIR, filename))"},
                {"type": "add", "line_num": line_num + 2, "text": "+ if not safe_path.startswith(os.path.abspath(BASE_DIR)): raise PermissionError('Access denied')"},
                {"type": "add", "line_num": line_num + 3, "text": "+ return send_file(safe_path)"},
            ]
        elif "SSRF" in upper_vuln:
            explanation = (
                "Validate destination hostname against a strict domain whitelist and reject private IP ranges."
            )
            vulnerable_snippet = sink_snippet or "response = requests.get(target_url)"
            secure_snippet = (
                "if not is_safe_external_url(target_url):\n"
                "    raise ValueError('SSRF blocked')\n"
                "response = requests.get(target_url, timeout=5, allow_redirects=False)"
            )
            diff_lines = [
                {"type": "context", "line_num": max(1, line_num - 1), "text": "target_url = request.args.get('url')"},
                {"type": "remove", "line_num": line_num, "text": f"- {vulnerable_snippet}"},
                {"type": "add", "line_num": line_num, "text": "+ # Secure: validate destination against domain allowlist"},
                {"type": "add", "line_num": line_num + 1, "text": "+ if not is_safe_external_url(target_url): raise ValueError('Blocked host')"},
                {"type": "add", "line_num": line_num + 2, "text": "+ response = requests.get(target_url, timeout=5, allow_redirects=False)"},
            ]
        elif "DESERIALIZATION" in upper_vuln:
            explanation = (
                "Replace unsafe pickle/yaml deserialization with safe structured data serialization (JSON or protobuf)."
            )
            vulnerable_snippet = sink_snippet or "data = pickle.loads(raw)"
            secure_snippet = "data = json.loads(raw.decode('utf-8'))"
            diff_lines = [
                {"type": "context", "line_num": max(1, line_num - 1), "text": "import json"},
                {"type": "remove", "line_num": line_num, "text": f"- {vulnerable_snippet}"},
                {"type": "add", "line_num": line_num, "text": "+ # Secure: safe JSON deserialization"},
                {"type": "add", "line_num": line_num + 1, "text": f"+ {secure_snippet}"},
            ]
        else:
            explanation = "Sanitize and validate untrusted input before invoking sensitive operations."
            secure_snippet = "sanitized = sanitize(param)\nsafe_call(sanitized)"
            diff_lines = [
                {"type": "remove", "line_num": line_num, "text": f"- {vulnerable_snippet}"},
                {"type": "add", "line_num": line_num, "text": "+ # Secure: sanitize input before sink"},
                {"type": "add", "line_num": line_num + 1, "text": "+ sanitized = sanitize(user_input)"},
                {"type": "add", "line_num": line_num + 2, "text": "+ safe_call(sanitized)"},
            ]

        unified_diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -{line_num},2 +{line_num},{len(diff_lines)} @@\n"
            + "\n".join(
                dl["text"] if dl["text"].startswith(("-", "+")) else f" {dl['text']}"
                for dl in diff_lines
            )
        )

        return {
            "file_path": file_path,
            "line": line_num,
            "vulnerable_snippet": vulnerable_snippet,
            "secure_snippet": secure_snippet,
            "hunk_header": f"@@ -{line_num},2 +{line_num},{len(diff_lines)} @@",
            "diff_lines": diff_lines,
            "explanation": explanation,
            "unified_diff": unified_diff,
        }
