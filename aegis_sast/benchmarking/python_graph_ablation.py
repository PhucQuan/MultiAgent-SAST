"""Synthetic benchmark runner for Python CFG/DFG graph ablation studies.

This module compares three progressively stronger modes:

- ``linear_taint_baseline``: lightweight linear taint propagation with no
  kill-set, no CFG semantics, and no function summaries.
- ``graph_core_no_summary``: explicit CFG/DFG graph reasoning without local
  helper summaries.
- ``graph_core_with_summary``: explicit CFG/DFG graph reasoning with local
  function summaries enabled.
"""

from __future__ import annotations

import ast
import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from aegis_sast.analysis.python_flow_graph import (
    PythonDataflowAnalyzer,
    PythonFlowGraph,
    PythonFlowGraphBuilder,
)
from aegis_sast.core.models import CodeLocation, TaintSink, TaintSource, VulnerabilityType


DEFAULT_MODES: Tuple[str, ...] = (
    "linear_taint_baseline",
    "graph_core_no_summary",
    "graph_core_with_summary",
)


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return node.__class__.__name__


def _word_tokens(text: str) -> List[str]:
    return re.findall(r"\b\w+\b", text)


def _mentions_taint(token: str, tainted_vars: Set[str]) -> bool:
    return any(name in _word_tokens(token) for name in tainted_vars)


class _NameCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.names: List[str] = []

    def visit_Name(self, node: ast.Name) -> None:  # noqa: N802 - ast visitor API
        self.names.append(node.id)


def _extract_read_names(node: Optional[ast.AST]) -> List[str]:
    if node is None:
        return []
    collector = _NameCollector()
    collector.visit(node)
    return collector.names


def _extract_write_names(node: ast.AST) -> List[str]:
    names: List[str] = []
    if isinstance(node, ast.Name):
        names.append(node.id)
    elif isinstance(node, (ast.Tuple, ast.List)):
        for child in node.elts:
            names.extend(_extract_write_names(child))
    elif isinstance(node, ast.Attribute):
        names.append(_safe_unparse(node))
    return names


def _extract_call_info(call: ast.Call) -> Tuple[str, List[str]]:
    callee = _safe_unparse(call.func)
    arguments = [_safe_unparse(arg) for arg in call.args]
    arguments.extend(
        [
            f"{keyword.arg}={_safe_unparse(keyword.value)}"
            if keyword.arg
            else _safe_unparse(keyword.value)
            for keyword in call.keywords
        ]
    )
    return callee, arguments


def _line_snippet(file_path: Path, line_number: int) -> str:
    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    if 0 < line_number <= len(lines):
        return lines[line_number - 1].strip()
    return ""


@dataclass
class BenchmarkSourceSpec:
    line: int
    variable_name: str
    pattern: str
    source_type: str = "HTTP_PARAM"


@dataclass
class BenchmarkSinkSpec:
    line: int
    function_name: str
    pattern: str
    vulnerability_type: str
    arguments: List[str] = field(default_factory=list)


@dataclass
class BenchmarkCase:
    case_id: str
    title: str
    description: str
    file_path: Path
    expected_vulnerable: bool
    source: BenchmarkSourceSpec
    sink: BenchmarkSinkSpec
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "description": self.description,
            "file_path": str(self.file_path),
            "expected_vulnerable": self.expected_vulnerable,
            "source": {
                "line": self.source.line,
                "variable_name": self.source.variable_name,
                "pattern": self.source.pattern,
                "source_type": self.source.source_type,
            },
            "sink": {
                "line": self.sink.line,
                "function_name": self.sink.function_name,
                "pattern": self.sink.pattern,
                "vulnerability_type": self.sink.vulnerability_type,
                "arguments": list(self.sink.arguments),
            },
            "tags": list(self.tags),
        }


@dataclass
class CasePrediction:
    case_id: str
    mode: str
    expected_vulnerable: bool
    predicted_vulnerable: bool
    outcome: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "mode": self.mode,
            "expected_vulnerable": self.expected_vulnerable,
            "predicted_vulnerable": self.predicted_vulnerable,
            "outcome": self.outcome,
            "metadata": self.metadata,
        }


@dataclass
class ModeMetrics:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    accuracy: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "accuracy": self.accuracy,
        }


@dataclass
class ModeResult:
    mode: str
    metrics: ModeMetrics
    predictions: List[CasePrediction]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "metrics": self.metrics.to_dict(),
            "predictions": [prediction.to_dict() for prediction in self.predictions],
        }


@dataclass
class BenchmarkRunResult:
    dataset_id: str
    dataset_description: str
    generated_at: str
    modes: List[ModeResult]
    manifest_path: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "dataset_description": self.dataset_description,
            "generated_at": self.generated_at,
            "manifest_path": self.manifest_path,
            "modes": [mode.to_dict() for mode in self.modes],
        }


def load_python_graph_ablation_manifest(manifest_path: Path) -> Tuple[str, str, List[BenchmarkCase]]:
    """Load the synthetic dataset manifest for the Python graph ablation benchmark."""
    manifest_path = Path(manifest_path)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    dataset_id = payload["dataset_id"]
    description = payload.get("description", "")
    base_dir = manifest_path.parent
    cases: List[BenchmarkCase] = []
    for item in payload.get("cases", []):
        source = BenchmarkSourceSpec(**item["source"])
        sink = BenchmarkSinkSpec(**item["sink"])
        cases.append(
            BenchmarkCase(
                case_id=item["case_id"],
                title=item["title"],
                description=item.get("description", ""),
                file_path=(base_dir / item["file"]).resolve(),
                expected_vulnerable=bool(item["expected_vulnerable"]),
                source=source,
                sink=sink,
                tags=list(item.get("tags", [])),
            )
        )
    return dataset_id, description, cases


class _LinearTaintBaseline:
    """Deliberately simple baseline used for ablation against graph reasoning."""

    def __init__(self, case: BenchmarkCase):
        self.case = case
        self.tainted_vars: Set[str] = set()
        if case.source.variable_name and case.source.variable_name != "unknown":
            self.tainted_vars.add(case.source.variable_name)
        self.sink_hits: List[Dict[str, Any]] = []
        self.statement_count = 0

    def run(self) -> Dict[str, Any]:
        source_text = self.case.file_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source_text, filename=str(self.case.file_path))
        self._walk_statements(tree.body)
        return {
            "predicted_vulnerable": bool(self.sink_hits),
            "sink_hits": self.sink_hits,
            "statement_count": self.statement_count,
            "tainted_vars": sorted(self.tainted_vars),
        }

    def _walk_statements(self, statements: Sequence[ast.stmt]) -> None:
        for statement in statements:
            self.statement_count += 1
            self._process_statement(statement)

    def _process_statement(self, statement: ast.stmt) -> None:
        if isinstance(statement, ast.FunctionDef):
            self._walk_statements(statement.body)
            return

        if isinstance(statement, ast.Assign):
            self._process_assign(statement.targets, statement.value)
            return

        if isinstance(statement, ast.AnnAssign):
            self._process_assign([statement.target], statement.value)
            return

        if isinstance(statement, ast.AugAssign):
            reads = _extract_read_names(statement.target) + _extract_read_names(statement.value)
            writes = _extract_write_names(statement.target)
            if any(_mentions_taint(token, self.tainted_vars) for token in reads):
                self.tainted_vars.update(writes)
            return

        if isinstance(statement, ast.Expr):
            self._process_expression(statement.value, statement.lineno)
            return

        if isinstance(statement, ast.If):
            self._walk_statements(statement.body)
            self._walk_statements(statement.orelse)
            return

        if isinstance(statement, (ast.For, ast.While)):
            self._walk_statements(statement.body)
            self._walk_statements(statement.orelse)
            return

        if isinstance(statement, ast.Try):
            self._walk_statements(statement.body)
            for handler in statement.handlers:
                self._walk_statements(handler.body)
            self._walk_statements(statement.orelse)
            self._walk_statements(statement.finalbody)
            return

        if isinstance(statement, ast.With):
            self._walk_statements(statement.body)

    def _process_assign(self, targets: Sequence[ast.AST], value: Optional[ast.AST]) -> None:
        writes: List[str] = []
        for target in targets:
            writes.extend(_extract_write_names(target))

        reads = _extract_read_names(value)
        if any(_mentions_taint(token, self.tainted_vars) for token in reads):
            self.tainted_vars.update(writes)
            return

        if isinstance(value, ast.Call):
            _, arguments = _extract_call_info(value)
            if any(_mentions_taint(argument, self.tainted_vars) for argument in arguments):
                self.tainted_vars.update(writes)

    def _process_expression(self, value: ast.AST, line_number: int) -> None:
        if not isinstance(value, ast.Call):
            return

        callee_name, arguments = _extract_call_info(value)
        if line_number != self.case.sink.line:
            return
        if self.case.sink.function_name not in callee_name and callee_name not in self.case.sink.function_name:
            return
        if any(_mentions_taint(argument, self.tainted_vars) for argument in arguments):
            self.sink_hits.append(
                {
                    "line_number": line_number,
                    "callee_name": callee_name,
                    "arguments": arguments,
                }
            )


class PythonGraphAblationBenchmark:
    """Run the synthetic graph ablation benchmark over one manifest."""

    def __init__(
        self,
        dataset_id: str,
        dataset_description: str,
        cases: List[BenchmarkCase],
        manifest_path: Path,
    ):
        self.dataset_id = dataset_id
        self.dataset_description = dataset_description
        self.cases = cases
        self.manifest_path = Path(manifest_path)

    @classmethod
    def from_manifest(cls, manifest_path: Path) -> "PythonGraphAblationBenchmark":
        dataset_id, description, cases = load_python_graph_ablation_manifest(manifest_path)
        return cls(dataset_id, description, cases, manifest_path)

    def run(self, modes: Optional[Iterable[str]] = None) -> BenchmarkRunResult:
        selected_modes = list(modes or DEFAULT_MODES)
        mode_results: List[ModeResult] = []

        for mode in selected_modes:
            predictions = [self._evaluate_case(case, mode) for case in self.cases]
            metrics = self._compute_metrics(predictions)
            mode_results.append(ModeResult(mode=mode, metrics=metrics, predictions=predictions))

        return BenchmarkRunResult(
            dataset_id=self.dataset_id,
            dataset_description=self.dataset_description,
            generated_at=datetime.now().isoformat(),
            modes=mode_results,
            manifest_path=str(self.manifest_path),
        )

    def _evaluate_case(self, case: BenchmarkCase, mode: str) -> CasePrediction:
        if mode == "linear_taint_baseline":
            payload = _LinearTaintBaseline(case).run()
        elif mode == "graph_core_no_summary":
            payload = self._run_graph_mode(case, use_summary=False)
        elif mode == "graph_core_with_summary":
            payload = self._run_graph_mode(case, use_summary=True)
        else:
            raise ValueError(f"Unsupported benchmark mode: {mode}")

        predicted = bool(payload["predicted_vulnerable"])
        outcome = self._classify_outcome(case.expected_vulnerable, predicted)
        return CasePrediction(
            case_id=case.case_id,
            mode=mode,
            expected_vulnerable=case.expected_vulnerable,
            predicted_vulnerable=predicted,
            outcome=outcome,
            metadata=payload,
        )

    @staticmethod
    def _classify_outcome(expected: bool, predicted: bool) -> str:
        if expected and predicted:
            return "tp"
        if not expected and predicted:
            return "fp"
        if expected and not predicted:
            return "fn"
        return "tn"

    @staticmethod
    def _compute_metrics(predictions: Sequence[CasePrediction]) -> ModeMetrics:
        metrics = ModeMetrics()
        for prediction in predictions:
            if prediction.outcome == "tp":
                metrics.tp += 1
            elif prediction.outcome == "fp":
                metrics.fp += 1
            elif prediction.outcome == "tn":
                metrics.tn += 1
            elif prediction.outcome == "fn":
                metrics.fn += 1

        total = metrics.tp + metrics.fp + metrics.tn + metrics.fn
        positive_predictions = metrics.tp + metrics.fp
        actual_positives = metrics.tp + metrics.fn

        metrics.precision = metrics.tp / positive_predictions if positive_predictions else 0.0
        metrics.recall = metrics.tp / actual_positives if actual_positives else 0.0
        if metrics.precision + metrics.recall:
            metrics.f1 = (
                2 * metrics.precision * metrics.recall / (metrics.precision + metrics.recall)
            )
        metrics.accuracy = (metrics.tp + metrics.tn) / total if total else 0.0
        return metrics

    def _run_graph_mode(self, case: BenchmarkCase, use_summary: bool) -> Dict[str, Any]:
        source_text = case.file_path.read_text(encoding="utf-8", errors="replace")
        graph = PythonFlowGraphBuilder(case.file_path, source_text).build()
        resolver: Optional[Callable[[str, List[str], Set[str]], bool]] = None
        if use_summary:
            resolver = self._build_local_summary_resolver(graph)
        analyzer = PythonDataflowAnalyzer(graph, callee_taint_resolver=resolver)
        paths = analyzer.trace_paths(
            self._to_taint_source(case),
            [self._to_taint_sink(case)],
            [],
        )
        return {
            "predicted_vulnerable": bool(paths),
            "path_count": len(paths),
            "graph_summary": graph.summary(),
            "path_metadata": [path.metadata for path in paths],
            "used_local_summary": use_summary,
        }

    def _build_local_summary_resolver(
        self,
        graph: PythonFlowGraph,
    ) -> Callable[[str, List[str], Set[str]], bool]:
        def resolve(callee_name: str, arguments: List[str], tainted_vars: Set[str]) -> bool:
            summary = graph.get_function_summary(callee_name)
            if summary is None:
                return False

            tainted_params: Set[str] = set()
            for index, argument in enumerate(arguments):
                if not _mentions_taint(argument, tainted_vars):
                    continue
                if index < len(summary.parameter_names):
                    tainted_params.add(summary.parameter_names[index])
                else:
                    tainted_params.update(summary.parameter_names)

            return bool(set(summary.dependent_parameters).intersection(tainted_params))

        return resolve

    def _to_taint_source(self, case: BenchmarkCase) -> TaintSource:
        location = CodeLocation(
            file_path=str(case.file_path),
            line_number=case.source.line,
            column_number=0,
            code_snippet=_line_snippet(case.file_path, case.source.line),
        )
        return TaintSource(
            location=location,
            source_type=case.source.source_type,
            variable_name=case.source.variable_name,
            pattern=case.source.pattern,
        )

    def _to_taint_sink(self, case: BenchmarkCase) -> TaintSink:
        location = CodeLocation(
            file_path=str(case.file_path),
            line_number=case.sink.line,
            column_number=0,
            code_snippet=_line_snippet(case.file_path, case.sink.line),
        )
        vulnerability_type = VulnerabilityType[case.sink.vulnerability_type]
        return TaintSink(
            location=location,
            sink_type=vulnerability_type,
            function_name=case.sink.function_name,
            pattern=case.sink.pattern,
            arguments=list(case.sink.arguments),
        )


def render_python_graph_ablation_markdown(result: BenchmarkRunResult) -> str:
    """Render one benchmark run result as Markdown."""
    lines: List[str] = []
    lines.append("# Python Graph Ablation Benchmark\n")
    lines.append(f"**Dataset**: `{result.dataset_id}`  ")
    lines.append(f"**Generated At**: {result.generated_at}  ")
    lines.append(f"**Manifest**: `{result.manifest_path}`  ")
    if result.dataset_description:
        lines.append(f"**Description**: {result.dataset_description}\n")

    for mode in result.modes:
        lines.append(f"## Mode: `{mode.mode}`\n")
        lines.append("| Metric | Value |")
        lines.append("|---|---:|")
        lines.append(f"| TP | {mode.metrics.tp} |")
        lines.append(f"| FP | {mode.metrics.fp} |")
        lines.append(f"| TN | {mode.metrics.tn} |")
        lines.append(f"| FN | {mode.metrics.fn} |")
        lines.append(f"| Precision | {mode.metrics.precision:.3f} |")
        lines.append(f"| Recall | {mode.metrics.recall:.3f} |")
        lines.append(f"| F1 | {mode.metrics.f1:.3f} |")
        lines.append(f"| Accuracy | {mode.metrics.accuracy:.3f} |\n")

        lines.append("| Case | Expected | Predicted | Outcome | Notes |")
        lines.append("|---|:---:|:---:|:---:|---|")
        for prediction in mode.predictions:
            notes = _format_prediction_notes(prediction)
            expected = "vuln" if prediction.expected_vulnerable else "safe"
            predicted = "vuln" if prediction.predicted_vulnerable else "safe"
            lines.append(
                f"| `{prediction.case_id}` | {expected} | {predicted} | `{prediction.outcome}` | {notes} |"
            )
        lines.append("")

    return "\n".join(lines)


def _format_prediction_notes(prediction: CasePrediction) -> str:
    metadata = prediction.metadata
    if prediction.mode == "linear_taint_baseline":
        hits = metadata.get("sink_hits", [])
        if hits:
            return f"linear hits={len(hits)} tainted={metadata.get('tainted_vars', [])}"
        return f"linear hits=0 tainted={metadata.get('tainted_vars', [])}"

    parts = [f"paths={metadata.get('path_count', 0)}"]
    graph_summary = metadata.get("graph_summary", {})
    if graph_summary:
        parts.append(
            "graph="
            f"n{graph_summary.get('node_count', 0)}/"
            f"cfg{graph_summary.get('cfg_edge_count', 0)}/"
            f"dfg{graph_summary.get('dfg_edge_count', 0)}"
        )
    if metadata.get("used_local_summary"):
        local_summaries = 0
        for path_metadata in metadata.get("path_metadata", []):
            local_summaries += len(path_metadata.get("local_callee_summaries", []))
        parts.append(f"local_summary_hits={local_summaries}")
    return ", ".join(parts)

