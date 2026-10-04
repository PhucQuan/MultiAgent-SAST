"""Python-only INSECURE_DESERIALIZATION pruning for narrow safe-payload patterns."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, Optional

from aegis_sast.analysis.python_path_traversal_filter import (
    PythonPathTraversalFilter,
    _AbstractValue,
    _unknown_value,
)
from aegis_sast.core.models import TaintSource, Vulnerability


class PythonDeserializationFilter(PythonPathTraversalFilter):
    """Suppress a narrow slice of Python deserialization false positives."""

    _PASSTHROUGH_CALLS = {
        "base64.b64decode",
        "base64.standard_b64decode",
        "base64.urlsafe_b64decode",
        "urllib.parse.unquote",
        "urllib.parse.unquote_plus",
    }
    _PASSTHROUGH_METHODS = {"decode", "encode"}

    def __init__(self, file_path: Path):
        super().__init__(file_path)

    def should_suppress(self, vulnerability: Vulnerability) -> bool:
        if self.module is None:
            return False
        if vulnerability.vuln_type.value != "INSECURE_DESERIALIZATION":
            return False

        sink = vulnerability.dataflow.sink
        sink_line = sink.location.line_number
        scope = self._find_scope_for_line(sink_line)
        if scope is None:
            return False

        env = self._execute_until_sink(
            statements=self._scope_statements(scope),
            sink_line=sink_line,
            source=vulnerability.dataflow.source,
        )
        if env is None:
            return False

        sink_call = self._find_sink_call(scope, sink_line, sink)
        if sink_call is None:
            return False

        sink_expr = self._sink_payload_expression(sink_call)
        if sink_expr is None:
            return False

        sink_value = self._evaluate_expression(
            sink_expr,
            env,
            vulnerability.dataflow.source,
        )
        return self._is_safe_payload(sink_value)

    def _evaluate_expression(
        self,
        expression: Optional[ast.AST],
        env: Dict[str, _AbstractValue],
        source: TaintSource,
    ) -> _AbstractValue:
        if isinstance(expression, ast.Attribute):
            if isinstance(expression.value, ast.Name) and expression.value.id in env:
                base_value = env[expression.value.id]
                if base_value.kind == "dict" and expression.attr in base_value.entries:
                    return base_value.entries[expression.attr].clone()
            return _unknown_value()

        return super()._evaluate_expression(expression, env, source)

    def _evaluate_call(
        self,
        call: ast.Call,
        env: Dict[str, _AbstractValue],
        source: TaintSource,
    ) -> _AbstractValue:
        callee = self._render(call.func)
        if callee in self._PASSTHROUGH_CALLS and call.args:
            return self._evaluate_expression(call.args[0], env, source)

        if isinstance(call.func, ast.Attribute):
            if call.func.attr in self._PASSTHROUGH_METHODS:
                return self._evaluate_expression(call.func.value, env, source)

        return super()._evaluate_call(call, env, source)

    @staticmethod
    def _sink_payload_expression(call: ast.Call) -> Optional[ast.AST]:
        if call.args:
            return call.args[0]
        return None

    @staticmethod
    def _is_safe_payload(value: _AbstractValue) -> bool:
        return value.kind == "safe"
