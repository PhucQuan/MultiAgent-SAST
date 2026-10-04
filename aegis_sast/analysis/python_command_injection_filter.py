"""Python-only COMMAND_INJECTION pruning for narrow safe-command patterns."""

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


class PythonCommandInjectionFilter(PythonPathTraversalFilter):
    """Suppress a narrow slice of Python command injection false positives."""

    _SUBPROCESS_FUNCTIONS = {
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.run",
    }

    def __init__(self, file_path: Path):
        super().__init__(file_path)

    def should_suppress(self, vulnerability: Vulnerability) -> bool:
        if self.module is None:
            return False
        if vulnerability.vuln_type.value != "COMMAND_INJECTION":
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

        sink_expr = self._sink_command_expression(sink_call)
        if sink_expr is None:
            return False

        sink_value = self._evaluate_expression(
            sink_expr,
            env,
            vulnerability.dataflow.source,
        )
        return self._is_safe_command(sink_value)

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

    def _sink_command_expression(self, call: ast.Call) -> Optional[ast.AST]:
        callee = self._render(call.func)
        if callee in self._SUBPROCESS_FUNCTIONS:
            if call.args:
                return call.args[0]
            for keyword in call.keywords:
                if keyword.arg == "args":
                    return keyword.value
            return None

        if call.args:
            return call.args[0]

        for keyword in call.keywords:
            if keyword.arg in {"args", "command"}:
                return keyword.value
        return None

    @staticmethod
    def _is_safe_command(value: _AbstractValue) -> bool:
        return value.kind == "safe"
