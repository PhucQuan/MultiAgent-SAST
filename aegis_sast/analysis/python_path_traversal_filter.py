"""Python-only PATH_TRAVERSAL pruning for narrow safe-path patterns."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from aegis_sast.core.models import TaintSink, TaintSource, Vulnerability

_NO_LITERAL = object()


@dataclass
class _AbstractValue:
    """Small abstract domain used to decide whether one sink path is safe."""

    kind: str
    literal: Any = _NO_LITERAL
    entries: Dict[Any, "_AbstractValue"] = field(default_factory=dict)
    items: List["_AbstractValue"] = field(default_factory=list)
    sections: Dict[str, Dict[str, "_AbstractValue"]] = field(default_factory=dict)
    whole_taint: bool = False

    def clone(self) -> "_AbstractValue":
        return _AbstractValue(
            kind=self.kind,
            literal=self.literal,
            entries={key: value.clone() for key, value in self.entries.items()},
            items=[value.clone() for value in self.items],
            sections={
                section: {key: value.clone() for key, value in mapping.items()}
                for section, mapping in self.sections.items()
            },
            whole_taint=self.whole_taint,
        )

    def is_safe_path(self) -> bool:
        return self.kind in {"safe", "guarded"}


def _safe_value(literal: Any = _NO_LITERAL) -> _AbstractValue:
    return _AbstractValue(kind="safe", literal=literal)


def _guarded_value(literal: Any = _NO_LITERAL) -> _AbstractValue:
    return _AbstractValue(kind="guarded", literal=literal)


def _tainted_value() -> _AbstractValue:
    return _AbstractValue(kind="tainted")


def _unknown_value() -> _AbstractValue:
    return _AbstractValue(kind="unknown")


def _dict_value(entries: Optional[Dict[Any, _AbstractValue]] = None) -> _AbstractValue:
    return _AbstractValue(kind="dict", entries=entries or {})


def _list_value(items: Optional[List[_AbstractValue]] = None) -> _AbstractValue:
    return _AbstractValue(kind="list", items=items or [])


def _config_value() -> _AbstractValue:
    return _AbstractValue(kind="config")


def _merge_values(values: Iterable[_AbstractValue]) -> _AbstractValue:
    collected = [value.clone() for value in values if value is not None]
    if not collected:
        return _unknown_value()

    if any(value.kind == "tainted" for value in collected):
        return _tainted_value()
    if any(value.kind == "unknown" for value in collected):
        return _unknown_value()

    kinds = {value.kind for value in collected}
    if kinds == {"dict"}:
        keys = set()
        whole_taint = any(value.whole_taint for value in collected)
        for value in collected:
            keys.update(value.entries.keys())
        merged_entries = {
            key: _merge_values(
                value.entries.get(key, _unknown_value())
                for value in collected
            )
            for key in keys
        }
        return _AbstractValue(
            kind="dict",
            entries=merged_entries,
            whole_taint=whole_taint,
        )

    if kinds == {"list"}:
        max_items = max(len(value.items) for value in collected)
        merged_items = []
        for index in range(max_items):
            merged_items.append(
                _merge_values(
                    value.items[index]
                    if index < len(value.items)
                    else _unknown_value()
                    for value in collected
                )
            )
        return _AbstractValue(kind="list", items=merged_items)

    if kinds == {"config"}:
        section_names = set()
        whole_taint = any(value.whole_taint for value in collected)
        for value in collected:
            section_names.update(value.sections.keys())
        merged_sections: Dict[str, Dict[str, _AbstractValue]] = {}
        for section_name in section_names:
            option_names = set()
            for value in collected:
                option_names.update(value.sections.get(section_name, {}).keys())
            merged_sections[section_name] = {
                option_name: _merge_values(
                    value.sections.get(section_name, {}).get(option_name, _unknown_value())
                    for value in collected
                )
                for option_name in option_names
            }
        return _AbstractValue(
            kind="config",
            sections=merged_sections,
            whole_taint=whole_taint,
        )

    if kinds <= {"safe", "guarded"}:
        guard_kind = "guarded" if "guarded" in kinds else "safe"
        literals = [value.literal for value in collected]
        if all(literal is not _NO_LITERAL for literal in literals):
            first = literals[0]
            if all(literal == first for literal in literals[1:]):
                return _guarded_value(first) if guard_kind == "guarded" else _safe_value(first)
        return _guarded_value() if guard_kind == "guarded" else _safe_value()

    return _unknown_value()


class PythonPathTraversalFilter:
    """Suppress a narrow slice of Python PATH_TRAVERSAL false positives."""

    _MODULE_STYLE_OPEN_RECEIVERS = {"bz2", "codecs", "gzip", "io", "lzma"}
    _PATH_RECEIVER_METHODS = {"exists", "is_dir", "is_file", "open", "read_bytes", "read_text"}
    _PARENT_TRAVERSAL_TOKENS = {"../", "..\\"}

    def __init__(self, file_path: Path):
        self.file_path = Path(file_path)
        try:
            self.source_text = self.file_path.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except OSError:
            self.source_text = ""

        try:
            self.module = ast.parse(self.source_text, filename=str(self.file_path))
        except SyntaxError:
            self.module = None

    def should_suppress(self, vulnerability: Vulnerability) -> bool:
        if self.module is None:
            return False
        if vulnerability.vuln_type.value != "PATH_TRAVERSAL":
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

        sink_expr = self._sink_path_expression(sink_call)
        if sink_expr is None:
            return False

        sink_value = self._evaluate_expression(
            sink_expr,
            env,
            vulnerability.dataflow.source,
        )
        return sink_value.is_safe_path()

    def _execute_until_sink(
        self,
        *,
        statements: List[ast.stmt],
        sink_line: int,
        source: TaintSource,
    ) -> Optional[Dict[str, _AbstractValue]]:
        current_envs: List[Dict[str, _AbstractValue]] = [{}]

        for statement in statements:
            start_line = getattr(statement, "lineno", 0)
            end_line = getattr(statement, "end_lineno", start_line)
            if start_line >= sink_line:
                break
            if end_line >= sink_line:
                next_envs: List[Dict[str, _AbstractValue]] = []
                for env in current_envs:
                    next_envs.extend(
                        self._execute_statement_until_sink(
                            statement,
                            env,
                            source,
                            sink_line,
                        )
                    )
                if not next_envs:
                    return None
                current_envs = [self._merge_envs(next_envs)]
                break

            next_envs: List[Dict[str, _AbstractValue]] = []
            for env in current_envs:
                next_envs.extend(self._execute_statement(statement, env, source))
            if not next_envs:
                return None
            current_envs = [self._merge_envs(next_envs)]

        return current_envs[0] if current_envs else None

    def _execute_until_sink_in_block(
        self,
        statements: List[ast.stmt],
        env: Dict[str, _AbstractValue],
        source: TaintSource,
        sink_line: int,
    ) -> List[Dict[str, _AbstractValue]]:
        current_envs: List[Dict[str, _AbstractValue]] = [self._clone_env(env)]

        for statement in statements:
            start_line = getattr(statement, "lineno", 0)
            end_line = getattr(statement, "end_lineno", start_line)
            if start_line >= sink_line:
                break
            if end_line >= sink_line:
                next_envs: List[Dict[str, _AbstractValue]] = []
                for current_env in current_envs:
                    next_envs.extend(
                        self._execute_statement_until_sink(
                            statement,
                            current_env,
                            source,
                            sink_line,
                        )
                    )
                return next_envs

            next_envs: List[Dict[str, _AbstractValue]] = []
            for current_env in current_envs:
                next_envs.extend(self._execute_statement(statement, current_env, source))
            if not next_envs:
                return []
            current_envs = [self._merge_envs(next_envs)]

        return current_envs

    def _execute_statement_until_sink(
        self,
        statement: ast.stmt,
        env: Dict[str, _AbstractValue],
        source: TaintSource,
        sink_line: int,
    ) -> List[Dict[str, _AbstractValue]]:
        if isinstance(statement, ast.Try):
            return self._execute_try_until_sink(statement, env, source, sink_line)

        if isinstance(statement, ast.If):
            return self._execute_if_until_sink(statement, env, source, sink_line)

        if isinstance(statement, ast.With):
            return self._execute_with_until_sink(statement, env, source, sink_line)

        if hasattr(ast, "Match") and isinstance(statement, ast.Match):
            return self._execute_match_until_sink(statement, env, source, sink_line)

        return [self._clone_env(env)]

    def _execute_block(
        self,
        statements: List[ast.stmt],
        env: Dict[str, _AbstractValue],
        source: TaintSource,
    ) -> List[Dict[str, _AbstractValue]]:
        current_envs: List[Dict[str, _AbstractValue]] = [self._clone_env(env)]

        for statement in statements:
            next_envs: List[Dict[str, _AbstractValue]] = []
            for current_env in current_envs:
                next_envs.extend(self._execute_statement(statement, current_env, source))
            if not next_envs:
                return []
            current_envs = [self._merge_envs(next_envs)]

        return current_envs

    def _execute_statement(
        self,
        statement: ast.stmt,
        env: Dict[str, _AbstractValue],
        source: TaintSource,
    ) -> List[Dict[str, _AbstractValue]]:
        if isinstance(statement, ast.Assign):
            value = self._evaluate_expression(statement.value, env, source)
            env_after = self._clone_env(env)
            for target in statement.targets:
                self._assign_target(env_after, target, value)
            return [env_after]

        if isinstance(statement, ast.AnnAssign):
            value = self._evaluate_expression(statement.value, env, source)
            env_after = self._clone_env(env)
            self._assign_target(env_after, statement.target, value)
            return [env_after]

        if isinstance(statement, ast.AugAssign):
            original = self._read_target(statement.target, env)
            update = self._evaluate_expression(statement.value, env, source)
            combined = self._combine_values(original, update)
            env_after = self._clone_env(env)
            self._assign_target(env_after, statement.target, combined)
            return [env_after]

        if isinstance(statement, ast.Expr):
            env_after = self._clone_env(env)
            if isinstance(statement.value, ast.Call):
                self._apply_mutating_call(env_after, statement.value, source)
            return [env_after]

        if isinstance(statement, ast.If):
            return self._execute_if(statement, env, source)

        if hasattr(ast, "Match") and isinstance(statement, ast.Match):
            return self._execute_match(statement, env, source)

        if isinstance(statement, ast.For):
            return self._execute_for(statement, env, source)

        if isinstance(statement, ast.While):
            return self._execute_while(statement, env, source)

        if isinstance(statement, ast.Try):
            return self._execute_try(statement, env, source)

        if isinstance(statement, ast.With):
            return self._execute_with(statement, env, source)

        if isinstance(statement, (ast.Return, ast.Raise)):
            return []

        return [self._clone_env(env)]

    def _execute_if(
        self,
        statement: ast.If,
        env: Dict[str, _AbstractValue],
        source: TaintSource,
    ) -> List[Dict[str, _AbstractValue]]:
        truth = self._evaluate_truth(statement.test, env, source)
        guarded_var = self._extract_parent_guard_variable(statement.test)
        guard_applies = guarded_var is not None and self._block_returns(statement.body)

        if truth is True:
            return self._execute_block(statement.body, env, source)

        if truth is False:
            false_seed = self._clone_env(env)
            if guard_applies and not statement.orelse:
                self._apply_guard(false_seed, guarded_var)
            if statement.orelse:
                return self._execute_block(statement.orelse, false_seed, source)
            return [false_seed]

        fallthrough: List[Dict[str, _AbstractValue]] = []
        body_envs = self._execute_block(statement.body, self._clone_env(env), source)
        fallthrough.extend(body_envs)

        false_seed = self._clone_env(env)
        if guard_applies and not statement.orelse:
            self._apply_guard(false_seed, guarded_var)
            fallthrough.append(false_seed)
            return fallthrough

        if statement.orelse:
            fallthrough.extend(self._execute_block(statement.orelse, false_seed, source))
        else:
            fallthrough.append(false_seed)
        return fallthrough

    def _execute_if_until_sink(
        self,
        statement: ast.If,
        env: Dict[str, _AbstractValue],
        source: TaintSource,
        sink_line: int,
    ) -> List[Dict[str, _AbstractValue]]:
        truth = self._evaluate_truth(statement.test, env, source)
        guarded_var = self._extract_parent_guard_variable(statement.test)
        guard_applies = guarded_var is not None and self._block_returns(statement.body)

        sink_in_body = self._block_contains_line(statement.body, sink_line)
        sink_in_orelse = self._block_contains_line(statement.orelse, sink_line)

        if sink_in_body:
            if truth is False:
                return []
            return self._execute_until_sink_in_block(
                statement.body,
                env,
                source,
                sink_line,
            )

        if sink_in_orelse:
            if truth is True:
                return []
            false_seed = self._clone_env(env)
            if guard_applies and not statement.orelse:
                self._apply_guard(false_seed, guarded_var)
            return self._execute_until_sink_in_block(
                statement.orelse,
                false_seed,
                source,
                sink_line,
            )

        return [self._clone_env(env)]

    def _execute_match(
        self,
        statement: ast.Match,
        env: Dict[str, _AbstractValue],
        source: TaintSource,
    ) -> List[Dict[str, _AbstractValue]]:
        subject_literal = self._evaluate_literal(statement.subject, env, source)
        if subject_literal is not _NO_LITERAL:
            for case in statement.cases:
                if self._match_pattern_accepts(case.pattern, subject_literal):
                    return self._execute_block(case.body, env, source)
            return [self._clone_env(env)]

        fallthrough: List[Dict[str, _AbstractValue]] = []
        for case in statement.cases:
            fallthrough.extend(self._execute_block(case.body, self._clone_env(env), source))
        return fallthrough or [self._clone_env(env)]

    def _execute_match_until_sink(
        self,
        statement: ast.Match,
        env: Dict[str, _AbstractValue],
        source: TaintSource,
        sink_line: int,
    ) -> List[Dict[str, _AbstractValue]]:
        subject_literal = self._evaluate_literal(statement.subject, env, source)
        fallthrough: List[Dict[str, _AbstractValue]] = []

        for case in statement.cases:
            if not self._block_contains_line(case.body, sink_line):
                continue
            if (
                subject_literal is not _NO_LITERAL
                and not self._match_pattern_accepts(case.pattern, subject_literal)
            ):
                continue
            fallthrough.extend(
                self._execute_until_sink_in_block(
                    case.body,
                    self._clone_env(env),
                    source,
                    sink_line,
                )
            )

        return fallthrough

    def _execute_for(
        self,
        statement: ast.For,
        env: Dict[str, _AbstractValue],
        source: TaintSource,
    ) -> List[Dict[str, _AbstractValue]]:
        fallthrough = [self._clone_env(env)]

        iter_value = self._evaluate_expression(statement.iter, env, source)
        target_value = None
        if self._matches_source_expression(statement.iter, source):
            target_value = _tainted_value()
        elif iter_value.kind == "list" and iter_value.items:
            target_value = _merge_values(iter_value.items)

        if target_value is not None:
            loop_seed = self._clone_env(env)
            self._assign_target(loop_seed, statement.target, target_value)
            body_envs = self._execute_block(statement.body, loop_seed, source)
            if body_envs:
                fallthrough.extend(body_envs)

        if statement.orelse:
            fallthrough.extend(self._execute_block(statement.orelse, self._clone_env(env), source))

        return fallthrough

    def _execute_while(
        self,
        statement: ast.While,
        env: Dict[str, _AbstractValue],
        source: TaintSource,
    ) -> List[Dict[str, _AbstractValue]]:
        truth = self._evaluate_truth(statement.test, env, source)
        if truth is False:
            if statement.orelse:
                return self._execute_block(statement.orelse, env, source)
            return [self._clone_env(env)]

        fallthrough = [self._clone_env(env)]
        body_envs = self._execute_block(statement.body, self._clone_env(env), source)
        if body_envs:
            fallthrough.extend(body_envs)
        if statement.orelse:
            fallthrough.extend(self._execute_block(statement.orelse, self._clone_env(env), source))
        return fallthrough

    def _execute_try(
        self,
        statement: ast.Try,
        env: Dict[str, _AbstractValue],
        source: TaintSource,
    ) -> List[Dict[str, _AbstractValue]]:
        fallthrough: List[Dict[str, _AbstractValue]] = []
        body_envs = self._execute_block(statement.body, self._clone_env(env), source)
        fallthrough.extend(body_envs)

        for handler in statement.handlers:
            handler_seed = self._clone_env(env)
            if handler.name:
                handler_seed[handler.name] = _unknown_value()
            fallthrough.extend(self._execute_block(handler.body, handler_seed, source))

        if statement.orelse:
            merged = self._merge_envs(fallthrough) if fallthrough else self._clone_env(env)
            fallthrough = self._execute_block(statement.orelse, merged, source)

        if statement.finalbody:
            merged = self._merge_envs(fallthrough) if fallthrough else self._clone_env(env)
            fallthrough = self._execute_block(statement.finalbody, merged, source)

        return fallthrough or [self._clone_env(env)]

    def _execute_try_until_sink(
        self,
        statement: ast.Try,
        env: Dict[str, _AbstractValue],
        source: TaintSource,
        sink_line: int,
    ) -> List[Dict[str, _AbstractValue]]:
        if self._block_contains_line(statement.body, sink_line):
            return self._execute_until_sink_in_block(
                statement.body,
                env,
                source,
                sink_line,
            )

        if self._block_contains_line(statement.orelse, sink_line):
            body_envs = self._execute_block(statement.body, self._clone_env(env), source)
            merged = self._merge_envs(body_envs) if body_envs else self._clone_env(env)
            return self._execute_until_sink_in_block(
                statement.orelse,
                merged,
                source,
                sink_line,
            )

        for handler in statement.handlers:
            if not self._block_contains_line(handler.body, sink_line):
                continue
            handler_seed = self._clone_env(env)
            if handler.name:
                handler_seed[handler.name] = _unknown_value()
            return self._execute_until_sink_in_block(
                handler.body,
                handler_seed,
                source,
                sink_line,
            )

        if self._block_contains_line(statement.finalbody, sink_line):
            fallthrough: List[Dict[str, _AbstractValue]] = []
            fallthrough.extend(self._execute_block(statement.body, self._clone_env(env), source))
            for handler in statement.handlers:
                handler_seed = self._clone_env(env)
                if handler.name:
                    handler_seed[handler.name] = _unknown_value()
                fallthrough.extend(self._execute_block(handler.body, handler_seed, source))
            if statement.orelse:
                merged_orelse = (
                    self._merge_envs(fallthrough) if fallthrough else self._clone_env(env)
                )
                fallthrough = self._execute_block(statement.orelse, merged_orelse, source)
            merged = self._merge_envs(fallthrough) if fallthrough else self._clone_env(env)
            return self._execute_until_sink_in_block(
                statement.finalbody,
                merged,
                source,
                sink_line,
            )

        return [self._clone_env(env)]

    def _execute_with(
        self,
        statement: ast.With,
        env: Dict[str, _AbstractValue],
        source: TaintSource,
    ) -> List[Dict[str, _AbstractValue]]:
        env_after = self._clone_env(env)
        for item in statement.items:
            context_value = self._evaluate_expression(item.context_expr, env_after, source)
            if item.optional_vars is not None:
                self._assign_target(env_after, item.optional_vars, context_value)
        body_envs = self._execute_block(statement.body, env_after, source)
        return body_envs or [env_after]

    def _execute_with_until_sink(
        self,
        statement: ast.With,
        env: Dict[str, _AbstractValue],
        source: TaintSource,
        sink_line: int,
    ) -> List[Dict[str, _AbstractValue]]:
        if getattr(statement, "lineno", 0) == sink_line:
            return [self._clone_env(env)]

        env_after = self._clone_env(env)
        for item in statement.items:
            context_value = self._evaluate_expression(item.context_expr, env_after, source)
            if item.optional_vars is not None:
                self._assign_target(env_after, item.optional_vars, context_value)
        if self._block_contains_line(statement.body, sink_line):
            return self._execute_until_sink_in_block(
                statement.body,
                env_after,
                source,
                sink_line,
            )
        return [env_after]

    def _apply_mutating_call(
        self,
        env: Dict[str, _AbstractValue],
        call: ast.Call,
        source: TaintSource,
    ) -> None:
        if not isinstance(call.func, ast.Attribute):
            return
        if not isinstance(call.func.value, ast.Name):
            return

        receiver_name = call.func.value.id
        receiver = env.get(receiver_name)
        if receiver is None:
            return

        updated = receiver.clone()
        method_name = call.func.attr

        if updated.kind == "list":
            if method_name == "append" and call.args:
                updated.items.append(self._evaluate_expression(call.args[0], env, source))
            elif method_name == "pop":
                index_literal = 0 if not call.args else self._literal_index(call.args[0], env, source)
                if index_literal is None:
                    updated.items = []
                    updated.whole_taint = True
                elif -len(updated.items) <= index_literal < len(updated.items):
                    updated.items.pop(index_literal)
            else:
                return
            env[receiver_name] = updated
            return

        if updated.kind == "config":
            if method_name == "add_section" and call.args:
                section_name = self._literal_string(call.args[0], env, source)
                if section_name is None:
                    updated.whole_taint = True
                else:
                    updated.sections.setdefault(section_name, {})
                env[receiver_name] = updated
                return
            if method_name == "set" and len(call.args) >= 3:
                section_name = self._literal_string(call.args[0], env, source)
                option_name = self._literal_string(call.args[1], env, source)
                option_value = self._evaluate_expression(call.args[2], env, source)
                if section_name is None or option_name is None:
                    updated.whole_taint = True
                else:
                    updated.sections.setdefault(section_name, {})[option_name] = option_value
                env[receiver_name] = updated
                return

    def _evaluate_expression(
        self,
        expression: Optional[ast.AST],
        env: Dict[str, _AbstractValue],
        source: TaintSource,
    ) -> _AbstractValue:
        if expression is None:
            return _unknown_value()

        if self._matches_source_expression(expression, source):
            return _tainted_value()

        if isinstance(expression, ast.Name):
            return env.get(expression.id, _unknown_value()).clone()

        if isinstance(expression, ast.Constant):
            return _safe_value(expression.value)

        if isinstance(expression, ast.List):
            return _list_value(
                [self._evaluate_expression(item, env, source) for item in expression.elts]
            )

        if isinstance(expression, ast.Tuple):
            return _list_value(
                [self._evaluate_expression(item, env, source) for item in expression.elts]
            )

        if isinstance(expression, ast.Dict):
            entries: Dict[Any, _AbstractValue] = {}
            dynamic_key = False
            for key_node, value_node in zip(expression.keys, expression.values):
                literal_key = self._literal_key(key_node, env, source)
                if literal_key is None:
                    dynamic_key = True
                    continue
                entries[literal_key] = self._evaluate_expression(value_node, env, source)
            return _AbstractValue(kind="dict", entries=entries, whole_taint=dynamic_key)

        if isinstance(expression, ast.JoinedStr):
            values = [
                self._evaluate_expression(item.value, env, source)
                if isinstance(item, ast.FormattedValue)
                else _safe_value()
                for item in expression.values
            ]
            return _merge_values(values)

        if isinstance(expression, ast.BinOp):
            left_value = self._evaluate_expression(expression.left, env, source)
            right_value = self._evaluate_expression(expression.right, env, source)
            literal_value = self._evaluate_literal(expression, env, source)
            merged = self._combine_values(left_value, right_value)
            if literal_value is not _NO_LITERAL and merged.kind == "safe":
                merged.literal = literal_value
            return merged

        if isinstance(expression, ast.Subscript):
            return self._evaluate_subscript(expression, env, source)

        if isinstance(expression, ast.IfExp):
            truth = self._evaluate_truth(expression.test, env, source)
            if truth is True:
                return self._evaluate_expression(expression.body, env, source)
            if truth is False:
                return self._evaluate_expression(expression.orelse, env, source)
            return _merge_values(
                [
                    self._evaluate_expression(expression.body, env, source),
                    self._evaluate_expression(expression.orelse, env, source),
                ]
            )

        if isinstance(expression, ast.Call):
            return self._evaluate_call(expression, env, source)

        if isinstance(expression, ast.Attribute):
            if isinstance(expression.value, ast.Name) and expression.value.id in env:
                base_value = env[expression.value.id]
                if base_value.kind == "dict" and expression.attr in base_value.entries:
                    return base_value.entries[expression.attr].clone()
            return _safe_value()

        if isinstance(expression, ast.UnaryOp) and isinstance(expression.op, ast.USub):
            literal = self._evaluate_literal(expression, env, source)
            if literal is not _NO_LITERAL:
                return _safe_value(literal)

        return _unknown_value()

    def _evaluate_call(
        self,
        call: ast.Call,
        env: Dict[str, _AbstractValue],
        source: TaintSource,
    ) -> _AbstractValue:
        callee = self._render(call.func)
        if callee == "configparser.ConfigParser":
            return _config_value()
        if callee == "pathlib.Path":
            return _merge_values(
                [self._evaluate_expression(argument, env, source) for argument in call.args]
                or [_safe_value()]
            )

        if isinstance(call.func, ast.Attribute):
            method_name = call.func.attr
            receiver_value = self._evaluate_expression(call.func.value, env, source)

            if method_name == "get":
                if receiver_value.kind == "dict":
                    key = self._literal_key(call.args[0], env, source) if call.args else None
                    return self._container_lookup(receiver_value, key)
                if receiver_value.kind == "config":
                    section_name = self._literal_string(call.args[0], env, source) if len(call.args) >= 1 else None
                    option_name = self._literal_string(call.args[1], env, source) if len(call.args) >= 2 else None
                    return self._config_lookup(receiver_value, section_name, option_name)

            if method_name in {"exists", "is_dir", "is_file", "open", "read_bytes", "read_text"}:
                return receiver_value

            if method_name in {"append", "pop", "set", "add_section"}:
                return receiver_value

        return _unknown_value()

    def _evaluate_subscript(
        self,
        expression: ast.Subscript,
        env: Dict[str, _AbstractValue],
        source: TaintSource,
    ) -> _AbstractValue:
        value = self._evaluate_expression(expression.value, env, source)
        index_literal = self._literal_key(expression.slice, env, source)

        if isinstance(value.literal, str):
            literal = self._evaluate_literal(expression, env, source)
            if literal is not _NO_LITERAL:
                return _safe_value(literal)
            if value.kind in {"guarded", "tainted", "unknown"}:
                return value.clone()

        if value.kind == "list":
            if not isinstance(index_literal, int):
                return _tainted_value() if value.whole_taint else _unknown_value()
            if -len(value.items) <= index_literal < len(value.items):
                return value.items[index_literal].clone()
            return _unknown_value()

        if value.kind == "dict":
            return self._container_lookup(value, index_literal)

        if value.kind == "config":
            return _unknown_value()

        if value.kind in {"guarded", "tainted"}:
            return value.clone()

        return _unknown_value()

    def _evaluate_truth(
        self,
        expression: ast.AST,
        env: Dict[str, _AbstractValue],
        source: TaintSource,
    ) -> Optional[bool]:
        literal = self._evaluate_literal(expression, env, source)
        if literal is _NO_LITERAL:
            return None
        try:
            return bool(literal)
        except Exception:
            return None

    def _evaluate_literal(
        self,
        expression: Optional[ast.AST],
        env: Dict[str, _AbstractValue],
        source: TaintSource,
    ) -> Any:
        if expression is None:
            return _NO_LITERAL

        if isinstance(expression, ast.Constant):
            return expression.value

        if isinstance(expression, ast.Name):
            value = env.get(expression.id)
            if value and value.kind in {"safe", "guarded"} and value.literal is not _NO_LITERAL:
                return value.literal
            return _NO_LITERAL

        if isinstance(expression, ast.Subscript):
            base_literal = self._evaluate_literal(expression.value, env, source)
            if base_literal is _NO_LITERAL:
                return _NO_LITERAL
            try:
                if isinstance(expression.slice, ast.Slice):
                    lower = self._evaluate_literal(expression.slice.lower, env, source)
                    upper = self._evaluate_literal(expression.slice.upper, env, source)
                    step = self._evaluate_literal(expression.slice.step, env, source)
                    lower_value = None if lower is _NO_LITERAL else lower
                    upper_value = None if upper is _NO_LITERAL else upper
                    step_value = None if step is _NO_LITERAL else step
                    return base_literal[slice(lower_value, upper_value, step_value)]
                index_value = self._evaluate_literal(expression.slice, env, source)
                if index_value is _NO_LITERAL:
                    return _NO_LITERAL
                return base_literal[index_value]
            except Exception:
                return _NO_LITERAL

        if isinstance(expression, ast.BinOp):
            left = self._evaluate_literal(expression.left, env, source)
            right = self._evaluate_literal(expression.right, env, source)
            if left is _NO_LITERAL or right is _NO_LITERAL:
                return _NO_LITERAL
            try:
                if isinstance(expression.op, ast.Add):
                    return left + right
                if isinstance(expression.op, ast.Sub):
                    return left - right
                if isinstance(expression.op, ast.Mult):
                    return left * right
                if isinstance(expression.op, ast.Div):
                    return left / right
                if isinstance(expression.op, ast.FloorDiv):
                    return left // right
                if isinstance(expression.op, ast.Mod):
                    return left % right
                if isinstance(expression.op, ast.Pow):
                    return left ** right
            except Exception:
                return _NO_LITERAL
            return _NO_LITERAL

        if isinstance(expression, ast.UnaryOp):
            operand = self._evaluate_literal(expression.operand, env, source)
            if operand is _NO_LITERAL:
                return _NO_LITERAL
            try:
                if isinstance(expression.op, ast.USub):
                    return -operand
                if isinstance(expression.op, ast.UAdd):
                    return +operand
                if isinstance(expression.op, ast.Not):
                    return not operand
            except Exception:
                return _NO_LITERAL
            return _NO_LITERAL

        if isinstance(expression, ast.Compare):
            left = self._evaluate_literal(expression.left, env, source)
            if left is _NO_LITERAL:
                return _NO_LITERAL
            current = left
            for operator, comparator in zip(expression.ops, expression.comparators):
                right = self._evaluate_literal(comparator, env, source)
                if right is _NO_LITERAL:
                    return _NO_LITERAL
                try:
                    if isinstance(operator, ast.In):
                        result = current in right
                    elif isinstance(operator, ast.NotIn):
                        result = current not in right
                    elif isinstance(operator, ast.Eq):
                        result = current == right
                    elif isinstance(operator, ast.NotEq):
                        result = current != right
                    elif isinstance(operator, ast.Gt):
                        result = current > right
                    elif isinstance(operator, ast.GtE):
                        result = current >= right
                    elif isinstance(operator, ast.Lt):
                        result = current < right
                    elif isinstance(operator, ast.LtE):
                        result = current <= right
                    else:
                        return _NO_LITERAL
                except Exception:
                    return _NO_LITERAL
                if not result:
                    return False
                current = right
            return True

        if isinstance(expression, ast.IfExp):
            truth = self._evaluate_truth(expression.test, env, source)
            if truth is True:
                return self._evaluate_literal(expression.body, env, source)
            if truth is False:
                return self._evaluate_literal(expression.orelse, env, source)
            return _NO_LITERAL

        if isinstance(expression, ast.List):
            values = []
            for item in expression.elts:
                literal = self._evaluate_literal(item, env, source)
                if literal is _NO_LITERAL:
                    return _NO_LITERAL
                values.append(literal)
            return values

        if isinstance(expression, ast.Tuple):
            values = []
            for item in expression.elts:
                literal = self._evaluate_literal(item, env, source)
                if literal is _NO_LITERAL:
                    return _NO_LITERAL
                values.append(literal)
            return tuple(values)

        return _NO_LITERAL

    def _assign_target(
        self,
        env: Dict[str, _AbstractValue],
        target: ast.AST,
        value: _AbstractValue,
    ) -> None:
        if isinstance(target, ast.Name):
            env[target.id] = value.clone()
            return

        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._assign_target(env, element, value)
            return

        if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            container_name = target.value.id
            container = env.get(container_name)
            if container is None or container.kind not in {"dict", "list"}:
                container = _dict_value()
            else:
                container = container.clone()

            key = self._literal_key(target.slice, env, None)
            if container.kind == "dict":
                if key is None:
                    container.whole_taint = True
                else:
                    container.entries[key] = value.clone()
                env[container_name] = container
                return

            if container.kind == "list":
                if not isinstance(key, int):
                    container.whole_taint = True
                else:
                    while len(container.items) <= key:
                        container.items.append(_unknown_value())
                    container.items[key] = value.clone()
                env[container_name] = container

    def _read_target(
        self,
        target: ast.AST,
        env: Dict[str, _AbstractValue],
    ) -> _AbstractValue:
        if isinstance(target, ast.Name):
            return env.get(target.id, _unknown_value()).clone()
        return _unknown_value()

    def _combine_values(
        self,
        left: _AbstractValue,
        right: _AbstractValue,
    ) -> _AbstractValue:
        merged = _merge_values([left, right])
        if merged.kind == "safe" and left.literal is not _NO_LITERAL and right.literal is not _NO_LITERAL:
            try:
                merged.literal = left.literal + right.literal
            except Exception:
                pass
        return merged

    def _container_lookup(
        self,
        container: _AbstractValue,
        key: Any,
    ) -> _AbstractValue:
        if key is None:
            return _tainted_value() if container.whole_taint else _unknown_value()
        if key in container.entries:
            return container.entries[key].clone()
        return _tainted_value() if container.whole_taint else _unknown_value()

    def _config_lookup(
        self,
        container: _AbstractValue,
        section_name: Optional[str],
        option_name: Optional[str],
    ) -> _AbstractValue:
        if section_name is None or option_name is None:
            return _tainted_value() if container.whole_taint else _unknown_value()
        section = container.sections.get(section_name)
        if not section:
            return _tainted_value() if container.whole_taint else _unknown_value()
        if option_name in section:
            return section[option_name].clone()
        return _tainted_value() if container.whole_taint else _unknown_value()

    def _extract_parent_guard_variable(self, expression: ast.AST) -> Optional[str]:
        if not isinstance(expression, ast.Compare):
            return None
        if len(expression.ops) != 1 or len(expression.comparators) != 1:
            return None
        operator = expression.ops[0]
        comparator = expression.comparators[0]
        if not isinstance(operator, ast.In):
            return None
        token = self._literal_string(expression.left, {}, None)
        if token not in self._PARENT_TRAVERSAL_TOKENS:
            return None
        if isinstance(comparator, ast.Name):
            return comparator.id
        return None

    def _apply_guard(
        self,
        env: Dict[str, _AbstractValue],
        variable_name: str,
    ) -> None:
        current = env.get(variable_name, _unknown_value())
        if current.kind == "safe":
            env[variable_name] = current
            return
        if current.kind == "guarded":
            env[variable_name] = current
            return
        if current.literal is not _NO_LITERAL:
            env[variable_name] = _guarded_value(current.literal)
            return
        env[variable_name] = _guarded_value()

    @staticmethod
    def _block_returns(statements: List[ast.stmt]) -> bool:
        return any(isinstance(statement, (ast.Return, ast.Raise)) for statement in ast.walk(ast.Module(body=statements, type_ignores=[])))

    @staticmethod
    def _clone_env(env: Dict[str, _AbstractValue]) -> Dict[str, _AbstractValue]:
        return {name: value.clone() for name, value in env.items()}

    def _merge_envs(
        self,
        envs: Iterable[Dict[str, _AbstractValue]],
    ) -> Dict[str, _AbstractValue]:
        collected = list(envs)
        names = set()
        for env in collected:
            names.update(env.keys())
        return {
            name: _merge_values(
                env.get(name, _unknown_value())
                for env in collected
            )
            for name in names
        }

    def _find_scope_for_line(self, line_number: int):
        if self.module is None:
            return None
        best_scope = self.module
        best_span = getattr(self.module, "end_lineno", 10**9) - getattr(self.module, "lineno", 1)
        for node in ast.walk(self.module):
            if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
                continue
            start_line = getattr(node, "lineno", 0)
            end_line = getattr(node, "end_lineno", start_line)
            if not (start_line <= line_number <= end_line):
                continue
            span = end_line - start_line
            if span <= best_span:
                best_scope = node
                best_span = span
        return best_scope

    @staticmethod
    def _scope_statements(scope) -> List[ast.stmt]:
        return list(getattr(scope, "body", []))

    def _find_sink_call(
        self,
        scope,
        sink_line: int,
        sink: TaintSink,
    ) -> Optional[ast.Call]:
        sink_function = sink.function_name or ""
        sink_leaf = sink_function.rsplit(".", 1)[-1]

        candidates: List[ast.Call] = []
        for node in ast.walk(scope):
            if not isinstance(node, ast.Call):
                continue
            if getattr(node, "lineno", 0) != sink_line:
                continue
            callee = self._render(node.func)
            callee_leaf = callee.rsplit(".", 1)[-1]
            if sink_function and (
                callee == sink_function
                or callee.endswith(f".{sink_leaf}")
                or sink_function.endswith(f".{callee_leaf}")
            ):
                candidates.append(node)

        if not candidates:
            return None

        candidates.sort(
            key=lambda node: len(self._render(node.func)),
            reverse=True,
        )
        return candidates[0]

    def _sink_path_expression(self, call: ast.Call) -> Optional[ast.AST]:
        if isinstance(call.func, ast.Attribute):
            receiver_text = self._render(call.func.value)
            method_name = call.func.attr
            if method_name in {"exists", "is_dir", "is_file", "read_bytes", "read_text"}:
                if call.args:
                    return call.args[0]
                return call.func.value
            if (
                method_name == "open"
            ):
                if receiver_text in self._MODULE_STYLE_OPEN_RECEIVERS and call.args:
                    return call.args[0]
                return call.func.value
        if call.args:
            return call.args[0]
        return None

    @staticmethod
    def _block_contains_line(statements: List[ast.stmt], line_number: int) -> bool:
        return any(
            getattr(statement, "lineno", 0) <= line_number <= getattr(statement, "end_lineno", getattr(statement, "lineno", 0))
            for statement in statements
        )

    def _match_pattern_accepts(self, pattern: ast.pattern, literal: Any) -> bool:
        if isinstance(pattern, ast.MatchAs) and pattern.pattern is None:
            return True
        if isinstance(pattern, ast.MatchValue):
            return self._constant_from_match_value(pattern.value) == literal
        if isinstance(pattern, ast.MatchSingleton):
            return pattern.value == literal
        if isinstance(pattern, ast.MatchOr):
            return any(self._match_pattern_accepts(item, literal) for item in pattern.patterns)
        return False

    @staticmethod
    def _constant_from_match_value(value: ast.AST) -> Any:
        if isinstance(value, ast.Constant):
            return value.value
        return _NO_LITERAL

    def _matches_source_expression(
        self,
        expression: ast.AST,
        source: Optional[TaintSource],
    ) -> bool:
        if source is None:
            return False
        if getattr(expression, "lineno", -1) != source.location.line_number:
            return False
        pattern_head = (source.pattern or "").split("(", 1)[0].strip()
        if not pattern_head:
            return False
        return pattern_head in self._render(expression)

    @staticmethod
    def _render(node: ast.AST) -> str:
        try:
            return ast.unparse(node)
        except Exception:
            return ""

    def _literal_string(
        self,
        expression: Optional[ast.AST],
        env: Dict[str, _AbstractValue],
        source: Optional[TaintSource],
    ) -> Optional[str]:
        if expression is None:
            return None
        literal = self._evaluate_literal(expression, env, source) if source is not None else self._literal_without_source(expression, env)
        return literal if isinstance(literal, str) else None

    def _literal_key(
        self,
        expression: Optional[ast.AST],
        env: Dict[str, _AbstractValue],
        source: Optional[TaintSource],
    ):
        if expression is None:
            return None
        if source is None:
            literal = self._literal_without_source(expression, env)
        else:
            literal = self._evaluate_literal(expression, env, source)
        if literal is _NO_LITERAL:
            return None
        return literal

    def _literal_index(
        self,
        expression: ast.AST,
        env: Dict[str, _AbstractValue],
        source: TaintSource,
    ) -> Optional[int]:
        literal = self._evaluate_literal(expression, env, source)
        return literal if isinstance(literal, int) else None

    def _literal_without_source(
        self,
        expression: ast.AST,
        env: Dict[str, _AbstractValue],
    ):
        return self._evaluate_literal(expression, env, None)
