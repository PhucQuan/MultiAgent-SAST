"""Backend tool-use thật cho lớp multi-agent, đọc mã nguồn Python bằng AST.

`ai/tools/code_tools.py` chỉ định nghĩa interface; mặc định nó trả về mock
(`// mock: <tên hàm>`). Với mock đó Auditor không đọc được dòng code nào nên
không thể phản bác giả thuyết — mọi finding đều thành true positive.

Module này dựng chỉ mục hàm cho một cây thư mục Python rồi gắn vào singleton
`code_tools`, để tool call trả về mã nguồn thật.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FunctionRecord:
    name: str
    file: str
    start_line: int
    end_line: int
    source: str
    calls: list[str] = field(default_factory=list)


class _CallCollector(ast.NodeVisitor):
    """Thu tên các hàm được gọi bên trong một thân hàm."""

    def __init__(self) -> None:
        self.names: list[str] = []

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Name):
            self.names.append(func.id)
        elif isinstance(func, ast.Attribute):
            self.names.append(func.attr)
        self.generic_visit(node)


class PythonCodeToolsBackend:
    """Chỉ mục hàm Python phục vụ get_callers / get_callees / get_function_body."""

    def __init__(self, root: Path, max_files: int | None = None):
        self.root = Path(root)
        self.by_name: dict[str, list[FunctionRecord]] = {}
        self._index(max_files)

    def _index(self, max_files: int | None) -> None:
        files = sorted(self.root.rglob("*.py"))
        if max_files:
            files = files[:max_files]
        for path in files:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(text)
            except (SyntaxError, OSError):
                continue
            lines = text.splitlines()
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                start = node.lineno
                end = getattr(node, "end_lineno", start) or start
                collector = _CallCollector()
                for child in node.body:
                    collector.visit(child)
                record = FunctionRecord(
                    name=node.name,
                    file=str(path),
                    start_line=start,
                    end_line=end,
                    source="\n".join(
                        f"{i}: {lines[i - 1]}"
                        for i in range(start, min(end, len(lines)) + 1)
                    ),
                    calls=sorted(set(collector.names)),
                )
                self.by_name.setdefault(node.name, []).append(record)

    @property
    def function_count(self) -> int:
        return sum(len(v) for v in self.by_name.values())

    # -- ba tool mà registry expose ---------------------------------------
    def get_function_body(self, function_name: str) -> str:
        records = self.by_name.get(function_name)
        if not records:
            return f"KHÔNG TÌM THẤY hàm tên '{function_name}' trong cây mã nguồn đã lập chỉ mục."
        out = []
        for r in records[:3]:
            out.append(f"# {r.file}:{r.start_line}-{r.end_line}\n{r.source}")
        return "\n\n".join(out)

    def get_callees(self, function_name: str) -> list[str]:
        records = self.by_name.get(function_name) or []
        names: set[str] = set()
        for r in records:
            names.update(r.calls)
        return sorted(names)

    def get_callers(self, function_name: str) -> list[str]:
        callers = []
        for name, records in self.by_name.items():
            for r in records:
                if function_name in r.calls:
                    callers.append(f"{name} ({r.file}:{r.start_line})")
                    break
        return sorted(callers)


def bind_python_backend(root: Path, max_files: int | None = None) -> PythonCodeToolsBackend:
    """Dựng chỉ mục rồi gắn vào singleton `code_tools` của lớp multi-agent."""
    from ai.tools.code_tools import code_tools

    backend = PythonCodeToolsBackend(root, max_files=max_files)
    code_tools.bind(
        get_callers=backend.get_callers,
        get_callees=backend.get_callees,
        get_body=backend.get_function_body,
    )
    return backend
