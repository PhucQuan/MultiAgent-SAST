"""Backend tool-use thật cho lớp multi-agent, đọc mã nguồn Python bằng AST.

`ai/tools/code_tools.py` chỉ định nghĩa interface; khi chưa gắn backend,
mọi tool call trả `success=False` kèm lý do. Module này dựng chỉ mục hàm cùng
flow graph cho một cây thư mục Python rồi gắn vào singleton `code_tools`, để
tool call trả về mã nguồn và đường dataflow thật.

Ngoài ba tool call-graph ban đầu, backend còn phục vụ các semantic tool mà
kết luận TP/FP thực sự dựa vào: `get_dataflow_path`, `get_sanitizer_trace`,
`get_backward_slice`, `get_control_flow_context`, `get_constant_propagation`
và `resolve_symbol`. Chúng dùng lại `PythonFlowGraphBuilder` của Core SAST,
nên bằng chứng agent trích ra đến từ đúng engine đã sinh ra finding.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass, field
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


# Từ khoá nhận diện lời gọi có khả năng là sanitizer. Cố tình rộng: mục tiêu
# là LIỆT KÊ ứng viên cho validator soi, không phải tự quyết định đã an toàn.
SANITIZER_KEYWORDS = (
    "escape", "quote", "sanitiz", "clean", "valid", "encode", "strip",
    "allowlist", "whitelist", "basename", "realpath", "abspath", "normpath",
    "parameteriz", "bind", "int", "float",
)


# Phương thức làm thay đổi nội dung của đối tượng nhận. Danh sách cố tình
# rộng: bỏ sót một phương thức ở đây nghĩa là một biến bị coi nhầm là hằng số.
_MUTATING_METHODS = frozenset({
    "append", "extend", "insert", "add", "update", "setdefault",
    "join", "format", "format_map", "write", "writelines",
    "__setitem__", "__iadd__",
})


def _is_literal_expr(node) -> bool:
    """Biểu thức có phải hằng số thuần không.

    f-string (`JoinedStr`) KHÔNG bao giờ là literal kể cả khi mọi phần tĩnh
    đều là chuỗi: nó tồn tại chính là để nhúng giá trị runtime vào.
    """
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_is_literal_expr(e) for e in node.elts)
    if isinstance(node, ast.BinOp):
        return _is_literal_expr(node.left) and _is_literal_expr(node.right)
    return False


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
        self._graph_cache: dict[str, object] = {}
        self._source_cache: dict[str, list[str]] = {}
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


    # -- semantic tool: dựa trên flow graph của Core SAST -----------------
    def _flow_graph(self, file: str):
        """Flow graph của một file, cache theo đường dẫn.

        Dựng graph tốn vài chục ms mỗi file; agent thường hỏi nhiều tool trên
        cùng một sink nên cache ở đây cắt hẳn phần lặp đó.
        """
        path = str(Path(file).resolve())
        if path in self._graph_cache:
            return self._graph_cache[path]
        try:
            from aegis_sast.analysis.python_flow_graph import PythonFlowGraphBuilder

            text = Path(path).read_text(encoding="utf-8", errors="replace")
            graph = PythonFlowGraphBuilder(Path(path), text).build()
        except Exception:
            graph = None
        self._graph_cache[path] = graph
        return graph

    def _source_lines(self, file: str) -> list[str]:
        path = str(Path(file).resolve())
        if path not in self._source_cache:
            try:
                self._source_cache[path] = Path(path).read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except OSError:
                self._source_cache[path] = []
        return self._source_cache[path]

    def _sink_argument_names(self, file: str, line: int) -> set[str]:
        """Tên biến xuất hiện trong ĐỐI SỐ của lời gọi tại `line`.

        Không dùng `node.reads` của flow graph cho việc này: `reads` gồm cả
        receiver của lời gọi, nên `cur.execute(q)` cho ra {cur, q}. Kiểm tra
        hằng số trên `cur` luôn thất bại (nó là connection object), và khiến
        một sink thực sự an toàn bị kết luận là không ràng buộc.
        """
        lines = self._source_lines(file)
        try:
            tree = ast.parse("\n".join(lines))
        except SyntaxError:
            return set()

        names: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or node.lineno != line:
                continue
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                for sub in ast.walk(arg):
                    if isinstance(sub, ast.Name):
                        names.add(sub.id)
        return names

    def get_dataflow_path(self, file: str, line: int) -> dict:
        """Truy ngược đường dataflow tới câu lệnh tại `file:line`.

        Đi ngược theo cạnh DFG từ node ở sink. Đường trả về là chuỗi câu lệnh
        có thật trong file, mỗi bước kèm số dòng, nên Auditor trích được
        citation kiểm chứng được thay vì mô tả chung chung.
        """
        graph = self._flow_graph(file)
        if graph is None:
            return {"file": file, "line": line, "error": "không dựng được flow graph"}

        sink_node = graph.find_preferred_node(line, ["call", "assign", "return"])
        if sink_node is None:
            return {"file": file, "line": line, "path": [], "note": "không có node nào trên dòng này"}

        # BFS ngược trên DFG, chặn độ sâu để không nuốt cả file.
        incoming: dict[str, list[str]] = {}
        for edge in graph.dfg_edges:
            incoming.setdefault(edge.target_id, []).append(edge.source_id)

        path_ids: list[str] = []
        seen = {sink_node.node_id}
        frontier = [sink_node.node_id]
        for _ in range(12):
            nxt = []
            for nid in frontier:
                for prev in incoming.get(nid, []):
                    if prev in seen:
                        continue
                    seen.add(prev)
                    path_ids.append(prev)
                    nxt.append(prev)
            if not nxt:
                break
            frontier = nxt

        steps = []
        for nid in reversed(path_ids):
            node = graph.nodes.get(nid)
            if node is None or node.kind in {"merge", "function_entry"}:
                continue
            steps.append(
                {
                    "line": node.location.line_number,
                    "kind": node.kind,
                    "label": node.label,
                    "reads": node.reads,
                    "writes": node.writes,
                }
            )
        steps.append(
            {
                "line": sink_node.location.line_number,
                "kind": "sink",
                "label": sink_node.label,
                "reads": sink_node.reads,
                "writes": sink_node.writes,
            }
        )
        return {
            "file": file,
            "line": line,
            "path": steps,
            "step_count": len(steps),
            "reaches_sink": len(steps) > 1,
        }

    def get_sanitizer_trace(self, file: str, line: int) -> dict:
        """Liệt kê lời gọi có thể là sanitizer chi phối sink tại `file:line`.

        Chỉ báo cáo sự kiện quan sát được (có lời gọi tên X ở dòng Y, trước
        sink, cùng biến); việc sanitizer đó có ĐÚNG ngữ cảnh hay không là
        phán đoán dành cho validator/agent, không quyết ở đây.
        """
        graph = self._flow_graph(file)
        if graph is None:
            return {"file": file, "line": line, "error": "không dựng được flow graph"}

        sink_node = graph.find_preferred_node(line, ["call", "assign", "return"])
        if sink_node is None:
            return {"file": file, "line": line, "sanitizers": []}

        tainted_vars = self._sink_argument_names(file, line) or set(sink_node.reads)
        sanitizers = []
        for node in graph.nodes.values():
            if node.kind != "call" or node.location.line_number >= line:
                continue
            callee = (node.callee_name or "").lower()
            if not callee:
                continue
            if any(k in callee for k in SANITIZER_KEYWORDS):
                sanitizers.append(
                    {
                        "line": node.location.line_number,
                        "callee": node.callee_name,
                        "label": node.label,
                        "guards_sink_variable": bool(
                            tainted_vars & (set(node.writes) | set(node.reads))
                        ),
                    }
                )
        return {
            "file": file,
            "line": line,
            "sink_reads": sorted(tainted_vars),
            "sanitizers": sanitizers,
            "sanitizer_count": len(sanitizers),
            "any_guards_sink_variable": any(
                s["guards_sink_variable"] for s in sanitizers
            ),
        }

    def get_backward_slice(self, file: str, line: int, variable: str = "") -> dict:
        """Các câu lệnh phía trên có ghi vào biến mà sink đọc."""
        graph = self._flow_graph(file)
        lines = self._source_lines(file)
        if graph is None:
            return {"file": file, "line": line, "error": "không dựng được flow graph"}

        wanted = {variable} if variable else self._sink_argument_names(file, line)
        if not wanted:
            sink_node = graph.find_preferred_node(line, ["call", "assign", "return"])
            wanted = set(sink_node.reads if sink_node else [])
        if not wanted:
            return {"file": file, "line": line, "slice": [], "note": "sink không đọc biến nào"}

        slice_lines = []
        for node in sorted(graph.nodes.values(), key=lambda n: n.location.line_number):
            if node.location.line_number >= line:
                continue
            if set(node.writes) & wanted:
                ln = node.location.line_number
                slice_lines.append(
                    {
                        "line": ln,
                        "code": lines[ln - 1].strip() if 0 < ln <= len(lines) else node.label,
                        "writes": node.writes,
                        "reads": node.reads,
                    }
                )
                wanted |= set(node.reads)
        return {
            "file": file,
            "line": line,
            "variables": sorted(wanted),
            "slice": slice_lines[-25:],
            "statement_count": len(slice_lines),
        }

    def get_forward_slice(self, file: str, line: int, variable: str = "") -> dict:
        """Giá trị sinh ra tại `line` lan tới những câu lệnh nào phía sau."""
        graph = self._flow_graph(file)
        lines = self._source_lines(file)
        if graph is None:
            return {"file": file, "line": line, "error": "không dựng được flow graph"}

        origin = graph.find_preferred_node(line, ["assign", "call", "parameter"])
        tainted = {variable} if variable else set(origin.writes if origin else [])
        if not tainted:
            return {"file": file, "line": line, "slice": []}

        reached = []
        for node in sorted(graph.nodes.values(), key=lambda n: n.location.line_number):
            if node.location.line_number <= line:
                continue
            if set(node.reads) & tainted:
                ln = node.location.line_number
                reached.append(
                    {
                        "line": ln,
                        "code": lines[ln - 1].strip() if 0 < ln <= len(lines) else node.label,
                        "kind": node.kind,
                        "callee": node.callee_name,
                    }
                )
                tainted |= set(node.writes)
        return {
            "file": file,
            "line": line,
            "variables": sorted(tainted),
            "slice": reached[:25],
            "statement_count": len(reached),
        }

    def get_control_flow_context(self, file: str, line: int) -> dict:
        """Guard bao quanh sink: điều kiện `if`, `match`, early return.

        Đây là bằng chứng quyết định cho nhóm false positive lớn nhất — sink
        nằm trong nhánh chỉ đạt tới khi giá trị đã thuộc một tập hữu hạn.
        """
        lines = self._source_lines(file)
        try:
            tree = ast.parse("\n".join(lines))
        except SyntaxError as e:
            return {"file": file, "line": line, "error": f"parse lỗi: {e}"}

        guards = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.If, ast.Match, ast.While, ast.For, ast.Try)):
                continue
            start = node.lineno
            end = getattr(node, "end_lineno", start) or start
            if not (start <= line <= end):
                continue
            kind = type(node).__name__.lower()
            test_src = ""
            if isinstance(node, ast.If) and node.test is not None:
                test_src = ast.unparse(node.test)
            elif isinstance(node, ast.Match):
                test_src = ast.unparse(node.subject)
            guards.append(
                {
                    "line": start,
                    "kind": kind,
                    "condition": test_src,
                    "dominates_sink": True,
                    "enclosing": True,
                    "code": lines[start - 1].strip() if 0 < start <= len(lines) else "",
                }
            )

        early_returns = self._early_return_guards(tree, lines, line)
        guards.extend(early_returns)

        return {
            "file": file,
            "line": line,
            "guards": guards,
            "guard_count": len(guards),
            "enclosing_branch": any(g.get("enclosing") for g in guards),
            "early_return_guards": early_returns,
            "guarded_by_early_return": bool(early_returns),
        }

    def _early_return_guards(self, tree, lines: list[str], line: int) -> list[dict]:
        """Guard dạng `if <điều kiện xấu>: return` nằm TRƯỚC sink.

        Mẫu này chi phối sink bằng cách thoát sớm chứ không bao bọc nó, nên
        cách tìm guard thông thường (khối chứa dòng sink) hoàn toàn bỏ sót.
        Đây lại là cách viết phòng thủ phổ biến nhất trong mã thật: kiểm tra
        đầu vào, trả lời lỗi rồi `return`, phần còn lại của hàm coi như đã an
        toàn.

        Chỉ tính là guard khi hội đủ ba điều kiện: nằm cùng hàm với sink, thân
        `if` kết thúc bằng `return`/`raise` vô điều kiện, và điều kiện kiểm tra
        có đọc một biến mà sink cũng đọc. Thiếu điều kiện thứ ba thì đó chỉ là
        một lần thoát sớm vì lý do khác, không liên quan tới dữ liệu vào sink.
        """
        sink_vars = self._sink_argument_names_from_tree(tree, line)
        if not sink_vars:
            return []

        enclosing = None
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            end = getattr(node, "end_lineno", node.lineno) or node.lineno
            if node.lineno <= line <= end:
                # Hàm lồng nhau: lấy hàm gần nhất bao quanh sink.
                if enclosing is None or node.lineno > enclosing.lineno:
                    enclosing = node
        if enclosing is None:
            return []

        found = []
        for node in ast.walk(enclosing):
            if not isinstance(node, ast.If) or node.lineno >= line:
                continue
            exits = node.body and isinstance(node.body[-1], (ast.Return, ast.Raise))
            if not exits:
                continue
            test_vars = {
                sub.id for sub in ast.walk(node.test) if isinstance(sub, ast.Name)
            }
            if not (test_vars & sink_vars):
                continue
            found.append(
                {
                    "line": node.lineno,
                    "kind": "early_return",
                    "condition": ast.unparse(node.test)[:300],
                    "dominates_sink": True,
                    "enclosing": False,
                    "checked_variables": sorted(test_vars & sink_vars),
                    "code": lines[node.lineno - 1].strip()
                    if 0 < node.lineno <= len(lines)
                    else "",
                }
            )
        return found

    @staticmethod
    def _sink_argument_names_from_tree(tree, line: int) -> set[str]:
        """Như `_sink_argument_names` nhưng dùng lại cây AST đã parse."""
        names: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or node.lineno != line:
                continue
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                for sub in ast.walk(arg):
                    if isinstance(sub, ast.Name):
                        names.add(sub.id)
        return names

    def get_constant_propagation(self, file: str, line: int, variable: str = "") -> dict:
        """Giá trị tại sink có bị ràng buộc về hằng số/tập hữu hạn không.

        Chỉ khẳng định `constant_bound=True` khi MỌI phép gán tới biến đó mà
        tìm thấy đều là literal. Một phép gán không phải literal là đủ để kết
        luận không ràng buộc — thà bỏ sót cơ hội suppress còn hơn suppress sai.
        """
        graph = self._flow_graph(file)
        lines = self._source_lines(file)
        if graph is None:
            return {"file": file, "line": line, "error": "không dựng được flow graph"}

        wanted = {variable} if variable else self._sink_argument_names(file, line)
        if not wanted:
            sink_node = graph.find_preferred_node(line, ["call", "assign", "return"])
            wanted = set(sink_node.reads if sink_node else [])
        if not wanted:
            return {"file": file, "line": line, "constant_bound": False, "assignments": []}

        try:
            tree = ast.parse("\n".join(lines))
        except SyntaxError as e:
            return {"file": file, "line": line, "error": f"parse lỗi: {e}"}

        assignments = []
        mutations = []
        for node in ast.walk(tree):
            if getattr(node, "lineno", line) >= line:
                continue

            # Gán thường: `x = <giá trị>`
            if isinstance(node, ast.Assign):
                names = {t.id for t in node.targets if isinstance(t, ast.Name)}
                if names & wanted:
                    assignments.append(
                        {
                            "line": node.lineno,
                            "target": sorted(names & wanted),
                            "value": ast.unparse(node.value)[:200],
                            "is_literal": _is_literal_expr(node.value),
                        }
                    )
                continue

            # Gán cộng dồn: `x += <giá trị>`. Bỏ sót nhánh này là lỗi nguy
            # hiểm nhất của kiểm tra hằng số — `s = ""` rồi `s += f"...{bẩn}"`
            # trông như một biến chỉ nhận literal, trong khi nó vừa nuốt trọn
            # dữ liệu do người dùng kiểm soát.
            if isinstance(node, ast.AugAssign):
                target = node.target
                if isinstance(target, ast.Name) and target.id in wanted:
                    assignments.append(
                        {
                            "line": node.lineno,
                            "target": [target.id],
                            "value": f"{ast.unparse(node.op).strip() if hasattr(ast, 'unparse') else '+'}= "
                            + ast.unparse(node.value)[:200],
                            "is_literal": _is_literal_expr(node.value),
                            "augmented": True,
                        }
                    )
                continue

            # Lời gọi làm thay đổi nội dung: `x.append(...)`, `x.extend(...)`.
            # Cùng lý do: danh sách khởi tạo bằng literal vẫn có thể được nối
            # thêm dữ liệu bẩn mà không có phép gán nào lên chính tên biến.
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                receiver = node.func.value
                if (
                    isinstance(receiver, ast.Name)
                    and receiver.id in wanted
                    and node.func.attr in _MUTATING_METHODS
                ):
                    args_literal = all(_is_literal_expr(a) for a in node.args)
                    mutations.append(
                        {
                            "line": node.lineno,
                            "target": receiver.id,
                            "method": node.func.attr,
                            "value": ast.unparse(node)[:200],
                            "is_literal": args_literal,
                        }
                    )

        all_writes = assignments + mutations
        return {
            "file": file,
            "line": line,
            "variables": sorted(wanted),
            "assignments": assignments,
            "mutations": mutations,
            # Ràng buộc hằng số chỉ thành lập khi MỌI phép ghi tới biến đều là
            # literal. Một phép ghi không phải literal là đủ để kết luận không
            # ràng buộc — thà bỏ lỡ cơ hội suppress còn hơn suppress nhầm.
            "constant_bound": bool(all_writes) and all(w["is_literal"] for w in all_writes),
        }

    def resolve_symbol(self, symbol: str, file: str = "") -> dict:
        """Mọi định nghĩa trùng tên `symbol`, để phân biệt hàm cùng tên."""
        records = self.by_name.get(symbol) or []
        definitions = [
            {"file": r.file, "line": r.start_line, "end_line": r.end_line}
            for r in records
        ]
        return {
            "symbol": symbol,
            "definitions": definitions,
            "definition_count": len(definitions),
            "ambiguous": len(definitions) > 1,
            "queried_from": file,
        }


def bind_python_backend(root: Path, max_files: int | None = None) -> PythonCodeToolsBackend:
    """Dựng chỉ mục rồi gắn toàn bộ tool vào singleton `code_tools`."""
    from ai.tools.code_tools import code_tools

    backend = PythonCodeToolsBackend(root, max_files=max_files)
    code_tools.bind(
        get_callers=backend.get_callers,
        get_callees=backend.get_callees,
        get_body=backend.get_function_body,
        get_dataflow_path=backend.get_dataflow_path,
        get_sanitizer_trace=backend.get_sanitizer_trace,
        get_backward_slice=backend.get_backward_slice,
        get_forward_slice=backend.get_forward_slice,
        get_control_flow_context=backend.get_control_flow_context,
        get_constant_propagation=backend.get_constant_propagation,
        resolve_symbol=backend.resolve_symbol,
    )
    return backend
