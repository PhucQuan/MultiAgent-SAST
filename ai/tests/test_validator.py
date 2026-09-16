"""Test validator tất định trên mã nguồn Python thật.

Các test ở đây cố tình KHÔNG mock tool: chúng chạy backend AST/flow-graph trên
file nguồn viết ra trong tmp_path. Mock hoá phần này sẽ làm mất đúng thứ cần
kiểm chứng — rằng bằng chứng validator đưa ra đến từ phân tích chương trình
thật, không phải từ một bảng tra cứu.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
for _p in (REPO_ROOT, REPO_ROOT / "scripts"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from ai.nodes.validator import validator_node  # noqa: E402
from ai.schemas.finding import (  # noqa: E402
    DataFlowStep,
    EvidenceBundle,
    Language,
    Location,
    NormalizedFinding,
)
from ai.schemas.state import GraphState  # noqa: E402

UNSAFE_SOURCE = '''import sqlite3
from flask import request


def unsafe_lookup():
    raw = request.args.get('name')
    conn = sqlite3.connect('db')
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + raw + "'")
    return cur.fetchall()
'''

SAFE_SOURCE = '''import sqlite3
from flask import request


def safe_sort():
    choice = request.args.get('sort')
    if choice == 'name':
        column = 'name'
    elif choice == 'age':
        column = 'age'
    else:
        column = 'id'
    conn = sqlite3.connect('db')
    cur = conn.cursor()
    cur.execute("SELECT * FROM users ORDER BY " + column)
    return cur.fetchall()
'''


def _finding(file: str, source_line: int, sink_line: int) -> NormalizedFinding:
    return NormalizedFinding(
        finding_id="v-001",
        vuln_type="SQL_INJECTION",
        cwe="CWE-89",
        language=Language.PYTHON,
        severity="high",
        confidence=0.7,
        evidence=EvidenceBundle(
            source=Location(file=file, line=source_line, code_slice="request.args.get"),
            sink=Location(file=file, line=sink_line, code_slice="cur.execute"),
            data_flow_path=[
                DataFlowStep(file=file, line=source_line, kind="source", code="request.args.get"),
                DataFlowStep(file=file, line=sink_line, kind="sink", code="cur.execute"),
            ],
            evidence_quality=0.8,
        ),
    )


@pytest.fixture
def bound_backend(tmp_path, monkeypatch):
    """Gắn backend thật lên một cây mã nguồn tạm."""
    from python_code_tools_backend import PythonCodeToolsBackend
    from ai.tools.code_tools import CodeToolsInterface
    import ai.nodes.validator as validator_mod

    def _bind(files: dict[str, str]) -> Path:
        for name, text in files.items():
            (tmp_path / name).write_text(text, encoding="utf-8")
        backend = PythonCodeToolsBackend(tmp_path)
        tools = CodeToolsInterface()
        tools.bind(
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
        monkeypatch.setattr(validator_mod, "code_tools", tools)
        return tmp_path

    return _bind


def test_validator_confirms_real_dataflow(bound_backend):
    root = bound_backend({"unsafe.py": UNSAFE_SOURCE})
    file = str(root / "unsafe.py")
    state = GraphState(finding=_finding(file, 6, 9))

    out = validator_node(state)
    assessment = out.validator_assessment

    assert assessment.dataflow_confirmed is True
    assert assessment.constant_bound is False
    assert assessment.proved_safe_pattern is False
    # Bằng chứng phải được ghi vào ledger với đủ provenance.
    assert assessment.evidence_ids
    artifact = out.evidence.get(assessment.evidence_ids[0])
    assert artifact.producer.startswith("validator/")
    assert artifact.content_hash.startswith("sha256:")


def test_validator_proves_constant_bound_case_safe(bound_backend):
    """Ca an toàn thật: biến tại sink chỉ nhận một trong ba literal.

    Đây là loại false positive mà không lượng tranh luận nào giữa hai mô hình
    giải quyết được — chỉ phân tích hằng số trả lời dứt điểm.
    """
    root = bound_backend({"safe.py": SAFE_SOURCE})
    file = str(root / "safe.py")
    state = GraphState(finding=_finding(file, 6, 15))

    out = validator_node(state)
    assessment = out.validator_assessment

    assert assessment.constant_bound is True
    assert assessment.proved_safe_pattern is True
    assert assessment.sink_reachable is False
    # Sink nằm SAU khối if chứ không nằm trong nó, nên không có guard nào bao
    # quanh sink. Tính an toàn ở đây đến từ ràng buộc hằng số của biến, và
    # phân biệt này quan trọng: hai cơ chế cần hai loại bằng chứng khác nhau.
    assert assessment.guarded_by_control_flow is False


def test_validator_reports_unavailable_tools_instead_of_guessing():
    """Không có backend thì validator phải nói rõ, không được kết luận an toàn."""
    from ai.tools.code_tools import CodeToolsInterface
    import ai.nodes.validator as validator_mod

    original = validator_mod.code_tools
    validator_mod.code_tools = CodeToolsInterface()
    try:
        state = GraphState(finding=_finding("khong_ton_tai.py", 1, 2))
        out = validator_node(state)
    finally:
        validator_mod.code_tools = original

    assessment = out.validator_assessment
    assert assessment.proved_safe_pattern is False
    assert assessment.tools_unavailable
    assert any("chưa gắn backend" in note for note in assessment.notes)
    # Vẫn dùng được evidence của Core SAST để trả lời câu hỏi dataflow.
    assert assessment.dataflow_confirmed is True


# --- các mẫu mà validator từng kết luận sai ------------------------------
AUGMENTED_SOURCE = '''import subprocess
from flask import request


def build_command():
    bar = request.args.get('cmd')
    argStr = ""
    if True:
        argStr = "sh -c "
    argStr += f"echo {bar}"
    proc = subprocess.run(argStr, shell=True)
    return proc
'''

MUTATED_LIST_SOURCE = '''import subprocess
from flask import request


def build_args():
    bar = request.args.get('cmd')
    argList = []
    argList.append("sh")
    argList.append("-c")
    argList.append(f"echo {bar}")
    proc = subprocess.run(argList)
    return proc
'''

EARLY_RETURN_SOURCE = '''from flask import request


def guarded_exec():
    param = request.args.get('p')
    bar = param
    if not bar.startswith("'") or not bar.endswith("'"):
        return "Chỉ chấp nhận chuỗi literal."
    exec(bar)
    return "ok"
'''


def test_augmented_assignment_is_not_constant_bound(bound_backend):
    """`s = ""` rồi `s += f"...{bẩn}"` KHÔNG phải ràng buộc hằng số.

    Đây là ca validator từng kết luận sai: chỉ xét `ast.Assign` nên phép gán
    cộng dồn nuốt trọn dữ liệu người dùng mà không để lại dấu vết nào, và một
    command injection thật bị chứng nhận là an toàn.
    """
    root = bound_backend({"aug.py": AUGMENTED_SOURCE})
    file = str(root / "aug.py")
    state = GraphState(finding=_finding(file, 6, 11))

    assessment = validator_node(state).validator_assessment
    assert assessment.constant_bound is False
    assert assessment.proved_safe_pattern is False


def test_mutating_call_is_not_constant_bound(bound_backend):
    """`lst = []` rồi `lst.append(f"...{bẩn}")` cũng không phải hằng số."""
    root = bound_backend({"mut.py": MUTATED_LIST_SOURCE})
    file = str(root / "mut.py")
    state = GraphState(finding=_finding(file, 6, 11))

    assessment = validator_node(state).validator_assessment
    assert assessment.constant_bound is False
    assert assessment.proved_safe_pattern is False


def test_early_return_guard_counts_as_proof_of_safety(bound_backend):
    """Guard thoát sớm kiểm tra đúng biến của sink là bằng chứng an toàn.

    Mẫu `if <điều kiện xấu>: return` chi phối sink bằng cách thoát sớm chứ
    không bao bọc nó, nên cách tìm guard theo khối chứa dòng sink bỏ sót hoàn
    toàn — dù đây là cách viết phòng thủ phổ biến nhất trong mã thật.
    """
    root = bound_backend({"guard.py": EARLY_RETURN_SOURCE})
    file = str(root / "guard.py")
    state = GraphState(finding=_finding(file, 5, 9))

    assessment = validator_node(state).validator_assessment
    assert assessment.guarded_by_early_return is True
    assert assessment.proved_safe_pattern is True
