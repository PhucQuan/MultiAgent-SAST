"""Test Task 5 — tool-use layer."""

import json

from ai.tools.code_tools import CodeToolsInterface, code_tools, make_mock_tools
from ai.tools.registry import MAX_TOOL_CALLS, TOOL_DEFINITIONS, dispatch_tool_call


def test_tool_call_budget_is_five():
    assert MAX_TOOL_CALLS == 5


def test_call_graph_tools_still_registered():
    names = {t["function"]["name"] for t in TOOL_DEFINITIONS}
    assert {"get_callers", "get_callees", "get_function_body"} <= names


def test_semantic_tools_registered():
    """Các tool mà kết luận TP/FP dựa vào phải có mặt trong allowlist."""
    names = {t["function"]["name"] for t in TOOL_DEFINITIONS}
    assert {
        "get_dataflow_path",
        "get_sanitizer_trace",
        "get_backward_slice",
        "get_constant_propagation",
        "get_control_flow_context",
    } <= names


def test_every_tool_declares_required_args():
    for t in TOOL_DEFINITIONS:
        params = t["function"]["parameters"]
        assert params["required"], t["function"]["name"]
        for arg in params["required"]:
            assert arg in params["properties"]


def test_unbound_tool_fails_loudly_instead_of_returning_empty():
    """Tool chưa gắn backend phải báo lỗi, không được trả [] như thật.

    Một `get_callers` trả [] vì backend chưa gắn sẽ bị agent đọc thành "không
    ai gọi hàm này" — tức là bằng chứng giả dẫn tới suppress sai.
    """
    tools = CodeToolsInterface()
    r = tools.get_callers("do_query")
    assert r.success is False
    assert "chưa được gắn" in r.error
    assert r.data is None


def test_explicit_mock_returns_success():
    tools = make_mock_tools()
    r = tools.get_callers("do_query")
    assert r.success is True
    assert r.data == []


def test_bound_backend_is_used():
    tools = CodeToolsInterface(
        get_callers=lambda n: [f"caller_of_{n}"],
        get_body=lambda n: f"def {n}(): pass",
    )
    assert tools.get_callers("f").data == ["caller_of_f"]
    assert tools.get_function_body("f").data == "def f(): pass"


def test_backend_exception_becomes_failed_result():
    def boom(_):
        raise RuntimeError("call graph chưa dựng")

    tools = CodeToolsInterface(get_callees=boom)
    r = tools.get_callees("f")
    assert r.success is False
    assert "call graph" in r.error


def test_dispatch_unknown_tool():
    out = json.loads(dispatch_tool_call("rm_rf", {"function_name": "x"}))
    assert "unknown tool" in out["error"]


def test_dispatch_missing_argument():
    out = json.loads(dispatch_tool_call("get_callers", {}))
    assert "missing argument" in out["error"]


def test_dispatch_known_tool_returns_tool_result_json(monkeypatch):
    import ai.tools.registry as registry

    monkeypatch.setattr(registry, "code_tools", make_mock_tools())
    out = json.loads(dispatch_tool_call("get_function_body", {"function_name": "q"}))
    assert out["success"] is True
    assert "mock: q" in out["data"]


def test_dispatch_rejects_tool_outside_allowlist():
    """Tên tool bịa ra bị từ chối thẳng, không đoán tool gần giống."""
    out = json.loads(dispatch_tool_call("execute_shell", {"cmd": "rm -rf /"}))
    assert out["success"] is False
    assert "unknown tool" in out["error"]


def test_dispatch_drops_unexpected_arguments():
    """Tham số lạ do model thêm vào bị loại, không truyền xuống backend."""
    import ai.tools.registry as registry

    seen = {}

    def spy(function_name):
        seen["function_name"] = function_name
        return "body"

    tools = make_mock_tools(get_function_body=spy)
    registry.code_tools = tools
    try:
        out = json.loads(
            dispatch_tool_call(
                "get_function_body", {"function_name": "q", "shell": "rm -rf /"}
            )
        )
    finally:
        from ai.tools.code_tools import code_tools as real

        registry.code_tools = real
    assert out["success"] is True
    assert seen == {"function_name": "q"}
