"""Test Task 5 — tool-use layer."""

import json

from ai.tools.code_tools import CodeToolsInterface, code_tools
from ai.tools.registry import MAX_TOOL_CALLS, TOOL_DEFINITIONS, dispatch_tool_call


def test_tool_call_budget_is_five():
    assert MAX_TOOL_CALLS == 5


def test_three_tools_registered():
    names = {t["function"]["name"] for t in TOOL_DEFINITIONS}
    assert names == {"get_callers", "get_callees", "get_function_body"}
    for t in TOOL_DEFINITIONS:
        assert t["function"]["parameters"]["required"] == ["function_name"]


def test_mock_backend_returns_success():
    r = code_tools.get_callers("do_query")
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


def test_dispatch_known_tool_returns_tool_result_json():
    out = json.loads(dispatch_tool_call("get_function_body", {"function_name": "q"}))
    assert out["success"] is True
    assert "mock: q" in out["data"]
