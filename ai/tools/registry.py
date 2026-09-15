"""Khai báo tool theo định dạng OpenAI function calling cho NVIDIA NIM."""

import json

from .code_tools import code_tools

# Giới hạn: tối đa 5 tool call/finding để tránh loop vô tận (mục 7 của guide).
MAX_TOOL_CALLS = 5

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "get_callers",
            "description": "Trả về danh sách hàm gọi function_name.",
            "parameters": {
                "type": "object",
                "properties": {"function_name": {"type": "string"}},
                "required": ["function_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_callees",
            "description": "Trả về danh sách hàm bị function_name gọi.",
            "parameters": {
                "type": "object",
                "properties": {"function_name": {"type": "string"}},
                "required": ["function_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_function_body",
            "description": "Trả về source code của function_name.",
            "parameters": {
                "type": "object",
                "properties": {"function_name": {"type": "string"}},
                "required": ["function_name"],
            },
        },
    },
]


def dispatch_tool_call(name: str, args: dict) -> str:
    """Thực thi một tool call và trả JSON để nhét lại vào message list."""
    try:
        if name == "get_callers":
            r = code_tools.get_callers(args["function_name"])
        elif name == "get_callees":
            r = code_tools.get_callees(args["function_name"])
        elif name == "get_function_body":
            r = code_tools.get_function_body(args["function_name"])
        else:
            return json.dumps({"error": f"unknown tool: {name}"})
    except KeyError as e:
        return json.dumps({"error": f"missing argument: {e}"})
    return json.dumps(r.model_dump(), ensure_ascii=False)
