"""Tool-use layer."""

from .actions import (
    EVIDENCE_ACTIONS,
    TERMINAL_ACTIONS,
    InvestigationAction,
    coerce,
)
from .code_tools import CodeToolsInterface, ToolResult, code_tools
from .registry import (
    MAX_TOOL_CALLS,
    TOOL_DEFINITIONS,
    TOOL_NAMES,
    dispatch_tool_call,
)

__all__ = [
    "CodeToolsInterface",
    "ToolResult",
    "code_tools",
    "MAX_TOOL_CALLS",
    "TOOL_DEFINITIONS",
    "TOOL_NAMES",
    "dispatch_tool_call",
    "InvestigationAction",
    "EVIDENCE_ACTIONS",
    "TERMINAL_ACTIONS",
    "coerce",
]
