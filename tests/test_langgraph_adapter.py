"""Tests for the optional LangGraph adapter."""

import importlib.util

import pytest

from aegis_sast.orchestration.langgraph_adapter import (
    LangGraphUnavailable,
    build_langgraph_workflow,
)


def test_langgraph_adapter_fails_clearly_when_dependency_missing():
    if importlib.util.find_spec("langgraph") is not None:
        pytest.skip("langgraph is installed in this environment")

    with pytest.raises(LangGraphUnavailable) as error:
        build_langgraph_workflow()

    assert "LangGraph is not installed" in str(error.value)
