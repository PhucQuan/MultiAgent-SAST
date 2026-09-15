"""Fixture dùng chung: settings giả, LLM giả, finding mẫu.

Không test nào trong thư mục này gọi ra mạng. Toàn bộ lời gọi LLM đều bị thay
bằng fake để kết quả tái lập được.
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ai import config as config_module  # noqa: E402
from ai.llm.nvidia_client import llm_client  # noqa: E402
from ai.schemas.finding import (  # noqa: E402
    DataFlowStep,
    EvidenceBundle,
    Language,
    Location,
    NormalizedFinding,
)
from ai.schemas.hypothesis import (  # noqa: E402
    Assumption,
    StructuredHypothesis,
    TriggerPathNode,
)
from ai.schemas.verdict import AgentVerdict, JudgeDecision, TriageState  # noqa: E402

ENV = {
    "NVIDIA_API_KEY": "nvapi-test-key",
    "NVIDIA_BASE_URL": "https://integrate.api.nvidia.com/v1",
    "AEGIS_MODEL_HYPOTHESIS": "qwen/qwen3-coder-480b-a35b-instruct",
    "AEGIS_MODEL_AUDITOR": "qwen/qwen3-coder-480b-a35b-instruct",
    "AEGIS_MODEL_SKEPTIC": "deepseek-ai/deepseek-v3.1",
    "AEGIS_MODEL_JUDGE": "nvidia/llama-3.3-nemotron-super-49b-v1.5",
    "AEGIS_MODEL_FALLBACK": "meta/llama-3.1-405b-instruct,mistralai/mistral-large-3-675b-instruct-2512",
    "AEGIS_TEMP_HYPOTHESIS": "0.5",
    "AEGIS_TEMP_AUDITOR": "0.3",
    "AEGIS_TEMP_SKEPTIC": "0.0",
    "AEGIS_TEMP_JUDGE": "0.0",
    "AEGIS_MAX_TOKENS": "2048",
    "AEGIS_TIMEOUT_SEC": "60",
    "AEGIS_MAX_RETRIES": "3",
    "AEGIS_DEBATE_ROUND_MAX": "3",
}


@pytest.fixture(autouse=True)
def env_settings(monkeypatch, tmp_path):
    """Nạp settings giả và cô lập cache LLM vào tmp_path cho mỗi test.

    Chặn luôn việc đọc `.env` thật: nếu không, kết quả test phụ thuộc vào cấu
    hình trên máy lập trình viên và API key thật bị kéo vào test.
    """
    monkeypatch.setitem(config_module.Settings.model_config, "env_file", ())
    for k in ("NVIDIA_API_KEYS", "AEGIS_SEED", "AEGIS_SKIP_SKEPTIC_CONFIDENCE"):
        monkeypatch.delenv(k, raising=False)
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("AEGIS_CACHE_DIR", str(tmp_path / "llm-cache"))
    config_module.reset_settings()
    llm_client._client = None
    llm_client._cache = None
    llm_client.usage_log.clear()
    yield
    config_module.reset_settings()
    llm_client._client = None
    llm_client._cache = None
    llm_client.usage_log.clear()


# --------------------------------------------------------------------------
# Dữ liệu mẫu
# --------------------------------------------------------------------------
def make_finding(
    language=Language.PHP,
    cwe="CWE-89",
    evidence_quality=0.8,
    finding_id="test-001",
) -> NormalizedFinding:
    return NormalizedFinding(
        finding_id=finding_id,
        vuln_type="SQL_INJECTION",
        cwe=cwe,
        language=language,
        severity="high",
        confidence=0.7,
        evidence=EvidenceBundle(
            source=Location(
                file="app.php", line=10, code_slice="$name = $_POST['name']; //potential"
            ),
            sink=Location(
                file="app.php",
                line=20,
                code_slice="mysqli_query($conn, \"SELECT * FROM users WHERE name = '$name'\"); //potential",
            ),
            data_flow_path=[
                DataFlowStep(
                    file="app.php", line=10, kind="source", code="$_POST['name']"
                ),
                DataFlowStep(
                    file="app.php", line=20, kind="sink", code="mysqli_query(...)"
                ),
            ],
            evidence_quality=evidence_quality,
        ),
    )


@pytest.fixture
def finding():
    return make_finding()


@pytest.fixture
def hypothesis():
    return StructuredHypothesis(
        assumptions=[
            Assumption(id="A1", text="$_POST['name'] do người dùng kiểm soát")
        ],
        trigger_path=[
            TriggerPathNode(file="app.php", line=20, description="Ghép chuỗi vào query")
        ],
    )


def verdict(exploitable=True, confidence=0.9) -> AgentVerdict:
    return AgentVerdict(
        reasoning="Ghép chuỗi trực tiếp từ $_POST vào mysqli_query.",
        grounded_citations=["app.php:20"],
        exploitable=exploitable,
        confidence=confidence,
    )


def judge_decision(state=TriageState.CONFIRMED, confidence=0.9) -> JudgeDecision:
    return JudgeDecision(
        reasoning="Auditor và Skeptic đồng thuận, evidence đủ.",
        correctness_score=0.9,
        severity_score=0.8,
        exploitability_score=0.9,
        triage_state=state,
        confidence=confidence,
    )


# --------------------------------------------------------------------------
# LLM giả
# --------------------------------------------------------------------------
class FakeStructuredLLM:
    """Thay `llm_client.call_structured` bằng bảng tra theo tên schema.

    Giá trị của bảng có thể là một object, một list (hàng đợi theo lượt gọi),
    hoặc None để mô phỏng LLM hỏng.
    """

    def __init__(self, responses: dict):
        self.responses = responses
        self.calls: list[dict] = []

    def __call__(self, model, messages, schema, temperature=0.0, use_cache=True):
        self.calls.append(
            {
                "model": model,
                "schema": schema.__name__,
                "messages": messages,
                "temperature": temperature,
            }
        )
        value = self.responses.get(schema.__name__, None)
        if isinstance(value, list):
            if not value:
                return None
            return value.pop(0)
        return value


@pytest.fixture
def fake_structured(monkeypatch):
    def _install(responses: dict) -> FakeStructuredLLM:
        fake = FakeStructuredLLM(responses)
        monkeypatch.setattr(llm_client, "call_structured", fake)
        return fake

    return _install


class FakeMessage:
    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls


class FakeChoice:
    def __init__(self, message):
        self.message = message


class FakeResponse:
    def __init__(self, message, usage=None):
        self.choices = [FakeChoice(message)]
        self.usage = usage


class FakeUsage:
    def __init__(self, prompt_tokens=10, completion_tokens=20):
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens


class FakeToolCall:
    """Bắt chước tool_call của OpenAI SDK (có .model_dump())."""

    def __init__(self, call_id, name, arguments):
        self.id = call_id
        self.type = "function"
        self.function = type(
            "Fn", (), {"name": name, "arguments": arguments}
        )()

    def model_dump(self):
        return {
            "id": self.id,
            "type": "function",
            "function": {
                "name": self.function.name,
                "arguments": self.function.arguments,
            },
        }


class FakeOpenAIClient:
    """Client giả cho tool-use loop của Auditor."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list[dict] = []
        client = self

        class _Completions:
            def create(self, **kwargs):
                client.calls.append(kwargs)
                if client._responses:
                    result = client._responses.pop(0)
                else:
                    result = FakeResponse(FakeMessage(content=""), FakeUsage())
                if isinstance(result, Exception):
                    raise result
                return result

        self.chat = type("Chat", (), {"completions": _Completions()})()


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Chặn mọi lời gọi mạng: client mặc định là fake không gọi tool nào.

    Nếu thiếu fixture này, tool-use loop của Auditor sẽ khởi tạo OpenAI client
    thật và bắn request ra `integrate.api.nvidia.com` khi chạy test.
    """
    monkeypatch.setattr(llm_client, "_client", FakeOpenAIClient([]))


@pytest.fixture
def fake_openai(monkeypatch):
    def _install(responses) -> FakeOpenAIClient:
        fake = FakeOpenAIClient(responses)
        monkeypatch.setattr(llm_client, "_client", fake)
        return fake

    return _install


@pytest.fixture
def mock_code_tools(monkeypatch):
    """Gắn tool giả lập cho test cần tool call trả dữ liệu.

    Tool chưa gắn backend cố tình trả `success=False`, nên test nào dựa vào
    dữ liệu tool phải yêu cầu fixture này — không còn mock ngầm toàn cục có
    thể khiến agent tưởng đang đọc code thật.
    """
    import ai.tools.registry as registry
    from ai.tools.code_tools import make_mock_tools

    def _bind(**overrides):
        tools = make_mock_tools(**overrides)
        monkeypatch.setattr(registry, "code_tools", tools)
        return tools

    return _bind
