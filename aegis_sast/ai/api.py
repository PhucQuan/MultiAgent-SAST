"""API công khai của tầng AI.

Core, orchestration, CLI và script benchmark chỉ được import từ đây. Import
thẳng `ai.graph`, `ai.llm.nvidia_client` hay `aegis_sast.ai.gemini_client` từ
bên ngoài tầng AI là đi vòng qua eligibility gate và policy suppression — tức
là bỏ qua đúng hai cơ chế giữ cho verdict an toàn và chi phí có trần.
"""

from .contracts import (
    EvidenceReference,
    ModelUsage,
    RecommendedAction,
    TriageRequest,
    TriageStatus,
    TriageVerdict,
)
from .gateway import (
    AIModelGateway,
    GeminiLegacyGateway,
    MockGateway,
    ModelPolicy,
    ModelResponse,
    NvidiaGateway,
    available_gateways,
    get_gateway,
    register_gateway,
)
from .service import AITriageService

__all__ = [
    "AITriageService",
    "TriageRequest",
    "TriageVerdict",
    "TriageStatus",
    "RecommendedAction",
    "EvidenceReference",
    "ModelUsage",
    "AIModelGateway",
    "ModelPolicy",
    "ModelResponse",
    "MockGateway",
    "NvidiaGateway",
    "GeminiLegacyGateway",
    "get_gateway",
    "register_gateway",
    "available_gateways",
]
