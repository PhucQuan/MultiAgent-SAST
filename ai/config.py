"""Cấu hình NVIDIA NIM cho multi-agent layer của Aegis-SAST.

Đọc toàn bộ tham số từ biến môi trường / `.env`. Không hard-code API key,
không hard-code model name trong node code (Quy tắc 6, mục 0 của guide).
"""

from pathlib import Path
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# `.env` cạnh gốc repo, để import được từ bất kỳ CWD nào.
_REPO_ENV = Path(__file__).resolve().parent.parent / ".env"


class Settings(BaseSettings):
    """Tham số runtime cho toàn bộ multi-agent workflow."""

    model_config = SettingsConfigDict(
        env_file=(".env", str(_REPO_ENV)),
        env_file_encoding="utf-8",
        extra="ignore",           # .env còn chứa key của Core SAST (GEMINI_*, ...)
        populate_by_name=True,
        protected_namespaces=(),  # cho phép field bắt đầu bằng `model_`
    )

    nvidia_api_key: str = Field(..., alias="NVIDIA_API_KEY")
    # Nhiều key trên cùng tài khoản để chia tải: 4 worker dội vào một key gây
    # 503 và xếp hàng phía server. Xoay vòng key giúp giãn tải.
    nvidia_api_keys: Annotated[list[str], NoDecode] = Field(
        default_factory=list, alias="NVIDIA_API_KEYS"
    )
    nvidia_base_url: str = Field(
        default="https://integrate.api.nvidia.com/v1", alias="NVIDIA_BASE_URL"
    )

    model_hypothesis: str = Field(..., alias="AEGIS_MODEL_HYPOTHESIS")
    model_auditor: str = Field(..., alias="AEGIS_MODEL_AUDITOR")
    model_skeptic: str = Field(..., alias="AEGIS_MODEL_SKEPTIC")
    model_judge: str = Field(..., alias="AEGIS_MODEL_JUDGE")
    # NoDecode: chuỗi phân tách bằng dấu phẩy, không phải JSON array.
    model_fallback: Annotated[list[str], NoDecode] = Field(
        ..., alias="AEGIS_MODEL_FALLBACK"
    )

    temp_hypothesis: float = Field(0.5, alias="AEGIS_TEMP_HYPOTHESIS")
    temp_auditor: float = Field(0.3, alias="AEGIS_TEMP_AUDITOR")
    temp_skeptic: float = Field(0.0, alias="AEGIS_TEMP_SKEPTIC")
    temp_judge: float = Field(0.0, alias="AEGIS_TEMP_JUDGE")

    max_tokens: int = Field(2048, alias="AEGIS_MAX_TOKENS")
    # Seed cố định cho suy luận. Temperature 0 KHÔNG đủ để tái lập: đo ngày
    # 2026-09-10, hai lần chạy temp=0 chỉ trùng 8/12 vì quỹ đạo tool-use phân kỳ.
    seed: int | None = Field(None, alias="AEGIS_SEED")
    timeout_sec: int = Field(60, alias="AEGIS_TIMEOUT_SEC")
    # Trần tổng thời gian LLM cho MỘT finding. Không có trần, một model bị
    # xếp hàng phía server có thể đốt hàng giờ cho một finding duy nhất.
    finding_budget_sec: int = Field(600, alias="AEGIS_FINDING_BUDGET_SEC")
    max_retries: int = Field(3, alias="AEGIS_MAX_RETRIES")
    debate_round_max: int = Field(3, alias="AEGIS_DEBATE_ROUND_MAX")
    # Bỏ qua Skeptic khi Auditor tự tin hơn ngưỡng này. Đo thực tế cho thấy
    # confidence LLM tự chấm gần như là hằng số 0.95, nên ngưỡng 0.8 của bản
    # guide khiến Skeptic không bao giờ chạy. Mặc định 0.99 = gần như luôn chạy.
    skip_skeptic_confidence: float = Field(
        0.99, alias="AEGIS_SKIP_SKEPTIC_CONFIDENCE"
    )
    cache_dir: str = Field("./cache/llm", alias="AEGIS_CACHE_DIR")

    @field_validator("nvidia_api_key")
    @classmethod
    def validate_key(cls, v: str) -> str:
        """API key NVIDIA NIM luôn có tiền tố `nvapi-`."""
        if not v.startswith("nvapi-"):
            raise ValueError("NVIDIA_API_KEY phải bắt đầu bằng 'nvapi-'")
        return v

    @field_validator("nvidia_api_keys", mode="before")
    @classmethod
    def parse_keys(cls, v):
        """`NVIDIA_API_KEYS` là chuỗi key phân tách bằng dấu phẩy."""
        if isinstance(v, str):
            return [k.strip() for k in v.split(",") if k.strip()]
        return v or []

    @field_validator("nvidia_api_keys")
    @classmethod
    def validate_keys(cls, v: list[str]) -> list[str]:
        for k in v:
            if not k.startswith("nvapi-"):
                raise ValueError("Mọi key trong NVIDIA_API_KEYS phải bắt đầu bằng 'nvapi-'")
        return v

    @property
    def api_keys(self) -> list[str]:
        """Danh sách key thực dùng: NVIDIA_API_KEYS nếu có, không thì key đơn."""
        return self.nvidia_api_keys or [self.nvidia_api_key]

    @field_validator("model_fallback", mode="before")
    @classmethod
    def parse_fallback(cls, v):
        """`AEGIS_MODEL_FALLBACK` là chuỗi phân tách bằng dấu phẩy."""
        if isinstance(v, str):
            return [m.strip() for m in v.split(",") if m.strip()]
        return v


_cached: Settings | None = None


def get_settings(reload: bool = False) -> Settings:
    """Trả về `Settings` singleton, khởi tạo lần đầu khi thực sự cần."""
    global _cached
    if _cached is None or reload:
        _cached = Settings()
    return _cached


def reset_settings() -> None:
    """Xoá cache settings (dùng trong test khi đổi biến môi trường)."""
    global _cached
    _cached = None


class _LazySettings:
    """Proxy để `from ai.config import settings` không nổ lúc import.

    Settings chỉ được validate ở lần truy cập thuộc tính đầu tiên, nhờ vậy
    `import ai...` vẫn chạy được trên máy chưa cấu hình `NVIDIA_API_KEY`.
    """

    def __getattr__(self, name: str):
        return getattr(get_settings(), name)

    def __repr__(self) -> str:
        return f"<LazySettings loaded={_cached is not None}>"


settings = _LazySettings()
