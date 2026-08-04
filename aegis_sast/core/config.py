"""Configuration management for Aegis-SAST using stdlib-only settings."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
import os


VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
VALID_OUTPUT_FORMATS = {"json", "markdown", "sarif", "html"}


def _load_dotenv(path: Path = Path(".env")) -> None:
    """Load simple KEY=VALUE pairs from a local .env file if present."""
    if not path.exists():
        return

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")
        os.environ.setdefault(key, value)


def _get_env(name: str) -> Optional[str]:
    """Read an environment variable using common case variants."""
    return (
        os.environ.get(name)
        or os.environ.get(name.upper())
        or os.environ.get(name.lower())
    )


def _get_first_env(*names: str) -> Optional[str]:
    """Read the first non-empty environment variable from a list of aliases."""
    for name in names:
        value = _get_env(name)
        if value is not None and value.strip():
            return value
    return None


def _parse_bool(name: str, default: bool) -> bool:
    """Parse a boolean environment variable."""
    value = _get_env(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_int(name: str, default: int) -> int:
    """Parse an integer environment variable safely."""
    value = _get_env(name)
    if value is None:
        return default
    try:
        return int(value.strip())
    except ValueError:
        return default


def _parse_path(name: str, default: Optional[Path]) -> Optional[Path]:
    """Parse a filesystem path environment variable."""
    value = _get_env(name)
    if value is None or not value.strip():
        return default
    return Path(value.strip())


def _parse_list(name: str, default: List[str]) -> List[str]:
    """Parse a comma-separated list environment variable."""
    value = _get_env(name)
    if value is None or not value.strip():
        return list(default)
    parts = [item.strip().lower() for item in value.replace(";", ",").split(",")]
    return [item for item in parts if item]


@dataclass
class AegisConfig:
    """Main configuration class for Aegis-SAST."""

    gemini_api_key: str = ""
    gemini_model: str = "gemini-3.6-flash"
    cache_enabled: bool = True
    cache_dir: Path = field(default_factory=lambda: Path(".aegis_cache"))
    cache_ttl_days: int = 30
    max_analysis_depth: int = 5
    enable_ai_verification: bool = True
    api_rate_limit: int = 60
    log_level: str = "INFO"
    log_file: Optional[Path] = field(default_factory=lambda: Path("aegis_sast.log"))
    custom_rules_path: Optional[Path] = None
    output_formats: List[str] = field(default_factory=lambda: ["json", "markdown"])
    output_dir: Path = field(default_factory=lambda: Path("reports"))

    def __post_init__(self) -> None:
        """Normalize values after construction."""
        self.log_level = self._validate_log_level(self.log_level)
        self.output_formats = self._validate_output_formats(self.output_formats)
        self.cache_dir = Path(self.cache_dir)
        self.output_dir = Path(self.output_dir)
        if self.log_file is not None:
            self.log_file = Path(self.log_file)
        if self.custom_rules_path is not None:
            self.custom_rules_path = Path(self.custom_rules_path)

    @classmethod
    def from_env(cls) -> "AegisConfig":
        """Build configuration from environment variables and .env."""
        _load_dotenv()
        return cls(
            gemini_api_key=_get_first_env(
                "GEMINI_API_KEY",
                "GOOGLE_API_KEY",
                "GOOGLE_GENAI_API_KEY",
            )
            or "",
            gemini_model=_get_env("GEMINI_MODEL") or "gemini-3.6-flash",
            cache_enabled=_parse_bool("CACHE_ENABLED", True),
            cache_dir=_parse_path("CACHE_DIR", Path(".aegis_cache")) or Path(".aegis_cache"),
            cache_ttl_days=_parse_int("CACHE_TTL_DAYS", 30),
            max_analysis_depth=_parse_int("MAX_ANALYSIS_DEPTH", 5),
            enable_ai_verification=_parse_bool("ENABLE_AI_VERIFICATION", True),
            api_rate_limit=_parse_int("API_RATE_LIMIT", 60),
            log_level=_get_env("LOG_LEVEL") or "INFO",
            log_file=_parse_path("LOG_FILE", Path("aegis_sast.log")),
            custom_rules_path=_parse_path("CUSTOM_RULES_PATH", None),
            output_formats=_parse_list("OUTPUT_FORMATS", ["json", "markdown"]),
            output_dir=_parse_path("OUTPUT_DIR", Path("reports")) or Path("reports"),
        )

    @staticmethod
    def _validate_log_level(value: str) -> str:
        """Validate log level names."""
        normalized = value.upper()
        if normalized not in VALID_LOG_LEVELS:
            raise ValueError(f"Log level must be one of {sorted(VALID_LOG_LEVELS)}")
        return normalized

    @staticmethod
    def _validate_output_formats(values: List[str]) -> List[str]:
        """Validate report output format names."""
        normalized = [item.lower() for item in values]
        for item in normalized:
            if item not in VALID_OUTPUT_FORMATS:
                raise ValueError(
                    f"Output format '{item}' not supported. "
                    f"Valid: {sorted(VALID_OUTPUT_FORMATS)}"
                )
        return normalized

    def ensure_directories(self) -> None:
        """Create necessary directories if they do not exist."""
        if self.cache_enabled:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if self.log_file is not None:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def validate_ai_config(self) -> None:
        """Validate AI configuration at runtime."""
        if self.enable_ai_verification and not self.gemini_api_key:
            from rich.console import Console

            console = Console()
            console.print(
                "[yellow]Warning: GEMINI_API_KEY or GOOGLE_API_KEY is required for AI verification.[/yellow]"
            )
            console.print(
                "[yellow]Disabling AI verification for the current run.[/yellow]"
            )
            self.enable_ai_verification = False


_config: Optional[AegisConfig] = None


def get_config() -> AegisConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = AegisConfig.from_env()
        _config.ensure_directories()
    return _config


def set_config(config: AegisConfig) -> None:
    """Set the global configuration instance."""
    global _config
    _config = config
    _config.ensure_directories()


def reload_config() -> AegisConfig:
    """Reload configuration from environment and return it."""
    global _config
    _config = AegisConfig.from_env()
    _config.ensure_directories()
    return _config
