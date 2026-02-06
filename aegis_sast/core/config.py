"""
Configuration management for Aegis-SAST.

Handles loading and validation of configuration from environment variables,
config files, and command-line arguments.
"""

from pathlib import Path
from typing import Optional, List
import os

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AegisConfig(BaseSettings):
    """Main configuration class for Aegis-SAST."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )
    
    # Gemini API Configuration
    gemini_api_key: str = Field(
        default="",
        description="Gemini API key for AI verification"
    )
    gemini_model: str = Field(
        default="gemini-1.5-flash",
        description="Gemini model to use"
    )
    
    # Cache Configuration
    cache_enabled: bool = Field(
        default=True,
        description="Enable hash-based caching of AI results"
    )
    cache_dir: Path = Field(
        default=Path(".aegis_cache"),
        description="Directory for cache storage"
    )
    cache_ttl_days: int = Field(
        default=30,
        description="Cache time-to-live in days"
    )
    
    # Analysis Configuration
    max_analysis_depth: int = Field(
        default=5,
        description="Maximum depth for inter-procedural analysis"
    )
    enable_ai_verification: bool = Field(
        default=True,
        description="Enable AI-based vulnerability verification"
    )
    
    # Rate Limiting
    api_rate_limit: int = Field(
        default=60,
        description="Maximum API requests per minute"
    )
    
    # Logging Configuration
    log_level: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR)"
    )
    log_file: Optional[Path] = Field(
        default=Path("aegis_sast.log"),
        description="Log file path"
    )
    
    # Rules Configuration
    custom_rules_path: Optional[Path] = Field(
        default=None,
        description="Path to custom rules file (YAML/JSON)"
    )
    
    # Output Configuration
    output_formats: List[str] = Field(
        default=["json", "markdown"],
        description="Output formats for reports"
    )
    output_dir: Path = Field(
        default=Path("reports"),
        description="Directory for output reports"
    )
    
    @field_validator("gemini_api_key")
    @classmethod
    def validate_api_key(cls, v: str) -> str:
        """Validate that API key is provided if AI verification is enabled."""
        if not v:
            # Will be checked at runtime if AI verification is enabled
            pass
        return v
    
    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        v_upper = v.upper()
        if v_upper not in valid_levels:
            raise ValueError(f"Log level must be one of {valid_levels}")
        return v_upper
    
    @field_validator("output_formats")
    @classmethod
    def validate_output_formats(cls, v: List[str]) -> List[str]:
        """Validate output formats."""
        valid_formats = ["json", "markdown", "html"]
        for fmt in v:
            if fmt.lower() not in valid_formats:
                raise ValueError(f"Output format '{fmt}' not supported. Valid: {valid_formats}")
        return [fmt.lower() for fmt in v]
    
    def ensure_directories(self):
        """Create necessary directories if they don't exist."""
        if self.cache_enabled:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
    
    def validate_ai_config(self):
        """Validate AI configuration at runtime."""
        if self.enable_ai_verification and not self.gemini_api_key:
            raise ValueError(
                "Gemini API key is required when AI verification is enabled. "
                "Set GEMINI_API_KEY environment variable or disable AI verification."
            )


# Global config instance
_config: Optional[AegisConfig] = None


def get_config() -> AegisConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = AegisConfig()
        _config.ensure_directories()
    return _config


def set_config(config: AegisConfig):
    """Set the global configuration instance."""
    global _config
    _config = config
    _config.ensure_directories()


def reload_config():
    """Reload configuration from environment."""
    global _config
    _config = AegisConfig()
    _config.ensure_directories()
    return _config
