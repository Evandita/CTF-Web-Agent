"""Configuration module using pydantic-settings with dotenv support."""

from pathlib import Path

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Resolve .env file path from project root
_PROJECT_ROOT = Path(__file__).parent.parent
_ENV_FILE = _PROJECT_ROOT / ".env"

# Load .env into os.environ before Settings class is instantiated
load_dotenv(_ENV_FILE, override=True)


class Settings(BaseSettings):
    """Application settings loaded from .env file and environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="CTF_",
        env_file=str(_ENV_FILE),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Ollama settings (required - must be set in .env)
    ollama_base_url: str = Field(description="Ollama server URL")
    ollama_text_model: str = Field(description="Ollama text model name")
    ollama_vision_model: str = Field(description="Ollama vision model name")

    # Agent settings
    max_iterations: int = 30
    timeout_seconds: int = 30

    # Browser settings
    headless: bool = False
    slow_mo: int = 100
    viewport_width: int = 1280
    viewport_height: int = 720

    # Flag detection patterns (ordered from most specific/longest to least specific)
    # IMPORTANT: Longer prefixes must come before shorter ones (e.g., picoCTF before CTF)
    flag_patterns: list[str] = [
        # Specific CTF platform patterns (longer prefixes first)
        r"picoCTF\{[^}]+\}",
        r"DUCTF\{[^}]+\}",
        r"ductf\{[^}]+\}",
        r"CUCTF\{[^}]+\}",
        r"GOOGLE\{[^}]+\}",
        r"google\{[^}]+\}",
        # Generic patterns
        r"FLAG\{[^}]+\}",
        r"flag\{[^}]+\}",
        r"CTF\{[^}]+\}",
        r"ctf\{[^}]+\}",
        r"HTB\{[^}]+\}",
        r"htb\{[^}]+\}",
        r"THM\{[^}]+\}",
        r"thm\{[^}]+\}",
        # Dash-separated flags
        r"FLAG-[a-zA-Z0-9-]+",
        r"flag-[a-zA-Z0-9-]+",
        # Catch-all pattern for any word followed by {content}
        r"[a-zA-Z0-9_]+\{[^}]+\}",
    ]

    # Human-in-the-loop settings
    hitl_enabled: bool = True

    # Vision model settings
    vision_enabled: bool = True


# Global settings instance
_settings: Settings | None = None


def get_settings() -> Settings:
    """Get the global settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def update_settings(**kwargs) -> Settings:
    """Update settings with new values."""
    global _settings
    current = get_settings()
    new_values = current.model_dump()
    new_values.update(kwargs)
    _settings = Settings(**new_values)
    return _settings
