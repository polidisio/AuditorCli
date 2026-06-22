from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


CONFIG_DIR = Path.home() / ".auditor"
LOG_DIR = CONFIG_DIR / "logs"
OUTPUT_DIR = CONFIG_DIR / "output"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AUDITOR_",
        env_file=CONFIG_DIR / ".env",
        env_file_encoding="utf-8",
    )

    # M365 / Entra ID
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = Field(default=None, repr=False)
    username: str | None = None

    # Network
    request_timeout: int = 30
    max_concurrent: int = 10

    # Output
    output_dir: Path = OUTPUT_DIR
    log_dir: Path = LOG_DIR
    debug: bool = False


def get_settings() -> Settings:
    CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    return Settings()
