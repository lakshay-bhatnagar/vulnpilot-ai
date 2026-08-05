"""Application configuration for VulnPilot AI backend."""

from functools import lru_cache
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    app_name: str = "VulnPilot AI"
    api_prefix: str = "/api/v1"
    cors_origins: tuple[str, ...] = (
        "http://localhost:5173",
        "http://localhost:3000",
    )
    max_upload_size_mb: int = 50
    openrouter_api_key: str = ""
    openrouter_model: str = "meta-llama/llama-3.3-70b-instruct:free"


@lru_cache
def get_settings() -> Settings:
    # Load only the backend-local file, regardless of the working directory used
    # to start uvicorn. Environment variables still take precedence over .env.
    load_dotenv(Path(__file__).with_name(".env"))

    return Settings(
        openrouter_api_key=os.getenv("OPENROUTER_API_KEY", ""),
        openrouter_model=os.getenv(
            "OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct:free"
        ),
    )
