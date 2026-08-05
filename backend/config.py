"""Application configuration for VulnPilot AI backend."""

from functools import lru_cache


class Settings:
    app_name: str = "VulnPilot AI"
    api_prefix: str = "/api/v1"
    cors_origins: list[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
    ]
    max_upload_size_mb: int = 50


@lru_cache
def get_settings() -> Settings:
    return Settings()
