from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    DATABASE_URL: str = "postgresql+asyncpg://radaruser:radarpass@db:5432/radardb"
    APP_ENV: str = "development"
    APP_TITLE: str = "DepRadar"
    APP_VERSION: str = "2.0.0"

    # External APIs
    PYPI_BASE_URL: str = "https://pypi.org/pypi"
    OSV_BASE_URL: str = "https://api.osv.dev/v1"
    GITHUB_RAW_BASE: str = "https://raw.githubusercontent.com"
    GITHUB_API_BASE: str = "https://api.github.com"
    GITHUB_TOKEN: str = ""

    # Risk thresholds
    ABANDONMENT_THRESHOLD_MONTHS: int = 24
    CACHE_TTL_HOURS: int = 12

    # Concurrency
    SCAN_CONCURRENCY: int = 10


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
