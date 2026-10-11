from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_env: str = "development"
    secret_key: str = "change-me"
    database_url: str = "sqlite:///./breachwatch.db"
    redis_url: str = "redis://localhost:6379/0"
    cors_origins: str = "http://localhost:5173"
    access_token_minutes: int = 30
    demo_admin_password: str = "AdminPass123!"
    demo_analyst_password: str = "AnalystPass123!"
    demo_viewer_password: str = "ViewerPass123!"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

@lru_cache
def get_settings() -> Settings:
    return Settings()
