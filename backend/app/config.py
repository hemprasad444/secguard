from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://secguard:secguard_secret@postgres:5432/secguard"

    # Redis
    REDIS_URL: str = "redis://redis:6379/0"

    # JWT
    SECRET_KEY: str = "change-me-to-a-random-secret-key-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALGORITHM: str = "HS256"

    # App
    APP_ENV: str = "development"
    APP_DEBUG: bool = True
    BACKEND_CORS_ORIGINS: str = "http://localhost:3000,http://localhost:80"

    # Tools
    TRIVY_SERVER_URL: str = "http://trivy:4954"
    ZAP_API_URL: str = "http://zap:8080"
    ZAP_API_KEY: str = "change-me-zap-api-key"
    SONARQUBE_URL: str = ""
    SONARQUBE_TOKEN: str = ""
    GITGUARDIAN_API_KEY: str = ""

    # Uploads
    UPLOAD_DIR: str = "/app/uploads"
    MAX_UPLOAD_SIZE_MB: int = 2048

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.BACKEND_CORS_ORIGINS.split(",") if o.strip()]

    @property
    def sync_database_url(self) -> str:
        return self.DATABASE_URL.replace("+asyncpg", "")

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
