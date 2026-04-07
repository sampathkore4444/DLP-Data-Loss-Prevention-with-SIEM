from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://securevault:securevault@localhost:5432/securevault"
    REDIS_URL: str = "redis://localhost:6379/0"
    OPENSEARCH_URL: str = "http://localhost:9200"
    OPENSEARCH_USERNAME: str = "admin"
    OPENSEARCH_PASSWORD: str = "Admin123!"
    MINIO_ENDPOINT: str = "localhost:9000"
    MINIO_ACCESS_KEY: str = "securevault"
    MINIO_SECRET_KEY: str = "securevault123"
    MINIO_BUCKET: str = "securevault-logs"
    SECRET_KEY: str = "change-this-secret-key-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    class Config:
        env_file = ".env"


@lru_cache()
def get_settings():
    return Settings()


settings = get_settings()
