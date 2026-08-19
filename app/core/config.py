from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str
    REDIS_URL: str

    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str

    ACCESS_TOKEN_EXPIRE_MINUTES: int
    REFRESH_TOKEN_EXPIRE_DAYS: int

    LOGIN_IP_LIMIT: int
    LOGIN_EMAIL_LIMIT: int
    LOGIN_GLOBAL_LIMIT: int

    REGISTER_IP_LIMIT: int
    RATE_LIMIT_WINDOW_SECONDS: int

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()