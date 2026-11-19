"""
Centralised configuration loaded from environment / .env file.
"""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── MongoDB ──
    MONGODB_URI: str = "mongodb://localhost:27017"
    DB_NAME: str = "soar_db"

    # ── JWT Authentication ──
    JWT_SECRET_KEY: str = "change-me-to-a-random-secret-key-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 480  # 8 hours

    # ── Threat Intelligence API Keys ──
    ABUSEIPDB_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""

    # ── AWS ──
    AWS_SIMULATION_MODE: bool = True
    AWS_REGION: str = "us-east-1"
    AWS_SECURITY_GROUP_ID: str = ""

    # ── SMTP Email (OTP) ──
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASS: str = ""
    SMTP_FROM: str = ""

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore"
    }


settings = Settings()
