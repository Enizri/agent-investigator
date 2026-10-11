"""Environment-backed settings and structured logging."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

SECRET_LOG_KEYS = {"api_key", "authorization", "password", "secret", "token"}


class Settings(BaseSettings):
    """Runtime configuration. Credentials may be empty for local unit tests."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    pinecone_api_key: str = ""
    pinecone_index: str = "security-investigator"
    pinecone_namespace: str = "security-v1"
    pinecone_cloud: str = "aws"
    pinecone_region: str = "us-east-1"

    llm_api_key: str = ""
    llm_base_url: str = ""
    llm_model: str = ""
    ollama_base_url: str = "http://127.0.0.1:11434"
    local_summarizer_enabled: bool = True
    local_summarizer_model: str = "qwen3:8b"

    database_path: str = "data/security.db"

    embedding_model: str = "BAAI/bge-small-en-v1.5"
    embedding_dimension: int = 384
    embed_mode: str = "contextual"
    query_instruction: str = "Represent this sentence for searching relevant passages: "
    reranker_model: str = "cross-encoder/ms-marco-MiniLM-L6-v2"
    rerank_enabled: bool = True

    top_k_dense: int = Field(default=20, gt=0)
    top_k_bm25: int = Field(default=20, gt=0)
    top_k_rerank: int = Field(default=6, gt=0)
    max_agent_steps: int = Field(default=6, gt=0, le=20)
    max_retrieval_attempts: int = Field(default=2, gt=0)
    rrf_k: int = Field(default=60, gt=0)

    reference_time: datetime = datetime(2026, 10, 11, tzinfo=UTC)
    random_seed: int = 42
    log_level: str = "INFO"

    @field_validator("reference_time")
    @classmethod
    def reference_time_is_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @field_validator("embed_mode")
    @classmethod
    def embed_mode_is_known(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"original", "summary", "contextual"}:
            raise ValueError("embed_mode must be original, summary, or contextual")
        return normalized

    @field_validator("embedding_dimension")
    @classmethod
    def dimension_is_positive(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("embedding_dimension must be positive")
        return value

    @field_validator("log_level")
    @classmethod
    def log_level_is_known(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in logging.getLevelNamesMapping():
            raise ValueError(f"unknown log level: {value}")
        return normalized

    @property
    def namespace_knowledge(self) -> str:
        return f"{self.pinecone_namespace}-knowledge"

    @property
    def namespace_incidents(self) -> str:
        return f"{self.pinecone_namespace}-incidents"

    @property
    def namespace_alerts(self) -> str:
        return f"{self.pinecone_namespace}-alerts"


@lru_cache
def get_settings() -> Settings:
    return Settings()


class StructuredFormatter(logging.Formatter):
    """One JSON object per log line. Secret-like extras are dropped."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key.startswith("_") or key in _STANDARD_LOG_ATTRS:
                continue
            if key.lower() in SECRET_LOG_KEYS or "api_key" in key.lower():
                continue
            payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


_STANDARD_LOG_ATTRS = frozenset(logging.makeLogRecord({}).__dict__) | {
    "message",
    "asctime",
    "taskName",
}


def setup_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level.upper())
    root.addHandler(handler)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
