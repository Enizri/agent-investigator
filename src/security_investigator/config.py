"""Environment-backed settings for the seeded local investigation."""

from __future__ import annotations

from datetime import UTC, datetime
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the seeded local investigation."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    ollama_base_url: str = "http://127.0.0.1:11434"
    local_summarizer_enabled: bool = True
    local_summarizer_model: str = "qwen3:8b"

    database_path: str = "data/security.db"

    embedding_model: str = "BAAI/bge-small-en-v1.5"
    embedding_dimension: int = 384
    query_instruction: str = "Represent this sentence for searching relevant passages: "
    reranker_model: str = "cross-encoder/ms-marco-MiniLM-L6-v2"
    rerank_enabled: bool = True

    top_k_dense: int = Field(default=20, gt=0)
    top_k_bm25: int = Field(default=20, gt=0)
    top_k_rerank: int = Field(default=6, gt=0)
    semantic_weight: float = Field(default=0.8, gt=0, le=1)
    bm25_weight: float = Field(default=0.2, gt=0, le=1)
    max_agent_steps: int = Field(default=6, gt=0, le=20)
    max_retrieval_attempts: int = Field(default=2, gt=0)
    situate_workers: int = Field(default=8, gt=0, le=32)

    reference_time: datetime = datetime(2026, 10, 11, tzinfo=UTC)
    random_seed: int = 42

    namespace_knowledge: str = "knowledge"
    namespace_incidents: str = "incidents"
    namespace_alerts: str = "alerts"

    @field_validator("reference_time")
    @classmethod
    def reference_time_is_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @field_validator("embedding_dimension")
    @classmethod
    def dimension_is_positive(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("embedding_dimension must be positive")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
