"""Phase 1: settings, domain models, and the health endpoint."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from security_investigator.api import create_app
from security_investigator.config import Settings, get_settings, setup_logging
from security_investigator.models import (
    InvestigationQuery,
    InvestigationResult,
    SecurityAlert,
    SecurityIncident,
)


def test_default_settings_do_not_require_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PINECONE_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    get_settings.cache_clear()
    settings = Settings(_env_file=None)
    assert settings.pinecone_api_key == ""
    assert settings.llm_api_key == ""
    assert settings.embedding_dimension == 384
    assert settings.namespace_knowledge == "security-v1-knowledge"
    assert settings.namespace_incidents == "security-v1-incidents"
    assert settings.namespace_alerts == "security-v1-alerts"
    assert settings.reference_time == datetime(2026, 10, 11, tzinfo=UTC)


def test_settings_reject_invalid_retrieval_limits() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, top_k_dense=0)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, embedding_dimension=0)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, log_level="loud")


def test_naive_reference_time_is_treated_as_utc() -> None:
    settings = Settings(_env_file=None, reference_time=datetime(2026, 10, 11, 12, 0, 0))
    assert settings.reference_time.tzinfo == UTC


def test_alert_and_incident_status_literals() -> None:
    alert = SecurityAlert(
        id=1,
        detected_at=datetime(2026, 10, 1, tzinfo=UTC),
        service_id=1,
        rule_id="RULE-1",
        alert_type="injection",
        severity="high",
        confidence=0.4,
        status="new",
        description="blocked payload",
    )
    assert alert.status == "new"
    with pytest.raises(ValidationError):
        SecurityIncident(
            id=1,
            title="x",
            service_id=1,
            severity="high",
            status="closed",
            detected_at=datetime(2026, 10, 1, tzinfo=UTC),
            description="nope",
        )


def test_investigation_query_requires_a_question() -> None:
    with pytest.raises(ValidationError):
        InvestigationQuery(question="")
    result = InvestigationResult(answer="insufficient evidence")
    assert result.findings == []
    assert result.citations == []


def test_health_endpoint() -> None:
    setup_logging("WARNING")
    client = TestClient(create_app())
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"]
