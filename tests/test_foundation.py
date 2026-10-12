"""Settings and domain models."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from security_investigator.config import Settings, get_settings
from security_investigator.models import SecurityAlert, SecurityIncident


def test_default_settings_are_local(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)
    get_settings.cache_clear()
    settings = Settings(_env_file=None)
    assert settings.embedding_dimension == 384
    assert settings.namespace_knowledge == "knowledge"
    assert settings.namespace_incidents == "incidents"
    assert settings.namespace_alerts == "alerts"
    assert settings.semantic_weight == 0.8
    assert settings.bm25_weight == 0.2
    assert settings.reference_time == datetime(2026, 10, 11, tzinfo=UTC)
    get_settings.cache_clear()


def test_settings_reject_invalid_retrieval_limits() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, top_k_dense=0)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, embedding_dimension=0)


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
