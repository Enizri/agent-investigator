"""Schema, foreign keys, read-only access, and investigation tools."""

import sqlite3
from pathlib import Path

import pytest

from security_investigator.database import (
    connect,
    dump_database,
    get_incident_history,
    incident_id_for_alert,
    incident_status_at,
    search_alerts,
    search_incidents,
    search_logs,
    write_database,
)
from security_investigator.generator import generate_company

EXPECTED_INDEXES = {
    "idx_logs_timestamp",
    "idx_logs_service_id",
    "idx_logs_request_id",
    "idx_logs_alert_id",
    "idx_alerts_detected_at",
    "idx_alerts_service_id",
    "idx_alerts_severity",
    "idx_alerts_status",
    "idx_incidents_detected_at",
    "idx_incidents_service_id",
    "idx_incidents_severity",
    "idx_incidents_status",
    "idx_incident_events_incident_id",
    "idx_incident_events_timestamp",
    "idx_remediations_incident_id",
}


@pytest.fixture
def database_path(tmp_path: Path) -> Path:
    company = generate_company()
    path = tmp_path / "security.db"
    write_database(path, company.tables)
    return path


def test_indexes_and_foreign_keys(database_path: Path) -> None:
    connection = sqlite3.connect(database_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        names = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
        }
        assert EXPECTED_INDEXES <= names
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        counts = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("services", "logs", "alerts", "incidents")
        }
    finally:
        connection.close()
    assert counts == {"services": 6, "logs": 15_000, "alerts": 250, "incidents": 30}


def test_dump_is_stable_across_writes(tmp_path: Path) -> None:
    company = generate_company()
    first = tmp_path / "first.db"
    second = tmp_path / "second.db"
    write_database(first, company.tables)
    write_database(second, company.tables)
    assert dump_database(first) == dump_database(second)


async def test_readonly_connection_rejects_writes(database_path: Path) -> None:
    connection = await connect(database_path, readonly=True)
    try:
        with pytest.raises(sqlite3.OperationalError):
            await connection.execute(
                "INSERT INTO services (id, name, description, owner_team, criticality) "
                "VALUES (99, 'x', 'x', 'x', 'low')"
            )
    finally:
        await connection.close()


async def test_tools_filter_and_reject_bad_input(database_path: Path) -> None:
    logs = await search_logs(database_path, service="billing-service", limit=5)
    assert logs
    assert all(log.service_id == 3 for log in logs)
    with pytest.raises(ValueError, match="unknown service"):
        await search_logs(database_path, service="not-a-service")
    with pytest.raises(ValueError, match="invalid timestamp"):
        await search_logs(database_path, start_time="yesterday")
    with pytest.raises(ValueError, match="limit"):
        await search_logs(database_path, limit=10_000)

    injected = await search_logs(database_path, pattern="'; DROP TABLE logs; --", limit=10)
    assert injected == []
    connection = sqlite3.connect(database_path)
    try:
        assert connection.execute("SELECT COUNT(*) FROM logs").fetchone()[0] == 15_000
    finally:
        connection.close()


async def test_status_reconstruction_and_unlinked_alerts(database_path: Path) -> None:
    assert await incident_status_at(database_path, 1, "2026-08-11T00:00:00Z") == "open"
    assert await incident_status_at(database_path, 1, "2026-08-11T12:00:00Z") == "investigating"
    assert await incident_status_at(database_path, 1, "2026-10-11T00:00:00Z") == "resolved"
    assert await incident_status_at(database_path, 9999, "2026-10-11T00:00:00Z") is None
    assert await get_incident_history(database_path, 9999) == []

    history = await get_incident_history(database_path, 4)
    assert [event.new_status for event in history][-1] == "reopened"
    assert "resolved" in [event.new_status for event in history]
    assert await incident_status_at(database_path, 4, "2026-09-02T00:00:00Z") == "resolved"

    open_critical = await search_incidents(
        database_path,
        status="open",
        severity="critical",
        as_of="2026-10-11T00:00:00Z",
    )
    assert any(incident.id == 2 and incident.status == "open" for incident in open_critical)

    lookalike = await search_alerts(database_path, service="billing-service", cwe_id="CWE-639")
    unlinked = [alert for alert in lookalike if alert.status == "new"]
    assert unlinked
    for alert in unlinked:
        assert await incident_id_for_alert(database_path, alert.id) is None
