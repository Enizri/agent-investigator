"""SQLite schema and connections. Status columns are the system of record."""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

import aiosqlite

from security_investigator.models import (
    IncidentEvent,
    LogEvent,
    Remediation,
    SecurityAlert,
    SecurityIncident,
)

logger = logging.getLogger(__name__)

MAX_TOOL_LIMIT = 200
MAX_PATTERN_LENGTH = 200
ALERT_STATUSES = {
    "new",
    "investigating",
    "closed_false_positive",
    "closed_expected_behavior",
    "linked_to_incident",
}
INCIDENT_STATUSES = {
    "open",
    "investigating",
    "mitigated",
    "resolved",
    "reopened",
    "false_positive",
}
SEVERITIES = {"critical", "high", "medium", "low", "info"}

SCHEMA = """
CREATE TABLE services (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    owner_team TEXT NOT NULL,
    criticality TEXT NOT NULL CHECK (criticality IN ('critical', 'high', 'medium', 'low'))
);

CREATE TABLE incidents (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    service_id INTEGER NOT NULL REFERENCES services(id),
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    owasp_category TEXT,
    cwe_id TEXT,
    status TEXT NOT NULL CHECK (
        status IN ('open', 'investigating', 'mitigated', 'resolved', 'reopened', 'false_positive')
    ),
    detected_at TEXT NOT NULL,
    resolved_at TEXT,
    verified_at TEXT,
    description TEXT NOT NULL,
    root_cause TEXT
);

CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
    detected_at TEXT NOT NULL,
    service_id INTEGER NOT NULL REFERENCES services(id),
    rule_id TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    owasp_category TEXT,
    cwe_id TEXT,
    status TEXT NOT NULL CHECK (
        status IN (
            'new',
            'investigating',
            'closed_false_positive',
            'closed_expected_behavior',
            'linked_to_incident'
        )
    ),
    description TEXT NOT NULL
);

CREATE TABLE logs (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    service_id INTEGER NOT NULL REFERENCES services(id),
    request_id TEXT NOT NULL,
    actor_id TEXT,
    source_ip TEXT,
    method TEXT,
    endpoint TEXT,
    http_status INTEGER,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    duration_ms INTEGER NOT NULL,
    alert_id INTEGER REFERENCES alerts(id)
);

CREATE TABLE incident_events (
    id INTEGER PRIMARY KEY,
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    previous_status TEXT,
    new_status TEXT NOT NULL CHECK (
        new_status IN ('open', 'investigating', 'mitigated', 'resolved', 'reopened', 'false_positive')
    ),
    description TEXT NOT NULL
);

CREATE TABLE remediations (
    id INTEGER PRIMARY KEY,
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    applied_at TEXT NOT NULL,
    fix_description TEXT NOT NULL,
    verification_status TEXT NOT NULL CHECK (
        verification_status IN ('pending', 'verified', 'failed')
    ),
    verified_at TEXT,
    evidence TEXT
);

CREATE TABLE incident_alerts (
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    alert_id INTEGER NOT NULL REFERENCES alerts(id),
    PRIMARY KEY (incident_id, alert_id)
);

CREATE TABLE alert_logs (
    alert_id INTEGER NOT NULL REFERENCES alerts(id),
    log_id INTEGER NOT NULL REFERENCES logs(id),
    PRIMARY KEY (alert_id, log_id)
);

CREATE INDEX idx_logs_timestamp ON logs(timestamp);
CREATE INDEX idx_logs_service_id ON logs(service_id);
CREATE INDEX idx_logs_request_id ON logs(request_id);
CREATE INDEX idx_logs_alert_id ON logs(alert_id);
CREATE INDEX idx_alerts_detected_at ON alerts(detected_at);
CREATE INDEX idx_alerts_service_id ON alerts(service_id);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_incidents_detected_at ON incidents(detected_at);
CREATE INDEX idx_incidents_service_id ON incidents(service_id);
CREATE INDEX idx_incidents_severity ON incidents(severity);
CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_incident_events_incident_id ON incident_events(incident_id);
CREATE INDEX idx_incident_events_timestamp ON incident_events(timestamp);
CREATE INDEX idx_remediations_incident_id ON remediations(incident_id);
"""

TABLE_ORDER = (
    "services",
    "incidents",
    "alerts",
    "logs",
    "incident_events",
    "remediations",
    "incident_alerts",
    "alert_logs",
)


def connect_sync(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def create_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)
    connection.execute("PRAGMA foreign_keys = ON")


def write_database(path: Path, tables: Mapping[str, Sequence[Sequence[object]]]) -> None:
    """Replace the database file with one deterministic snapshot."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        create_schema(connection)
        for table in TABLE_ORDER:
            rows = tables[table]
            if not rows:
                continue
            width = len(rows[0])
            placeholders = ", ".join("?" for _ in range(width))
            connection.executemany(
                f"INSERT INTO {table} VALUES ({placeholders})",
                rows,
            )
        connection.commit()
        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise RuntimeError(f"foreign key violations: {violations}")
    finally:
        connection.close()


def dump_database(path: Path) -> dict[str, list[tuple[object, ...]]]:
    connection = connect_sync(path)
    try:
        dumped: dict[str, list[tuple[object, ...]]] = {}
        for table in TABLE_ORDER:
            order = "1, 2" if table in {"incident_alerts", "alert_logs"} else "1"
            cursor = connection.execute(f"SELECT * FROM {table} ORDER BY {order}")
            dumped[table] = [tuple(row) for row in cursor.fetchall()]
        return dumped
    finally:
        connection.close()


async def connect(path: Path, *, readonly: bool = False) -> aiosqlite.Connection:
    if readonly:
        uri = f"file:{path.resolve()}?mode=ro"
        connection = await aiosqlite.connect(uri, uri=True)
    else:
        connection = await aiosqlite.connect(path)
    connection.row_factory = aiosqlite.Row
    await connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _parse_timestamp(value: str) -> str:
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("invalid timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _check_limit(limit: int) -> int:
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1 or limit > MAX_TOOL_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_TOOL_LIMIT}")
    return limit


def _check_choice(value: str | None, allowed: set[str], label: str) -> str | None:
    if value is None:
        return None
    if value not in allowed:
        raise ValueError(f"unknown {label}: {value}")
    return value


def _like_pattern(pattern: str) -> str:
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise ValueError("pattern is too long")
    escaped = pattern.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _dt(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value)


def _log_tool(name: str, result_count: int) -> None:
    logger.info("tool call", extra={"tool": name, "result_count": result_count})


async def _require_service(connection: aiosqlite.Connection, service: str | None) -> int | None:
    if service is None:
        return None
    cursor = await connection.execute("SELECT id FROM services WHERE name = ?", (service,))
    row = await cursor.fetchone()
    if row is None:
        raise ValueError(f"unknown service: {service}")
    return int(row["id"])


def _incident_from_row(row: aiosqlite.Row) -> SecurityIncident:
    return SecurityIncident(
        id=row["id"],
        title=row["title"],
        service_id=row["service_id"],
        severity=row["severity"],
        owasp_category=row["owasp_category"],
        cwe_id=row["cwe_id"],
        status=row["status"],
        detected_at=_dt(row["detected_at"]),
        resolved_at=_dt(row["resolved_at"]),
        verified_at=_dt(row["verified_at"]),
        description=row["description"],
        root_cause=row["root_cause"],
    )


def _alert_from_row(row: aiosqlite.Row) -> SecurityAlert:
    return SecurityAlert(
        id=row["id"],
        detected_at=_dt(row["detected_at"]),
        service_id=row["service_id"],
        rule_id=row["rule_id"],
        alert_type=row["alert_type"],
        severity=row["severity"],
        confidence=row["confidence"],
        owasp_category=row["owasp_category"],
        cwe_id=row["cwe_id"],
        status=row["status"],
        description=row["description"],
    )


async def search_logs(
    database_path: Path,
    *,
    service: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    pattern: str | None = None,
    limit: int = 100,
) -> list[LogEvent]:
    limit = _check_limit(limit)
    start = _parse_timestamp(start_time) if start_time else None
    end = _parse_timestamp(end_time) if end_time else None
    clauses = ["1 = 1"]
    parameters: list[object] = []
    connection = await connect(database_path, readonly=True)
    try:
        service_id = await _require_service(connection, service)
        if service_id is not None:
            clauses.append("logs.service_id = ?")
            parameters.append(service_id)
        if start is not None:
            clauses.append("logs.timestamp >= ?")
            parameters.append(start)
        if end is not None:
            clauses.append("logs.timestamp <= ?")
            parameters.append(end)
        if pattern:
            clauses.append("logs.message LIKE ? ESCAPE '\\'")
            parameters.append(_like_pattern(pattern))
        parameters.append(limit)
        cursor = await connection.execute(
            f"""
            SELECT logs.* FROM logs
            WHERE {" AND ".join(clauses)}
            ORDER BY logs.timestamp, logs.id
            LIMIT ?
            """,
            parameters,
        )
        rows = await cursor.fetchall()
        events = [
            LogEvent(
                id=row["id"],
                timestamp=_dt(row["timestamp"]),
                service_id=row["service_id"],
                request_id=row["request_id"],
                actor_id=row["actor_id"],
                source_ip=row["source_ip"],
                method=row["method"],
                endpoint=row["endpoint"],
                http_status=row["http_status"],
                event_type=row["event_type"],
                message=row["message"],
                duration_ms=row["duration_ms"],
                alert_id=row["alert_id"],
            )
            for row in rows
        ]
        _log_tool("search_logs", len(events))
        return events
    finally:
        await connection.close()


async def search_incidents(
    database_path: Path,
    *,
    status: str | None = None,
    severity: str | None = None,
    service: str | None = None,
    cwe_id: str | None = None,
    as_of: str | None = None,
    limit: int = 100,
) -> list[SecurityIncident]:
    """Return incidents. When as_of is set, status is reconstructed from events."""
    limit = _check_limit(limit)
    status = _check_choice(status, INCIDENT_STATUSES, "incident status")
    severity = _check_choice(severity, SEVERITIES, "severity")
    moment = _parse_timestamp(as_of) if as_of else None
    clauses = ["incidents.detected_at <= ?"] if moment else ["1 = 1"]
    parameters: list[object] = [moment] if moment else []
    connection = await connect(database_path, readonly=True)
    try:
        service_id = await _require_service(connection, service)
        if service_id is not None:
            clauses.append("incidents.service_id = ?")
            parameters.append(service_id)
        if severity is not None:
            clauses.append("incidents.severity = ?")
            parameters.append(severity)
        if cwe_id is not None:
            clauses.append("incidents.cwe_id = ?")
            parameters.append(cwe_id)
        if status is not None and moment is None:
            clauses.append("incidents.status = ?")
            parameters.append(status)
        parameters.append(limit if moment is None else MAX_TOOL_LIMIT)
        cursor = await connection.execute(
            f"""
            SELECT incidents.* FROM incidents
            WHERE {" AND ".join(clauses)}
            ORDER BY incidents.detected_at, incidents.id
            LIMIT ?
            """,
            parameters,
        )
        rows = await cursor.fetchall()
        incidents: list[SecurityIncident] = []
        for row in rows:
            incident = _incident_from_row(row)
            if moment is not None:
                reconstructed = await _status_at(connection, incident.id, moment)
                if reconstructed is None:
                    continue
                incident = incident.model_copy(update={"status": reconstructed})
                if status is not None and reconstructed != status:
                    continue
            incidents.append(incident)
            if len(incidents) >= limit:
                break
        _log_tool("search_incidents", len(incidents))
        return incidents
    finally:
        await connection.close()


async def search_alerts(
    database_path: Path,
    *,
    status: str | None = None,
    severity: str | None = None,
    service: str | None = None,
    cwe_id: str | None = None,
    as_of: str | None = None,
    limit: int = 100,
) -> list[SecurityAlert]:
    limit = _check_limit(limit)
    status = _check_choice(status, ALERT_STATUSES, "alert status")
    severity = _check_choice(severity, SEVERITIES, "severity")
    moment = _parse_timestamp(as_of) if as_of else None
    clauses = ["1 = 1"]
    parameters: list[object] = []
    connection = await connect(database_path, readonly=True)
    try:
        service_id = await _require_service(connection, service)
        if service_id is not None:
            clauses.append("alerts.service_id = ?")
            parameters.append(service_id)
        if severity is not None:
            clauses.append("alerts.severity = ?")
            parameters.append(severity)
        if cwe_id is not None:
            clauses.append("alerts.cwe_id = ?")
            parameters.append(cwe_id)
        if status is not None:
            clauses.append("alerts.status = ?")
            parameters.append(status)
        if moment is not None:
            clauses.append("alerts.detected_at <= ?")
            parameters.append(moment)
        parameters.append(limit)
        cursor = await connection.execute(
            f"""
            SELECT alerts.* FROM alerts
            WHERE {" AND ".join(clauses)}
            ORDER BY alerts.detected_at DESC, alerts.id DESC
            LIMIT ?
            """,
            parameters,
        )
        rows = await cursor.fetchall()
        alerts = [_alert_from_row(row) for row in rows]
        _log_tool("search_alerts", len(alerts))
        return alerts
    finally:
        await connection.close()


async def _status_at(
    connection: aiosqlite.Connection, incident_id: int, timestamp: str
) -> str | None:
    cursor = await connection.execute(
        """
        SELECT new_status FROM incident_events
        WHERE incident_id = ? AND timestamp <= ?
        ORDER BY timestamp DESC, id DESC
        LIMIT 1
        """,
        (incident_id, timestamp),
    )
    row = await cursor.fetchone()
    if row is None:
        return None
    return str(row["new_status"])


async def get_incident_history(database_path: Path, incident_id: int) -> list[IncidentEvent]:
    connection = await connect(database_path, readonly=True)
    try:
        cursor = await connection.execute(
            """
            SELECT id, incident_id, timestamp, event_type, previous_status, new_status, description
            FROM incident_events
            WHERE incident_id = ?
            ORDER BY timestamp, id
            """,
            (incident_id,),
        )
        rows = await cursor.fetchall()
        events = [
            IncidentEvent(
                id=row["id"],
                incident_id=row["incident_id"],
                timestamp=_dt(row["timestamp"]),
                event_type=row["event_type"],
                previous_status=row["previous_status"],
                new_status=row["new_status"],
                description=row["description"],
            )
            for row in rows
        ]
        _log_tool("get_incident_history", len(events))
        return events
    finally:
        await connection.close()


async def incident_status_at(database_path: Path, incident_id: int, timestamp: str) -> str | None:
    moment = _parse_timestamp(timestamp)
    connection = await connect(database_path, readonly=True)
    try:
        exists = await connection.execute("SELECT 1 FROM incidents WHERE id = ?", (incident_id,))
        if await exists.fetchone() is None:
            _log_tool("incident_status_at", 0)
            return None
        status = await _status_at(connection, incident_id, moment)
        _log_tool("incident_status_at", 0 if status is None else 1)
        return status
    finally:
        await connection.close()


async def incident_id_for_alert(database_path: Path, alert_id: int) -> int | None:
    """Relationship-table lookup. Text similarity must not call this implicitly."""
    connection = await connect(database_path, readonly=True)
    try:
        cursor = await connection.execute(
            "SELECT incident_id FROM incident_alerts WHERE alert_id = ?",
            (alert_id,),
        )
        row = await cursor.fetchone()
        _log_tool("incident_id_for_alert", 0 if row is None else 1)
        return None if row is None else int(row["incident_id"])
    finally:
        await connection.close()


async def alerts_for_incident(database_path: Path, incident_id: int) -> list[SecurityAlert]:
    connection = await connect(database_path, readonly=True)
    try:
        cursor = await connection.execute(
            """
            SELECT alerts.*
            FROM alerts
            JOIN incident_alerts ON incident_alerts.alert_id = alerts.id
            WHERE incident_alerts.incident_id = ?
            ORDER BY alerts.detected_at, alerts.id
            """,
            (incident_id,),
        )
        rows = await cursor.fetchall()
        alerts = [_alert_from_row(row) for row in rows]
        _log_tool("alerts_for_incident", len(alerts))
        return alerts
    finally:
        await connection.close()


async def list_remediations(database_path: Path, incident_id: int) -> list[Remediation]:
    connection = await connect(database_path, readonly=True)
    try:
        cursor = await connection.execute(
            """
            SELECT id, incident_id, applied_at, fix_description, verification_status, verified_at, evidence
            FROM remediations
            WHERE incident_id = ?
            ORDER BY applied_at, id
            """,
            (incident_id,),
        )
        rows = await cursor.fetchall()
        return [
            Remediation(
                id=row["id"],
                incident_id=row["incident_id"],
                applied_at=_dt(row["applied_at"]),
                fix_description=row["fix_description"],
                verification_status=row["verification_status"],
                verified_at=_dt(row["verified_at"]),
                evidence=row["evidence"],
            )
            for row in rows
        ]
    finally:
        await connection.close()
