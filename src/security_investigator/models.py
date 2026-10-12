"""Domain models shared by the database, retrieval, agent, and API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

AlertStatus = Literal[
    "new",
    "investigating",
    "closed_false_positive",
    "closed_expected_behavior",
    "linked_to_incident",
]

IncidentStatus = Literal[
    "open",
    "investigating",
    "mitigated",
    "resolved",
    "reopened",
    "false_positive",
]

Severity = Literal["critical", "high", "medium", "low", "info"]

VerificationStatus = Literal["pending", "verified", "failed"]

DocumentType = Literal["security_knowledge", "incident_report", "alert_summary"]


class LogEvent(BaseModel):
    id: int
    timestamp: datetime
    service_id: int
    request_id: str
    actor_id: str | None = None
    source_ip: str | None = None
    method: str | None = None
    endpoint: str | None = None
    http_status: int | None = None
    event_type: str
    message: str
    duration_ms: int | None = None
    alert_id: int | None = None


class SecurityAlert(BaseModel):
    id: int
    detected_at: datetime
    service_id: int
    rule_id: str
    alert_type: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    owasp_category: str | None = None
    cwe_id: str | None = None
    status: AlertStatus
    description: str


class SecurityIncident(BaseModel):
    id: int
    title: str
    service_id: int
    severity: Severity
    owasp_category: str | None = None
    cwe_id: str | None = None
    status: IncidentStatus
    detected_at: datetime
    resolved_at: datetime | None = None
    verified_at: datetime | None = None
    description: str
    root_cause: str | None = None


class IncidentEvent(BaseModel):
    id: int
    incident_id: int
    timestamp: datetime
    event_type: str
    previous_status: IncidentStatus | None = None
    new_status: IncidentStatus
    description: str


class Remediation(BaseModel):
    id: int
    incident_id: int
    applied_at: datetime
    fix_description: str
    verification_status: VerificationStatus
    verified_at: datetime | None = None
    evidence: str | None = None


class SecurityDocument(BaseModel):
    document_id: str
    title: str
    source_url: str
    document_type: DocumentType
    taxonomy_version: str
    text: str
    section: str | None = None


class RetrievedChunk(BaseModel):
    chunk_id: str
    document_id: str
    text: str
    source_type: str
    source_id: str
    title: str
    score: float
    retrieval_method: str
    dense_rank: int | None = None
    bm25_rank: int | None = None
    summary: str = ""


class ChunkSummaryPair(BaseModel):
    """One retrieved chunk and the situating sentence stored with it."""

    chunk_id: str
    text: str
    summary: str


class EvidenceReference(BaseModel):
    evidence_id: str
    source_type: str
    source_id: str
    description: str


class Finding(BaseModel):
    incident_id: int | None = None
    alert_id: int | None = None
    status: str
    severity: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)


class InvestigationResult(BaseModel):
    answer: str
    findings: list[Finding] = Field(default_factory=list)
    unverified_alerts: list[int] = Field(default_factory=list)
    citations: list[EvidenceReference] = Field(default_factory=list)
    chunk_pairs: list[ChunkSummaryPair] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    as_of: datetime | None = None
    trace_id: str | None = None
