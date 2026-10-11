"""HTTP API for investigation, search, and evaluation."""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, Field

from security_investigator import __version__
from security_investigator.agent import InvestigationDeps, investigate
from security_investigator.config import Settings, get_settings, setup_logging
from security_investigator.database import (
    get_incident_history,
    list_remediations,
    search_alerts,
    search_incidents,
)
from security_investigator.evaluation import evaluate, generate_benchmark
from security_investigator.generator import generate_company
from security_investigator.llm import answer_model_from_settings, summarizer_from_settings
from security_investigator.models import (
    IncidentEvent,
    InvestigationResult,
    Remediation,
    RetrievedChunk,
    SecurityAlert,
    SecurityIncident,
)
from security_investigator.retrieval import bm25_search, dense_search, hybrid_search

logger = logging.getLogger(__name__)


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    version: str


class InvestigateRequest(BaseModel):
    question: str = Field(min_length=1, max_length=4000)
    as_of: datetime | None = None


class SearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=4000)
    top_k: int = Field(default=6, gt=0, le=50)
    mode: Literal["dense", "bm25", "hybrid"] = "hybrid"


class EvaluateRequest(BaseModel):
    limit: int = Field(default=5, ge=1, le=120)


class IncidentDetail(BaseModel):
    incident: SecurityIncident
    history: list[IncidentEvent]
    remediations: list[Remediation]


class EvaluationResponse(BaseModel):
    retrieval: list[dict[str, float | int | str]]
    investigation: list[dict[str, float | int | str]]
    question_count: int


def create_app(deps: InvestigationDeps | None = None, settings: Settings | None = None) -> FastAPI:
    active_settings = settings or (deps.settings if deps else None) or get_settings()
    setup_logging(active_settings.log_level)
    if deps is None:
        deps = InvestigationDeps(
            database_path=Path(active_settings.database_path),
            settings=active_settings,
        )
    elif deps.settings is None:
        deps.settings = active_settings
    if deps.chunk_summarizer is None:
        deps.chunk_summarizer = summarizer_from_settings(active_settings)
    if deps.answer_model is None:
        deps.answer_model = answer_model_from_settings(active_settings)
    app = FastAPI(title="Security Investigator", version=__version__)
    app.state.deps = deps

    @app.middleware("http")
    async def log_request(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        started = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - started) * 1000
        logger.info(
            "request complete",
            extra={
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method,
                "status_code": response.status_code,
                "duration_ms": round(elapsed_ms, 3),
            },
        )
        response.headers["x-request-id"] = request_id
        return response

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(status="ok", version=__version__)

    @app.post("/investigate", response_model=InvestigationResult)
    async def investigate_route(body: InvestigateRequest) -> InvestigationResult:
        _require_database(app.state.deps.database_path)
        try:
            return await investigate(body.question, as_of=body.as_of, deps=app.state.deps)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/search", response_model=list[RetrievedChunk])
    async def search_route(body: SearchRequest) -> list[RetrievedChunk]:
        active = app.state.deps
        _require_retrieval(active, body.mode)
        try:
            if body.mode == "dense":
                return await dense_search(
                    body.query,
                    top_k=body.top_k,
                    settings=active.settings,
                    embedder=active.embedder,
                    index=active.index,
                    chunks=active.chunks,
                )
            if body.mode == "bm25":
                return bm25_search(
                    body.query,
                    top_k=body.top_k,
                    chunks=active.chunks,
                    index=active.bm25_index,
                )
            return await hybrid_search(
                body.query,
                top_k=body.top_k,
                settings=active.settings,
                embedder=active.embedder,
                index=active.index,
                chunks=active.chunks,
                bm25_index=active.bm25_index,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.get("/incidents", response_model=list[SecurityIncident])
    async def incidents_route(
        status: str | None = None,
        severity: str | None = None,
        service: str | None = None,
        cwe_id: str | None = None,
        as_of: str | None = None,
        limit: int = Query(default=100, ge=1, le=200),
    ) -> list[SecurityIncident]:
        _require_database(app.state.deps.database_path)
        try:
            return await search_incidents(
                app.state.deps.database_path,
                status=status,
                severity=severity,
                service=service,
                cwe_id=cwe_id,
                as_of=as_of,
                limit=limit,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/incidents/{incident_id}", response_model=IncidentDetail)
    async def incident_route(incident_id: int, as_of: str | None = None) -> IncidentDetail:
        _require_database(app.state.deps.database_path)
        try:
            incidents = await search_incidents(
                app.state.deps.database_path,
                as_of=as_of,
                limit=200,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        incident = next((item for item in incidents if item.id == incident_id), None)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        return IncidentDetail(
            incident=incident,
            history=await get_incident_history(app.state.deps.database_path, incident_id),
            remediations=await list_remediations(app.state.deps.database_path, incident_id),
        )

    @app.get("/alerts", response_model=list[SecurityAlert])
    async def alerts_route(
        status: str | None = None,
        severity: str | None = None,
        service: str | None = None,
        cwe_id: str | None = None,
        as_of: str | None = None,
        limit: int = Query(default=100, ge=1, le=200),
    ) -> list[SecurityAlert]:
        _require_database(app.state.deps.database_path)
        try:
            return await search_alerts(
                app.state.deps.database_path,
                status=status,
                severity=severity,
                service=service,
                cwe_id=cwe_id,
                as_of=as_of,
                limit=limit,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/evaluate", response_model=EvaluationResponse)
    async def evaluate_route(body: EvaluateRequest) -> EvaluationResponse:
        active = app.state.deps
        _require_database(active.database_path)
        if active.index is None or active.embedder is None or active.chunks is None:
            raise HTTPException(status_code=503, detail="retrieval index is not configured")
        settings = active.settings or active_settings
        questions = generate_benchmark(
            generate_company(
                seed=settings.random_seed, reference_time=settings.reference_time
            ).manifest
        )[: body.limit]
        report = await evaluate(
            active.database_path,
            settings=settings,
            embedder=active.embedder,
            index=active.index,
            chunks=active.chunks,
            bm25_index=active.bm25_index,
            questions=questions,
            rerank_enabled=False,
            score_fn=active.score_fn,
        )
        return EvaluationResponse(
            retrieval=report["retrieval_summary"],
            investigation=report["investigation_summary"],
            question_count=len(questions),
        )

    return app


def _require_database(path: Path) -> None:
    if not path.exists():
        raise HTTPException(status_code=503, detail="security database is not built")


def _require_retrieval(deps: InvestigationDeps, mode: str) -> None:
    if mode in {"dense", "hybrid"} and (
        deps.index is None or deps.embedder is None or deps.chunks is None
    ):
        raise HTTPException(status_code=503, detail="retrieval index is not configured")
    if mode == "bm25" and deps.bm25_index is None and not deps.chunks:
        raise HTTPException(status_code=503, detail="retrieval index is not configured")


app = create_app()
