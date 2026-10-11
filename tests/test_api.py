"""HTTP routes for investigation, search, and evaluation."""

import hashlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from security_investigator.agent import InvestigationDeps
from security_investigator.api import create_app
from security_investigator.config import Settings
from security_investigator.database import write_database
from security_investigator.generator import generate_company
from security_investigator.ingestion import vectors_for_chunks
from security_investigator.retrieval import BM25Index, MemoryDenseIndex


def _embed(texts: list[str]) -> list[list[float]]:
    vectors = []
    for text in texts:
        digest = hashlib.sha256(text.encode()).digest()
        values: list[float] = []
        counter = 0
        while len(values) < 384:
            block = hashlib.sha256(digest + counter.to_bytes(4, "little")).digest()
            values.extend((byte / 127.5) - 1 for byte in block)
            counter += 1
        vectors.append(values[:384])
    return vectors


@pytest.fixture(scope="module")
def client(tmp_path_factory: pytest.TempPathFactory) -> TestClient:
    database_path = tmp_path_factory.mktemp("api") / "security.db"
    write_database(database_path, generate_company().tables)
    settings = Settings(_env_file=None)
    chunks = [
        {
            "chunk_id": "knowledge-001-001",
            "document_id": "knowledge-001",
            "document_type": "knowledge",
            "source_type": "knowledge",
            "source_id": "CWE-89",
            "title": "SQL injection",
            "section": "summary",
            "text": "SQL injection CWE-89 uses parameterized queries.",
            "namespace": settings.namespace_knowledge,
        },
        {
            "chunk_id": "knowledge-002-001",
            "document_id": "knowledge-002",
            "document_type": "knowledge",
            "source_type": "knowledge",
            "source_id": "CWE-639",
            "title": "Broken access control",
            "section": "summary",
            "text": "Authorization checks belong on the server.",
            "namespace": settings.namespace_knowledge,
        },
        {
            "chunk_id": "knowledge-003-001",
            "document_id": "knowledge-003",
            "document_type": "knowledge",
            "source_type": "knowledge",
            "source_id": "CWE-79",
            "title": "Output encoding",
            "section": "summary",
            "text": "Browsers need encoded output.",
            "namespace": settings.namespace_knowledge,
        },
    ]
    memory = MemoryDenseIndex()
    embeddings = _embed([chunk["text"] for chunk in chunks])
    for namespace, vectors in vectors_for_chunks(chunks, embeddings, dimension=384).items():
        memory.upsert(namespace, vectors)
    class KeepDraft:
        async def complete(self, prompt: str) -> str:
            return str(json.loads(prompt)["draft"])

    deps = InvestigationDeps(
        database_path=database_path,
        settings=settings,
        embedder=_embed,
        index=memory,
        chunks=chunks,
        bm25_index=BM25Index(chunks),
        rerank_enabled=False,
        answer_model=KeepDraft(),
    )
    return TestClient(create_app(deps=deps, settings=settings))


def test_health_and_request_id(client: TestClient) -> None:
    response = client.get("/health", headers={"x-request-id": "req-test"})
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.headers["x-request-id"] == "req-test"


def test_investigate_returns_a_cited_result(client: TestClient) -> None:
    response = client.post(
        "/investigate",
        json={"question": "Which critical incidents are active on user-service?"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["trace_id"].startswith("trace-")
    assert any(finding["incident_id"] == 2 for finding in body["findings"])
    assert "company is secure" not in body["answer"]


def test_invalid_requests_are_422(client: TestClient) -> None:
    assert client.post("/investigate", json={"question": ""}).status_code == 422
    assert (
        client.post("/investigate", json={"question": "status", "as_of": "yesterday"}).status_code
        == 422
    )
    assert client.get("/incidents", params={"status": "closed", "limit": 10}).status_code == 422
    assert client.get("/incidents", params={"limit": 500}).status_code == 422
    assert client.get("/alerts", params={"as_of": "not-a-time"}).status_code == 422
    assert client.post("/search", json={"query": "CWE-89", "top_k": 0}).status_code == 422


def test_incident_and_alert_reads(client: TestClient) -> None:
    missing = client.get("/incidents/999999")
    assert missing.status_code == 404
    detail = client.get("/incidents/2")
    assert detail.status_code == 200
    assert detail.json()["incident"]["status"] == "open"
    assert detail.json()["history"]
    incidents = client.get("/incidents", params={"severity": "critical", "status": "open"})
    assert incidents.status_code == 200
    assert any(item["id"] == 2 for item in incidents.json())
    alerts = client.get("/alerts", params={"service": "billing-service", "limit": 20})
    assert alerts.status_code == 200
    assert alerts.json()


def test_search_and_evaluate(client: TestClient) -> None:
    lexical = client.post("/search", json={"query": "CWE-89", "mode": "bm25", "top_k": 3})
    assert lexical.status_code == 200
    assert lexical.json()[0]["chunk_id"] == "knowledge-001-001"
    dense = client.post("/search", json={"query": "SQL injection", "mode": "dense", "top_k": 3})
    assert dense.status_code == 200
    assert dense.json()[0]["retrieval_method"] == "dense"
    evaluated = client.post("/evaluate", json={"limit": 1})
    assert evaluated.status_code == 200
    body = evaluated.json()
    assert body["question_count"] == 1
    assert {row["variant"] for row in body["retrieval"]} == {
        "A_dense",
        "B_bm25",
        "C_hybrid",
        "D_reranked",
    }


def test_missing_database_and_index_are_503(tmp_path: Path) -> None:
    settings = Settings(_env_file=None)
    missing = TestClient(
        create_app(
            deps=InvestigationDeps(database_path=tmp_path / "missing.db", settings=settings),
            settings=settings,
        )
    )
    assert (
        missing.post("/investigate", json={"question": "Which incidents are open?"}).status_code
        == 503
    )
    assert missing.post("/search", json={"query": "CWE-89", "mode": "dense"}).status_code == 503
    assert missing.post("/evaluate", json={"limit": 1}).status_code == 503
