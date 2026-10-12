"""Dense, BM25, fusion, and rerank behavior without external services."""

import hashlib

import pytest

from security_investigator.config import Settings
from security_investigator.models import RetrievedChunk
from security_investigator.preprocess import vectors_for_chunks
from security_investigator.retrieval import (
    BM25Index,
    MemoryDenseIndex,
    bm25_search,
    dense_search,
    hybrid_search,
    rank_fusion,
    rerank,
    search_knowledge,
    tokenize,
)


def _settings() -> Settings:
    return Settings(_env_file=None)


def _embed(texts: list[str]) -> list[list[float]]:
    vocabulary = ("cwe-89", "cwe-639", "sql injection", "broken access")
    vectors: list[list[float]] = []
    for text in texts:
        lowered = text.lower()
        vector = [0.0] * 384
        for index, term in enumerate(vocabulary):
            if term in lowered:
                vector[index] = 1.0
        if not any(vector):
            digest = hashlib.sha256(lowered.encode()).digest()
            vector[10] = (digest[0] / 255) or 0.01
        vectors.append(vector)
    return vectors


def _chunks() -> list[dict[str, str]]:
    settings = _settings()
    return [
        {
            "chunk_id": "knowledge-003-001",
            "document_id": "knowledge-003",
            "title": "Injection",
            "source_url": "https://owasp.org/Top10/2025/A05_2025-Injection/",
            "section": "Summary",
            "document_type": "security_knowledge",
            "taxonomy_version": "OWASP Top 10:2025",
            "text": "Injection is A05:2025. CWE-89 is SQL injection.",
            "source_id": "knowledge-003",
            "source_type": "security_knowledge",
            "license": "CC BY-SA 4.0",
            "namespace": settings.namespace_knowledge,
        },
        {
            "chunk_id": "knowledge-001-001",
            "document_id": "knowledge-001",
            "title": "Broken Access Control",
            "source_url": "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/",
            "section": "Summary",
            "document_type": "security_knowledge",
            "taxonomy_version": "OWASP Top 10:2025",
            "text": "Broken access control includes CWE-639.",
            "source_id": "knowledge-001",
            "source_type": "security_knowledge",
            "license": "CC BY-SA 4.0",
            "namespace": settings.namespace_knowledge,
        },
        {
            "chunk_id": "incident-001-001",
            "document_id": "incident-001",
            "title": "SQL injection in billing invoice search",
            "source_url": "internal://incidents/1",
            "section": "Summary",
            "document_type": "incident_report",
            "taxonomy_version": "A05:2025-Injection",
            "text": "Incident 1 status resolved. CWE-89 billing invoice search.",
            "source_id": "1",
            "source_type": "incident_report",
            "license": "internal synthetic record",
            "namespace": settings.namespace_incidents,
        },
    ]


def _index(chunks: list[dict[str, str]]) -> MemoryDenseIndex:
    index = MemoryDenseIndex()
    grouped = vectors_for_chunks(chunks, _embed([chunk["text"] for chunk in chunks]), dimension=384)
    for namespace, vectors in grouped.items():
        index.upsert(namespace, vectors)
    return index


def _chunk(chunk_id: str, method: str, score: float) -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id=chunk_id,
        document_id=chunk_id,
        text=chunk_id,
        source_type="security_knowledge",
        source_id=chunk_id,
        title=chunk_id,
        score=score,
        retrieval_method=method,
    )


def test_tokenizer_keeps_technical_identifiers() -> None:
    tokens = tokenize("Explain CWE-89 and CVE-2099-10042 on /v1/invoices rule RULE-CWE-89-BLOCK")
    assert "cwe-89" in tokens
    assert "cve-2099-10042" in tokens
    assert "v1/invoices" in tokens
    assert "rule-cwe-89-block" in tokens


async def test_dense_search_hydrates_local_text_and_drops_unknown_ids() -> None:
    chunks = _chunks()
    index = _index(chunks)
    index.upsert(
        _settings().namespace_knowledge,
        [{"id": "missing-chunk", "values": _embed(["CWE-89 SQL injection"])[0], "metadata": {}}],
    )
    results = await dense_search(
        "What is CWE-89 SQL injection?",
        top_k=5,
        settings=_settings(),
        embedder=_embed,
        index=index,
        chunks=chunks,
    )
    assert results
    assert all(result.chunk_id != "missing-chunk" for result in results)
    assert all(result.text for result in results)
    assert all(result.retrieval_method == "dense" for result in results)
    assert results[0].chunk_id in {"knowledge-003-001", "incident-001-001"}


async def test_dense_search_filters_document_type() -> None:
    chunks = _chunks()
    results = await dense_search(
        "CWE-89 SQL injection",
        top_k=5,
        document_type="incident_report",
        settings=_settings(),
        embedder=_embed,
        index=_index(chunks),
        chunks=chunks,
    )
    assert results
    assert {result.source_type for result in results} == {"incident_report"}


def test_bm25_ranks_exact_identifiers_first() -> None:
    chunks = _chunks()
    results = bm25_search("CWE-89", top_k=3, chunks=chunks, index=BM25Index(chunks))
    assert results[0].chunk_id == "knowledge-003-001"
    assert results[0].retrieval_method == "bm25"
    assert results[0].bm25_rank == 1
    filtered = bm25_search(
        "CWE-89",
        top_k=3,
        document_type="incident_report",
        chunks=chunks,
        index=BM25Index(chunks),
    )
    assert [result.chunk_id for result in filtered] == ["incident-001-001"]


def test_rank_fusion_weights_dense_above_bm25() -> None:
    dense = [_chunk("a", "dense", 0.1), _chunk("b", "dense", 0.2)]
    lexical = [_chunk("b", "bm25", 50), _chunk("c", "bm25", 10)]
    fused = rank_fusion(dense, lexical, semantic_weight=0.8, bm25_weight=0.2)
    assert [item.chunk_id for item in fused] == ["a", "b", "c"]
    assert fused[0].score == pytest.approx(1.0)
    assert fused[0].dense_rank == 1
    assert fused[1].dense_rank == 2
    assert fused[1].bm25_rank == 1
    assert len({item.chunk_id for item in fused}) == 3


async def test_hybrid_search_blends_dense_and_bm25() -> None:
    chunks = _chunks()
    results = await hybrid_search(
        "CWE-89",
        top_k=3,
        settings=_settings(),
        embedder=_embed,
        index=_index(chunks),
        chunks=chunks,
        bm25_index=BM25Index(chunks),
    )
    assert results
    assert all(result.retrieval_method == "hybrid" for result in results)
    assert results[0].chunk_id in {"knowledge-003-001", "incident-001-001"}
    assert results[0].score > 0


def test_rerank_is_stable_and_keeps_ids() -> None:
    candidates = [
        _chunk("b", "hybrid", 0.2),
        _chunk("a", "hybrid", 0.9),
        _chunk("b", "hybrid", 0.3),
        _chunk("c", "hybrid", 0.1),
    ]
    candidates[0] = candidates[0].model_copy(update={"text": "sql injection cwe-89"})
    candidates[1] = candidates[1].model_copy(update={"text": "unrelated billing note"})
    candidates[3] = candidates[3].model_copy(update={"text": "cwe-89 sql"})

    def score(pairs: list[tuple[str, str]]) -> list[float]:
        return [float(text.lower().count("cwe-89")) for _query, text in pairs]

    ranked = rerank("cwe-89", candidates, top_k=2, score_fn=score)
    assert [item.chunk_id for item in ranked] == ["b", "c"]
    assert ranked[0].document_id == "b"
    assert rerank.last_latency_ms >= 0

    again = rerank("cwe-89", candidates, top_k=2, score_fn=score)
    assert [item.chunk_id for item in again] == [item.chunk_id for item in ranked]

    assert rerank("cwe-89", [], top_k=6, score_fn=score) == []
    disabled = rerank("cwe-89", candidates, top_k=2, enabled=False, score_fn=score)
    assert [item.chunk_id for item in disabled] == ["b", "a"]


async def test_search_knowledge_can_skip_the_reranker() -> None:
    chunks = _chunks()
    results = await search_knowledge(
        "CWE-89",
        top_k=2,
        settings=_settings(),
        embedder=_embed,
        index=_index(chunks),
        chunks=chunks,
        bm25_index=BM25Index(chunks),
        rerank_enabled=False,
    )
    assert results
    assert all(result.retrieval_method == "hybrid" for result in results)
