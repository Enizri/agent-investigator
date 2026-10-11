"""Dense, lexical, and fused retrieval over one local chunk corpus."""

from __future__ import annotations

import asyncio
import logging
import math
import re
import time
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from security_investigator.config import Settings, get_settings
from security_investigator.ingestion import (
    Embedder,
    embed_query,
    load_local_chunks,
    sentence_transformer_embedder,
)
from security_investigator.models import RetrievedChunk

logger = logging.getLogger(__name__)

TOKEN_PATTERN = re.compile(r"[a-z0-9]+(?:[._:/-][a-z0-9]+)*", re.IGNORECASE)
_reranker: Any = None
_reranker_name: str | None = None


class DenseIndex(Protocol):
    async def query(
        self,
        vector: Sequence[float],
        *,
        top_k: int,
        namespace: str | None = None,
        metadata_filter: Mapping[str, str] | None = None,
    ) -> list[tuple[str, float, dict[str, Any]]]: ...


class MemoryDenseIndex:
    """Cosine index used by tests and offline experiments. Production uses Pinecone."""

    def __init__(self) -> None:
        self.records: dict[tuple[str, str], dict[str, Any]] = {}

    def upsert(self, namespace: str, vectors: Sequence[Mapping[str, Any]]) -> None:
        for vector in vectors:
            self.records[(namespace, str(vector["id"]))] = {
                "id": vector["id"],
                "values": list(vector["values"]),
                "metadata": dict(vector.get("metadata") or {}),
                "namespace": namespace,
            }

    async def query(
        self,
        vector: Sequence[float],
        *,
        top_k: int,
        namespace: str | None = None,
        metadata_filter: Mapping[str, str] | None = None,
    ) -> list[tuple[str, float, dict[str, Any]]]:
        scored: list[tuple[float, str, dict[str, Any]]] = []
        for record in self.records.values():
            if namespace is not None and record["namespace"] != namespace:
                continue
            metadata = record["metadata"]
            if metadata_filter and any(
                metadata.get(key) != value for key, value in metadata_filter.items()
            ):
                continue
            scored.append((_cosine(vector, record["values"]), str(record["id"]), metadata))
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [(chunk_id, score, metadata) for score, chunk_id, metadata in scored[:top_k]]


class PineconeDenseIndex:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._index: Any = None

    def _client_index(self) -> Any:
        if self._index is None:
            from security_investigator.ingestion import PineconeVectorIndex

            sink = PineconeVectorIndex(self.settings)
            self._index = sink.ensure_index()
        return self._index

    async def query(
        self,
        vector: Sequence[float],
        *,
        top_k: int,
        namespace: str | None = None,
        metadata_filter: Mapping[str, str] | None = None,
    ) -> list[tuple[str, float, dict[str, Any]]]:
        def run() -> Any:
            pinecone_filter = None
            if metadata_filter:
                pinecone_filter = {key: {"$eq": value} for key, value in metadata_filter.items()}
            return self._client_index().query(
                vector=list(vector),
                top_k=top_k,
                namespace=namespace or "",
                filter=pinecone_filter,
                include_metadata=True,
                include_values=False,
            )

        response = await asyncio.to_thread(run)
        hits: list[tuple[str, float, dict[str, Any]]] = []
        for match in response.matches or []:
            metadata = dict(match.metadata or {})
            hits.append((str(match.id), float(match.score), metadata))
        return hits


def _cosine(left: Sequence[float], right: Sequence[float]) -> float:
    if len(left) != len(right) or not left:
        return 0.0
    dot = 0.0
    left_norm = 0.0
    right_norm = 0.0
    for a, b in zip(left, right, strict=True):
        dot += a * b
        left_norm += a * a
        right_norm += b * b
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    return dot / math.sqrt(left_norm * right_norm)


def chunk_lookup(chunks: Sequence[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    return {str(chunk["chunk_id"]): chunk for chunk in chunks}


def _hydrate(
    hits: Sequence[tuple[str, float, dict[str, Any]]],
    chunks: Mapping[str, Mapping[str, Any]],
    *,
    retrieval_method: str,
) -> list[RetrievedChunk]:
    hydrated: list[RetrievedChunk] = []
    for rank, (chunk_id, score, _metadata) in enumerate(hits, start=1):
        stored = chunks.get(chunk_id)
        if stored is None or not stored.get("text"):
            logger.info(
                "dropped retrieval hit with no local text",
                extra={"chunk_id": chunk_id, "retrieval_method": retrieval_method},
            )
            continue
        hydrated.append(
            RetrievedChunk(
                chunk_id=chunk_id,
                document_id=str(stored["document_id"]),
                text=str(stored["text"]),
                source_type=str(stored.get("source_type") or stored.get("document_type") or ""),
                source_id=str(stored.get("source_id") or ""),
                title=str(stored.get("title") or ""),
                score=float(score),
                retrieval_method=retrieval_method,
                dense_rank=rank if retrieval_method == "dense" else None,
                bm25_rank=rank if retrieval_method == "bm25" else None,
                summary=str(stored.get("summary") or _metadata.get("summary") or ""),
            )
        )
    return hydrated


def _namespaces(settings: Settings, namespace: str | None) -> list[str | None]:
    if namespace is not None:
        return [namespace]
    return [
        settings.namespace_knowledge,
        settings.namespace_incidents,
        settings.namespace_alerts,
    ]


async def dense_search(
    query: str,
    top_k: int = 20,
    *,
    namespace: str | None = None,
    document_type: str | None = None,
    settings: Settings | None = None,
    embedder: Embedder | None = None,
    index: DenseIndex | None = None,
    chunks: Sequence[Mapping[str, Any]] | None = None,
) -> list[RetrievedChunk]:
    """Variant A: embed the query and read a dense index. Text comes from the local store."""
    settings = settings or get_settings()
    active_embedder = embedder or sentence_transformer_embedder(settings.embedding_model)
    active_index = index or PineconeDenseIndex(settings)
    stored = chunk_lookup(chunks if chunks is not None else load_local_chunks(settings_index_dir()))
    vector = await asyncio.to_thread(embed_query, query, active_embedder, settings)
    metadata_filter = {"document_type": document_type} if document_type else None
    hits: list[tuple[str, float, dict[str, Any]]] = []
    for candidate_namespace in _namespaces(settings, namespace):
        hits.extend(
            await active_index.query(
                vector,
                top_k=top_k,
                namespace=candidate_namespace,
                metadata_filter=metadata_filter,
            )
        )
    hits.sort(key=lambda item: (-item[1], item[0]))
    deduped: list[tuple[str, float, dict[str, Any]]] = []
    seen: set[str] = set()
    for hit in hits:
        if hit[0] in seen:
            continue
        seen.add(hit[0])
        deduped.append(hit)
        if len(deduped) >= top_k:
            break
    return _hydrate(deduped, stored, retrieval_method="dense")


def settings_index_dir():
    from pathlib import Path

    return Path("data/indexes")


def tokenize(text: str) -> list[str]:
    """Keep identifiers such as CWE-89, CVE ids, paths, and rule ids as single tokens."""
    return [match.group(0).lower() for match in TOKEN_PATTERN.finditer(text)]


class BM25Index:
    def __init__(self, chunks: Sequence[Mapping[str, Any]]) -> None:
        from rank_bm25 import BM25Okapi

        self.chunks = list(chunks)
        self.tokenized = [tokenize(_search_text(chunk)) for chunk in self.chunks]
        self.engine = BM25Okapi(self.tokenized) if self.tokenized else None

    def search(
        self,
        query: str,
        top_k: int = 20,
        *,
        namespace: str | None = None,
        document_type: str | None = None,
    ) -> list[tuple[Mapping[str, Any], float]]:
        if self.engine is None or top_k <= 0:
            return []
        tokens = tokenize(query)
        if not tokens:
            return []
        scores = self.engine.get_scores(tokens)
        ranked = sorted(
            ((float(score), index) for index, score in enumerate(scores) if score > 0),
            key=lambda item: (-item[0], self.chunks[item[1]]["chunk_id"]),
        )
        matches: list[tuple[Mapping[str, Any], float]] = []
        for score, index in ranked:
            chunk = self.chunks[index]
            if namespace is not None and chunk.get("namespace") != namespace:
                continue
            if document_type is not None and chunk.get("document_type") != document_type:
                continue
            matches.append((chunk, score))
            if len(matches) >= top_k:
                break
        return matches


def _search_text(chunk: Mapping[str, Any]) -> str:
    return " ".join(
        str(chunk.get(field) or "")
        for field in ("title", "text", "source_id", "document_id", "section")
    )


def bm25_search(
    query: str,
    top_k: int = 20,
    *,
    namespace: str | None = None,
    document_type: str | None = None,
    chunks: Sequence[Mapping[str, Any]] | None = None,
    index: BM25Index | None = None,
) -> list[RetrievedChunk]:
    active = index or BM25Index(
        chunks if chunks is not None else load_local_chunks(settings_index_dir())
    )
    matches = active.search(query, top_k, namespace=namespace, document_type=document_type)
    hits = [(str(chunk["chunk_id"]), score, {}) for chunk, score in matches]
    stored = chunk_lookup(chunk for chunk, _score in matches)
    return _hydrate(hits, stored, retrieval_method="bm25")


def reciprocal_rank_fusion(
    rankings: Sequence[Sequence[RetrievedChunk]],
    *,
    k: int = 60,
) -> list[RetrievedChunk]:
    """Fuse rankings by reciprocal rank. Raw retriever scores are not combined."""
    fused: dict[str, float] = {}
    chosen: dict[str, RetrievedChunk] = {}
    dense_ranks: dict[str, int] = {}
    bm25_ranks: dict[str, int] = {}
    for ranking in rankings:
        for rank, chunk in enumerate(ranking, start=1):
            fused[chunk.chunk_id] = fused.get(chunk.chunk_id, 0.0) + (1.0 / (k + rank))
            chosen.setdefault(chunk.chunk_id, chunk)
            if chunk.retrieval_method == "dense":
                dense_ranks[chunk.chunk_id] = rank
            elif chunk.retrieval_method == "bm25":
                bm25_ranks[chunk.chunk_id] = rank
    ordered = sorted(fused, key=lambda chunk_id: (-fused[chunk_id], chunk_id))
    return [
        chosen[chunk_id].model_copy(
            update={
                "score": fused[chunk_id],
                "retrieval_method": "hybrid",
                "dense_rank": dense_ranks.get(chunk_id),
                "bm25_rank": bm25_ranks.get(chunk_id),
            }
        )
        for chunk_id in ordered
    ]


async def hybrid_search(
    query: str,
    top_k: int = 20,
    *,
    namespace: str | None = None,
    document_type: str | None = None,
    settings: Settings | None = None,
    embedder: Embedder | None = None,
    index: DenseIndex | None = None,
    chunks: Sequence[Mapping[str, Any]] | None = None,
    bm25_index: BM25Index | None = None,
    rrf_k: int | None = None,
) -> list[RetrievedChunk]:
    settings = settings or get_settings()
    dense, lexical = await asyncio.gather(
        dense_search(
            query,
            settings.top_k_dense,
            namespace=namespace,
            document_type=document_type,
            settings=settings,
            embedder=embedder,
            index=index,
            chunks=chunks,
        ),
        asyncio.to_thread(
            bm25_search,
            query,
            settings.top_k_bm25,
            namespace=namespace,
            document_type=document_type,
            chunks=chunks,
            index=bm25_index,
        ),
    )
    fused = reciprocal_rank_fusion(
        [dense, lexical], k=rrf_k if rrf_k is not None else settings.rrf_k
    )
    return fused[:top_k]


def load_reranker(model_name: str) -> Any:
    global _reranker, _reranker_name
    if _reranker is None or _reranker_name != model_name:
        from sentence_transformers import CrossEncoder

        _reranker = CrossEncoder(model_name)
        _reranker_name = model_name
    return _reranker


def rerank(
    query: str,
    candidates: Sequence[RetrievedChunk],
    top_k: int = 6,
    *,
    enabled: bool = True,
    score_fn: Any = None,
    model_name: str | None = None,
) -> list[RetrievedChunk]:
    """Order candidates by query-document relevance. The score is not a probability."""
    started = time.perf_counter()
    unique: list[RetrievedChunk] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate.chunk_id in seen:
            continue
        seen.add(candidate.chunk_id)
        unique.append(candidate)
    if not unique or not enabled:
        results = list(unique[:top_k])
    else:
        if score_fn is None:
            settings = get_settings()
            encoder = load_reranker(model_name or settings.reranker_model)

            def score_fn(pairs: Sequence[tuple[str, str]]) -> Sequence[float]:
                predicted = encoder.predict(list(pairs))
                return [float(score) for score in predicted]

        scores = list(score_fn([(query, candidate.text) for candidate in unique]))
        ordered = sorted(
            zip(unique, scores, strict=True),
            key=lambda item: (-float(item[1]), item[0].chunk_id),
        )
        results = [
            chunk.model_copy(update={"score": float(score)}) for chunk, score in ordered[:top_k]
        ]
    elapsed_ms = (time.perf_counter() - started) * 1000
    rerank.last_latency_ms = elapsed_ms  # type: ignore[attr-defined]
    logger.info(
        "rerank complete",
        extra={
            "rerank_latency_ms": round(elapsed_ms, 3),
            "candidate_count": len(candidates),
            "result_count": len(results),
            "enabled": enabled,
        },
    )
    return results


async def rerank_async(
    query: str,
    candidates: Sequence[RetrievedChunk],
    top_k: int = 6,
    *,
    enabled: bool = True,
    score_fn: Any = None,
) -> list[RetrievedChunk]:
    return await asyncio.to_thread(
        rerank,
        query,
        candidates,
        top_k,
        enabled=enabled,
        score_fn=score_fn,
    )


async def search_knowledge(
    query: str,
    top_k: int = 6,
    *,
    namespace: str | None = None,
    document_type: str | None = None,
    settings: Settings | None = None,
    embedder: Embedder | None = None,
    index: DenseIndex | None = None,
    chunks: Sequence[Mapping[str, Any]] | None = None,
    bm25_index: BM25Index | None = None,
    rerank_enabled: bool | None = None,
    score_fn: Any = None,
) -> list[RetrievedChunk]:
    """Hybrid retrieval followed by the cross-encoder, unless reranking is disabled."""
    settings = settings or get_settings()
    candidates = await hybrid_search(
        query,
        top_k=max(top_k, settings.top_k_dense),
        namespace=namespace,
        document_type=document_type,
        settings=settings,
        embedder=embedder,
        index=index,
        chunks=chunks,
        bm25_index=bm25_index,
    )
    enabled = settings.rerank_enabled if rerank_enabled is None else rerank_enabled
    if not enabled:
        return candidates[:top_k]
    return await rerank_async(query, candidates, top_k, enabled=True, score_fn=score_fn)
