"""Chunking and the seeded preprocess index."""

import hashlib
import threading
import time
from pathlib import Path

import pytest

from security_investigator.config import Settings
from security_investigator.database import write_database
from security_investigator.generator import generate_company
from security_investigator.preprocess import (
    SourceDocument,
    build_chunks,
    chunk_document,
    content_hash,
    embed_query,
    knowledge_documents,
    limit_documents,
    load_local_chunks,
    load_operational_documents,
    load_vectors,
    preprocess_corpus,
    situate_chunks,
    vectors_for_chunks,
)


def _settings() -> Settings:
    return Settings(_env_file=None)


def _embed(texts: list[str]) -> list[list[float]]:
    vectors: list[list[float]] = []
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


def test_knowledge_catalog_size_and_stable_chunk_ids() -> None:
    documents = knowledge_documents(_settings())
    assert 40 <= len(documents) <= 60
    first = build_chunks(documents)
    second = build_chunks(documents)
    assert [chunk["chunk_id"] for chunk in first] == [chunk["chunk_id"] for chunk in second]
    assert first[0]["chunk_id"] == "knowledge-001-001"
    assert first[0]["source_url"].startswith("https://")
    assert first[0]["context"] == ""
    assert "CWE-89" in " ".join(chunk["text"] for chunk in first)
    assert "CWE-639" in " ".join(chunk["text"] for chunk in first)


def test_long_section_splits_without_changing_ids_fields() -> None:
    paragraph = "authorization boundary " * 80
    document = SourceDocument(
        document_id="knowledge-900",
        title="Long note",
        source_url="https://example.org/long",
        document_type="security_knowledge",
        taxonomy_version="OWASP Top 10:2025",
        sections=(("Prevention", "\n\n".join([paragraph, paragraph, paragraph])),),
        source_id="knowledge-900",
        license="test",
        namespace="knowledge",
    )
    chunks = chunk_document(document)
    assert len(chunks) >= 2
    assert chunks[0]["chunk_id"] == "knowledge-900-001"
    assert chunks[1]["chunk_id"] == "knowledge-900-002"
    assert {chunk["section"] for chunk in chunks} == {"Prevention"}


def test_operational_summaries_omit_raw_logs(tmp_path: Path) -> None:
    settings = _settings()
    company = generate_company()
    database_path = tmp_path / "security.db"
    write_database(database_path, company.tables)
    operational = load_operational_documents(database_path, settings)
    chunks = build_chunks(operational)
    blob = "\n".join(chunk["text"] for chunk in chunks)
    assert "Ignore previous instructions" not in blob
    incident = next(chunk for chunk in chunks if chunk["document_id"] == "incident-001")
    assert incident["source_id"] == "1"
    assert "resolved" in incident["text"]
    assert incident["namespace"] == settings.namespace_incidents


async def test_preprocess_situates_once_and_embeds_both_texts(tmp_path: Path) -> None:
    settings = _settings()
    company = generate_company()
    database_path = tmp_path / "security.db"
    write_database(database_path, company.tables)
    calls = {"count": 0}
    lock = threading.Lock()

    def situate(document: str, chunk: str) -> str:
        with lock:
            calls["count"] += 1
        assert document
        assert chunk
        return "Situating sentence for this chunk."

    index_directory = tmp_path / "indexes"
    manifest = await preprocess_corpus(
        database_path,
        index_directory,
        settings=settings,
        situate=situate,
        embedder=_embed,
    )
    again = await preprocess_corpus(
        database_path,
        index_directory,
        settings=settings,
        situate=situate,
        embedder=_embed,
    )
    assert manifest["content_hash"] == again["content_hash"]
    assert calls["count"] == manifest["chunk_count"]
    local = load_local_chunks(index_directory)
    assert len(local) == manifest["chunk_count"]
    assert content_hash(local) == manifest["content_hash"]
    sample = next(chunk for chunk in local if chunk["document_id"] == "incident-001")
    assert sample["context"] == "Situating sentence for this chunk."
    assert sample["contextualized"].startswith(sample["context"])
    assert sample["text"] not in sample["context"]
    basic = load_vectors(index_directory / "basic_embeddings.json")
    contextual = load_vectors(index_directory / "contextual_embeddings.json")
    assert len(basic) == len(local) == len(contextual)
    assert len(basic[0]) == 384
    assert basic[0] != contextual[0]
    query_vector = embed_query("CWE-89", _embed, settings)
    assert query_vector != _embed(["CWE-89"])[0]


async def test_situate_chunks_runs_on_several_workers() -> None:
    documents = [
        SourceDocument(
            document_id=f"knowledge-{index:03d}",
            title=f"Note {index}",
            source_url="https://example.org/note",
            document_type="security_knowledge",
            taxonomy_version="OWASP Top 10:2025",
            sections=(("Summary", f"chunk body {index}"),),
            source_id=f"knowledge-{index:03d}",
            license="test",
            namespace="knowledge",
        )
        for index in range(1, 7)
    ]
    chunks = build_chunks(documents)
    threads: set[int] = set()
    lock = threading.Lock()

    def situate(document: str, chunk: str) -> str:
        with lock:
            threads.add(threading.get_ident())
        time.sleep(0.05)
        return f"context for {chunk}"

    situated = await situate_chunks(documents, chunks, situate, workers=4)
    assert [chunk["context"] for chunk in situated] == [
        f"context for chunk body {index}" for index in range(1, 7)
    ]
    assert len(threads) > 1


async def test_preprocess_limit_indexes_only_the_first_chunks(tmp_path: Path) -> None:
    database_path = tmp_path / "security.db"
    write_database(database_path, generate_company().tables)

    def situate(document: str, chunk: str) -> str:
        return "short context"

    manifest = await preprocess_corpus(
        database_path,
        tmp_path / "indexes",
        settings=_settings(),
        situate=situate,
        embedder=_embed,
        limit=2,
    )
    assert manifest["chunk_count"] == 2
    assert len(load_local_chunks(tmp_path / "indexes")) == 2
    with pytest.raises(ValueError, match="limit"):
        await preprocess_corpus(
            database_path,
            tmp_path / "other",
            settings=_settings(),
            situate=situate,
            embedder=_embed,
            limit=0,
        )


def _document(document_id: str, document_type: str) -> SourceDocument:
    return SourceDocument(
        document_id=document_id,
        title=document_id,
        source_url="internal://test",
        document_type=document_type,
        taxonomy_version="OWASP Top 10:2025",
        sections=(("Summary", document_id),),
        source_id=document_id,
        license="internal synthetic record",
        namespace=document_type,
    )


def test_document_limit_keeps_a_mix_of_types() -> None:
    documents = (
        [_document(f"knowledge-{index}", "knowledge") for index in range(4)]
        + [_document(f"incident-{index}", "incident_report") for index in range(4)]
        + [_document(f"alert-{index}", "alert_summary") for index in range(4)]
    )
    chosen = limit_documents(documents, 6)
    assert [document.document_id for document in chosen] == [
        "knowledge-0",
        "incident-0",
        "alert-0",
        "knowledge-1",
        "incident-1",
        "alert-1",
    ]


def test_dimension_mismatch_is_rejected() -> None:
    chunks = build_chunks(knowledge_documents(_settings()))[:1]
    try:
        vectors_for_chunks(chunks, [[0.1, 0.2]], dimension=384)
    except ValueError as exc:
        assert "dimension" in str(exc)
    else:
        raise AssertionError("expected a dimension error")
