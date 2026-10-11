"""Chunking, local index files, and idempotent dense upserts."""

import hashlib
from pathlib import Path

import pytest

from security_investigator.config import Settings
from security_investigator.database import write_database
from security_investigator.generator import generate_company
from security_investigator.ingestion import (
    SourceDocument,
    build_chunks,
    chunk_document,
    content_hash,
    embed_query,
    ensure_indexable_path,
    export_knowledge_markdown,
    index_corpus,
    index_incoming,
    knowledge_documents,
    load_local_chunks,
    load_markdown,
    load_operational_documents,
    passage_text,
    upsert_chunks,
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


class MemoryIndex:
    def __init__(self) -> None:
        self.batches: list[tuple[str, list[dict]]] = []
        self.by_id: dict[tuple[str, str], dict] = {}

    def upsert(self, namespace: str, vectors: list[dict]) -> None:
        self.batches.append((namespace, list(vectors)))
        for vector in vectors:
            self.by_id[(namespace, vector["id"])] = vector


def test_knowledge_catalog_size_and_stable_chunk_ids() -> None:
    documents = knowledge_documents(_settings())
    assert 40 <= len(documents) <= 60
    first = build_chunks(documents)
    second = build_chunks(documents)
    assert [chunk["chunk_id"] for chunk in first] == [chunk["chunk_id"] for chunk in second]
    assert first[0]["chunk_id"] == "knowledge-001-001"
    assert first[0]["source_url"].startswith("https://")
    assert "CWE-89" in " ".join(chunk["text"] for chunk in first)
    assert "CWE-639" in " ".join(chunk["text"] for chunk in first)


def test_seeded_chunks_keep_the_written_summary() -> None:
    documents = knowledge_documents(Settings(_env_file=None))
    chunks = build_chunks(documents[:1])
    written = next(chunk for chunk in chunks if chunk["section"] == "Summary")
    other = next(chunk for chunk in chunks if chunk["section"] != "Summary")
    assert written["summary"] == written["text"]
    assert other["summary"] == written["text"]
    assert other["text"] != other["summary"]


def test_incoming_record_reuses_a_stored_summary(tmp_path: Path) -> None:
    class Once:
        calls = 0

        async def summarize(self, question: str, chunks: list[dict[str, str]]) -> dict[str, str]:
            Once.calls += 1
            return {chunks[0]["chunk_id"]: "New alert on the billing endpoint."}

    settings = Settings(_env_file=None, pinecone_api_key="")
    first = index_incoming(
        "GET /admin returned 200 for a user role.",
        title="New admin alert",
        source_id="alert-new",
        index_directory=tmp_path,
        settings=settings,
        summarizer=Once(),
        push=False,
    )
    second = index_incoming(
        "GET /admin returned 200 for a user role.",
        title="New admin alert",
        source_id="alert-new",
        index_directory=tmp_path,
        settings=settings,
        summarizer=Once(),
        push=False,
    )
    assert first["reused"] is False
    assert second["reused"] is True
    assert second["summary"] == "New alert on the billing endpoint."
    assert Once.calls == 1


def test_passage_text_can_embed_the_summary_with_the_original() -> None:
    chunk = {"text": "GET /admin returned 200.", "summary": "Possible broken access control."}
    assert passage_text(chunk, "original") == "GET /admin returned 200."
    assert passage_text(chunk, "summary") == "Possible broken access control."
    assert (
        passage_text(chunk, "contextual")
        == "Possible broken access control.\n\nGET /admin returned 200."
    )
    assert passage_text({"text": "only original"}, "summary") == "only original"


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
        namespace="security-v1-knowledge",
    )
    chunks = chunk_document(document)
    assert len(chunks) >= 2
    assert [chunk["chunk_id"] for chunk in chunks] == [
        "knowledge-900-001",
        "knowledge-900-002",
        *[chunk["chunk_id"] for chunk in chunks[2:]],
    ]
    assert {chunk["section"] for chunk in chunks} == {"Prevention"}


def test_evaluation_paths_are_refused(tmp_path: Path) -> None:
    banned = tmp_path / "data" / "scenarios" / "manifest.json"
    banned.parent.mkdir(parents=True)
    banned.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="evaluation data"):
        ensure_indexable_path(banned)
    with pytest.raises(ValueError, match="evaluation data"):
        load_markdown(banned, namespace="security-v1-knowledge")


def test_markdown_round_trip_and_operational_summaries_omit_raw_logs(tmp_path: Path) -> None:
    settings = _settings()
    export_knowledge_markdown(tmp_path / "knowledge", settings)
    loaded = load_markdown(
        tmp_path / "knowledge" / "knowledge-003.md", namespace=settings.namespace_knowledge
    )
    original = next(
        document
        for document in knowledge_documents(settings)
        if document.document_id == "knowledge-003"
    )
    assert loaded.title == original.title
    assert loaded.sections == original.sections

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


def test_upsert_is_idempotent_and_keeps_text_local(tmp_path: Path) -> None:
    settings = _settings()
    company = generate_company()
    database_path = tmp_path / "security.db"
    write_database(database_path, company.tables)
    index = MemoryIndex()
    manifest = index_corpus(
        database_path,
        tmp_path / "indexes",
        settings=settings,
        embedder=_embed,
        vector_index=index,
        push=True,
    )
    again = index_corpus(
        database_path,
        tmp_path / "indexes",
        settings=settings,
        embedder=_embed,
        vector_index=index,
        push=True,
    )
    assert manifest["content_hash"] == again["content_hash"]
    local = load_local_chunks(tmp_path / "indexes")
    assert len(local) == manifest["chunk_count"]
    assert content_hash(local) == manifest["content_hash"]
    assert len(index.by_id) == len(local)
    sample = next(iter(index.by_id.values()))
    assert "text" not in sample["metadata"]
    assert len(sample["values"]) == 384
    query_vector = embed_query("CWE-89", _embed, settings)
    assert query_vector != _embed(["CWE-89"])[0]


def test_dimension_mismatch_is_rejected() -> None:
    chunks = build_chunks(knowledge_documents(_settings()))[:1]
    with pytest.raises(ValueError, match="dimension"):
        vectors_for_chunks(chunks, [[0.1, 0.2]], dimension=384)
    upsert_chunks(MemoryIndex(), chunks, _embed([chunks[0]["text"]]), dimension=384)
