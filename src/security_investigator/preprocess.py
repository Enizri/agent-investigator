"""Chunk seeded documents, situate each chunk, and save the local indexes."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tqdm.auto import tqdm

from security_investigator.config import Settings, get_settings
from security_investigator.database import connect_sync
from security_investigator.knowledge_catalog import knowledge_records
from security_investigator.llm import situate_context

TOKEN_PER_WORD = 1.3
TARGET_TOKENS = 400
MAX_TOKENS = 500
WORD_WINDOW = 350
TOP10_FALLBACK = "OWASP Top 10:2025"
METADATA_FIELDS = ("document_id", "document_type", "source_id", "title", "section")

Embedder = Callable[[Sequence[str]], list[list[float]]]
Situator = Callable[[str, str], str]
_embedding_model: Any = None
_embedding_model_name: str | None = None


@dataclass(frozen=True)
class SourceDocument:
    document_id: str
    title: str
    source_url: str
    document_type: str
    taxonomy_version: str
    sections: tuple[tuple[str, str], ...]
    source_id: str
    license: str
    namespace: str


def estimate_tokens(text: str) -> int:
    words = text.split()
    if not words:
        return 0
    return max(1, round(len(words) * TOKEN_PER_WORD))


def normalize_text(text: str) -> str:
    cleaned = text.replace("\r\n", "\n").replace("\r", "\n")
    cleaned = re.sub(r"[ \t]+", " ", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def chunk_section(section: str, text: str) -> list[tuple[str, str]]:
    normalized = normalize_text(text)
    if not normalized:
        return []
    if estimate_tokens(normalized) <= MAX_TOKENS:
        return [(section, normalized)]
    paragraphs = [part.strip() for part in re.split(r"\n\s*\n", normalized) if part.strip()]
    pieces: list[tuple[str, str]] = []
    buffer: list[str] = []
    tokens = 0

    def flush() -> None:
        nonlocal buffer, tokens
        if buffer:
            pieces.append((section, "\n\n".join(buffer)))
            buffer = []
            tokens = 0

    for paragraph in paragraphs:
        piece_tokens = estimate_tokens(paragraph)
        if piece_tokens > MAX_TOKENS:
            flush()
            words = paragraph.split()
            for start in range(0, len(words), WORD_WINDOW):
                pieces.append((section, " ".join(words[start : start + WORD_WINDOW])))
            continue
        if buffer and tokens + piece_tokens > MAX_TOKENS:
            flush()
        buffer.append(paragraph)
        tokens += piece_tokens
        if tokens >= TARGET_TOKENS:
            flush()
    flush()
    return pieces


def document_text(document: SourceDocument) -> str:
    parts = [document.title]
    for name, text in document.sections:
        parts.append(f"{name}\n{text}")
    return "\n\n".join(parts)


def chunk_document(document: SourceDocument) -> list[dict[str, str]]:
    chunks: list[dict[str, str]] = []
    for section, text in document.sections:
        for section_name, body in chunk_section(section, text):
            ordinal = len(chunks) + 1
            chunks.append(
                {
                    "chunk_id": f"{document.document_id}-{ordinal:03d}",
                    "document_id": document.document_id,
                    "title": document.title,
                    "source_url": document.source_url,
                    "section": section_name,
                    "document_type": document.document_type,
                    "taxonomy_version": document.taxonomy_version,
                    "text": body,
                    "context": "",
                    "contextualized": body,
                    "source_id": document.source_id,
                    "source_type": document.document_type,
                    "license": document.license,
                    "namespace": document.namespace,
                }
            )
    return chunks


def knowledge_documents(settings: Settings | None = None) -> list[SourceDocument]:
    settings = settings or get_settings()
    documents: list[SourceDocument] = []
    for record in knowledge_records():
        documents.append(
            SourceDocument(
                document_id=record["document_id"],
                title=record["title"],
                source_url=record["source_url"],
                document_type=record["document_type"],
                taxonomy_version=record["taxonomy_version"],
                sections=tuple(record["sections"].items()),
                source_id=record["document_id"],
                license=record["license"],
                namespace=settings.namespace_knowledge,
            )
        )
    return documents


def load_operational_documents(
    database_path: Path, settings: Settings | None = None
) -> list[SourceDocument]:
    """Sanitized incident and alert summaries. Raw log bodies are not included."""
    settings = settings or get_settings()
    connection = connect_sync(database_path)
    try:
        documents: list[SourceDocument] = []
        incidents = connection.execute(
            """
            SELECT incidents.id, incidents.title, services.name, incidents.severity,
                   incidents.owasp_category, incidents.cwe_id, incidents.status,
                   incidents.detected_at, incidents.resolved_at, incidents.verified_at,
                   incidents.description, incidents.root_cause
            FROM incidents
            JOIN services ON services.id = incidents.service_id
            ORDER BY incidents.id
            """
        ).fetchall()
        for incident in incidents:
            events = connection.execute(
                """
                SELECT timestamp, new_status, description
                FROM incident_events
                WHERE incident_id = ?
                ORDER BY timestamp, id
                """,
                (incident["id"],),
            ).fetchall()
            remediation = connection.execute(
                """
                SELECT applied_at, fix_description, verification_status, verified_at, evidence
                FROM remediations
                WHERE incident_id = ?
                ORDER BY id
                """,
                (incident["id"],),
            ).fetchall()
            timeline = "\n".join(
                f"{event['timestamp']} {event['new_status']}: {event['description']}"
                for event in events
            )
            fix_lines = [
                (
                    f"Applied {row['applied_at']}. {row['fix_description']} "
                    f"Verification status: {row['verification_status']}."
                )
                for row in remediation
            ]
            summary = "\n".join(
                [
                    f"Incident {incident['id']}: {incident['title']}.",
                    f"Service: {incident['name']}. Status: {incident['status']}. Severity: {incident['severity']}.",
                    f"Detected: {incident['detected_at']}. Resolved: {incident['resolved_at'] or 'not resolved'}. Verified: {incident['verified_at'] or 'not verified'}.",
                    f"OWASP: {incident['owasp_category'] or 'unspecified'}. CWE: {incident['cwe_id'] or 'unspecified'}.",
                    incident["description"],
                    f"Root cause: {incident['root_cause'] or 'not recorded'}.",
                ]
            )
            sections = [("Summary", summary), ("Timeline", timeline or "No timeline events.")]
            if fix_lines:
                sections.append(("Remediation", "\n".join(fix_lines)))
            documents.append(
                SourceDocument(
                    document_id=f"incident-{incident['id']:03d}",
                    title=incident["title"],
                    source_url=f"internal://incidents/{incident['id']}",
                    document_type="incident_report",
                    taxonomy_version=incident["owasp_category"] or TOP10_FALLBACK,
                    sections=tuple(sections),
                    source_id=str(incident["id"]),
                    license="internal synthetic record",
                    namespace=settings.namespace_incidents,
                )
            )
        alerts = connection.execute(
            """
            SELECT alerts.id, alerts.detected_at, services.name, alerts.rule_id,
                   alerts.alert_type, alerts.severity, alerts.confidence,
                   alerts.owasp_category, alerts.cwe_id, alerts.status, alerts.description
            FROM alerts
            JOIN services ON services.id = alerts.service_id
            ORDER BY alerts.id
            """
        ).fetchall()
        for alert in alerts:
            summary = "\n".join(
                [
                    f"Alert {alert['id']} ({alert['rule_id']}) on {alert['name']} at {alert['detected_at']}.",
                    f"Status: {alert['status']}. Severity: {alert['severity']}. Confidence: {alert['confidence']}.",
                    f"Type: {alert['alert_type']}. OWASP: {alert['owasp_category'] or 'unspecified'}. CWE: {alert['cwe_id'] or 'unspecified'}.",
                    alert["description"],
                ]
            )
            documents.append(
                SourceDocument(
                    document_id=f"alert-{alert['id']:03d}",
                    title=f"{alert['rule_id']} on {alert['name']}",
                    source_url=f"internal://alerts/{alert['id']}",
                    document_type="alert_summary",
                    taxonomy_version=alert["owasp_category"] or TOP10_FALLBACK,
                    sections=(("Summary", summary),),
                    source_id=str(alert["id"]),
                    license="internal synthetic record",
                    namespace=settings.namespace_alerts,
                )
            )
        return documents
    finally:
        connection.close()


def build_chunks(documents: Sequence[SourceDocument]) -> list[dict[str, str]]:
    chunks: list[dict[str, str]] = []
    for document in documents:
        chunks.extend(chunk_document(document))
    return chunks


def seeded_documents(database_path: Path, settings: Settings | None = None) -> list[SourceDocument]:
    settings = settings or get_settings()
    return knowledge_documents(settings) + load_operational_documents(database_path, settings)


def limit_documents(documents: Sequence[SourceDocument], limit: int) -> list[SourceDocument]:
    """Keep a mix of knowledge, incidents, and alerts, up to limit documents."""
    grouped: dict[str, list[SourceDocument]] = {}
    for document in documents:
        grouped.setdefault(document.document_type, []).append(document)
    chosen: list[SourceDocument] = []
    while len(chosen) < limit and any(grouped.values()):
        for group in grouped.values():
            if group and len(chosen) < limit:
                chosen.append(group.pop(0))
    return chosen


async def situate_chunks(
    documents: Sequence[SourceDocument],
    chunks: Sequence[Mapping[str, str]],
    situate: Situator,
    *,
    stored: Mapping[str, Mapping[str, Any]] | None = None,
    workers: int = 8,
    progress: bool = False,
) -> list[dict[str, str]]:
    """Write one situating sentence per chunk. Model calls run together on a thread pool."""
    bodies = {document.document_id: document_text(document) for document in documents}
    situated: list[dict[str, str] | None] = [None] * len(chunks)
    pending: list[tuple[int, str, str, str]] = []
    for index, chunk in enumerate(chunks):
        updated = dict(chunk)
        prior = (stored or {}).get(str(chunk["chunk_id"]))
        context = ""
        if prior and str(prior.get("text") or "") == chunk["text"]:
            context = str(prior.get("context") or "").strip()
        if context:
            updated["context"] = context
            updated["contextualized"] = f"{context}\n\n{chunk['text']}"
            situated[index] = updated
        else:
            pending.append(
                (index, bodies[str(chunk["document_id"])], str(chunk["text"]), str(chunk["chunk_id"]))
            )
    if pending:
        loop = asyncio.get_running_loop()
        bar = tqdm(total=len(pending), desc="situating", disable=not progress)

        async def run_one(index: int, document: str, text: str, chunk_id: str) -> tuple[int, str, str]:
            sentence = await loop.run_in_executor(pool, situate, document, text)
            bar.update(1)
            bar.set_postfix_str(chunk_id)
            return index, text, str(sentence)

        try:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                results = await asyncio.gather(
                    *[
                        run_one(index, document, text, chunk_id)
                        for index, document, text, chunk_id in pending
                    ]
                )
        finally:
            bar.close()
        for index, text, context in results:
            updated = dict(chunks[index])
            sentence = context.strip()
            updated["context"] = sentence
            updated["contextualized"] = f"{sentence}\n\n{text}" if sentence else text
            situated[index] = updated
    return [chunk for chunk in situated if chunk is not None]


def content_hash(chunks: Sequence[Mapping[str, str]]) -> str:
    payload = json.dumps(list(chunks), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def write_local_index(
    directory: Path,
    chunks: Sequence[Mapping[str, str]],
    settings: Settings,
) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(chunk, sort_keys=True) for chunk in chunks]
    (directory / "chunks.jsonl").write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    manifest = {
        "chunk_count": len(chunks),
        "content_hash": content_hash(chunks),
        "embedding_dimension": settings.embedding_dimension,
        "embedding_model": settings.embedding_model,
        "namespaces": sorted({str(chunk["namespace"]) for chunk in chunks}),
    }
    (directory / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def load_local_chunks(directory: Path) -> list[dict[str, Any]]:
    path = directory / "chunks.jsonl"
    if not path.exists():
        return []
    chunks: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            chunks.append(json.loads(line))
    return chunks


def write_vectors(path: Path, vectors: Sequence[Sequence[float]]) -> None:
    path.write_text(json.dumps(vectors), encoding="utf-8")


def load_vectors(path: Path) -> list[list[float]]:
    if not path.exists():
        return []
    loaded = json.loads(path.read_text(encoding="utf-8"))
    return [list(vector) for vector in loaded]


def load_embedding_model(model_name: str) -> Any:
    global _embedding_model, _embedding_model_name
    if _embedding_model is None or _embedding_model_name != model_name:
        from sentence_transformers import SentenceTransformer

        _embedding_model = SentenceTransformer(model_name)
        _embedding_model_name = model_name
    return _embedding_model


def sentence_transformer_embedder(model_name: str) -> Embedder:
    def embed(texts: Sequence[str]) -> list[list[float]]:
        model = load_embedding_model(model_name)
        vectors = model.encode(list(texts), normalize_embeddings=True)
        return [vector.tolist() for vector in vectors]

    return embed


def embed_passages(texts: Sequence[str], embedder: Embedder) -> list[list[float]]:
    if not texts:
        return []
    return embedder(texts)


def embed_query(text: str, embedder: Embedder, settings: Settings | None = None) -> list[float]:
    settings = settings or get_settings()
    return embedder([f"{settings.query_instruction}{text}"])[0]


def vectors_for_chunks(
    chunks: Sequence[Mapping[str, str]],
    embeddings: Sequence[Sequence[float]],
    *,
    dimension: int,
) -> dict[str, list[dict[str, Any]]]:
    if len(chunks) != len(embeddings):
        raise ValueError("embedding count does not match chunk count")
    grouped: dict[str, list[dict[str, Any]]] = {}
    for chunk, vector in zip(chunks, embeddings, strict=True):
        if len(vector) != dimension:
            raise ValueError(
                f"chunk {chunk['chunk_id']} has dimension {len(vector)}, expected {dimension}"
            )
        metadata = {key: chunk[key] for key in METADATA_FIELDS if chunk.get(key) not in (None, "")}
        grouped.setdefault(str(chunk["namespace"]), []).append(
            {"id": chunk["chunk_id"], "values": list(vector), "metadata": metadata}
        )
    return grouped


async def preprocess_corpus(
    database_path: Path,
    index_directory: Path,
    *,
    settings: Settings | None = None,
    situate: Situator | None = None,
    embedder: Embedder | None = None,
    limit: int | None = None,
    document_limit: int | None = None,
    progress: bool = False,
) -> dict[str, Any]:
    """Chunk the seed, situate every chunk, embed the raw text and the contextualized text."""
    settings = settings or get_settings()
    if limit is not None and limit <= 0:
        raise ValueError("limit must be positive")
    if document_limit is not None and document_limit <= 0:
        raise ValueError("document_limit must be positive")
    documents = await asyncio.to_thread(seeded_documents, database_path, settings)
    if document_limit is not None:
        documents = limit_documents(documents, document_limit)
    chunks = build_chunks(documents)
    if limit is not None:
        chunks = chunks[:limit]
    if progress:
        print(
            f"indexing {len(documents)} documents, {len(chunks)} chunks",
            flush=True,
        )
    stored = {
        str(chunk["chunk_id"]): chunk
        for chunk in await asyncio.to_thread(load_local_chunks, index_directory)
    }
    active_situate = situate or (
        lambda document, chunk: situate_context(document, chunk, settings=settings)
    )
    situated = await situate_chunks(
        documents,
        chunks,
        active_situate,
        stored=stored,
        workers=settings.situate_workers,
        progress=progress,
    )
    manifest = await asyncio.to_thread(write_local_index, index_directory, situated, settings)
    active_embedder = embedder or sentence_transformer_embedder(settings.embedding_model)
    basic = await asyncio.to_thread(
        embed_passages, [str(chunk["text"]) for chunk in situated], active_embedder
    )
    contextual = await asyncio.to_thread(
        embed_passages, [str(chunk["contextualized"]) for chunk in situated], active_embedder
    )
    await asyncio.to_thread(write_vectors, index_directory / "basic_embeddings.json", basic)
    await asyncio.to_thread(
        write_vectors, index_directory / "contextual_embeddings.json", contextual
    )
    manifest["chunks"] = situated
    manifest["basic_embeddings"] = basic
    manifest["contextual_embeddings"] = contextual
    return manifest
