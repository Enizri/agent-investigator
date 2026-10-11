"""Load, chunk, and index security text. Evaluation files are never indexed."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from security_investigator.config import Settings, get_settings
from security_investigator.database import connect_sync
from security_investigator.knowledge_catalog import knowledge_records

# Fixed estimator so chunk ids do not drift with a tokenizer version.
TOKEN_PER_WORD = 1.3
TARGET_TOKENS = 400
MAX_TOKENS = 500
WORD_WINDOW = 350
TOP10_FALLBACK = "OWASP Top 10:2025"

METADATA_FIELDS = (
    "chunk_id",
    "document_id",
    "document_type",
    "source_id",
    "title",
    "section",
    "source_url",
    "taxonomy_version",
    "summary",
)

Embedder = Callable[[Sequence[str]], list[list[float]]]
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


class VectorIndex(Protocol):
    def upsert(self, namespace: str, vectors: Sequence[Mapping[str, Any]]) -> None: ...


def estimate_tokens(text: str) -> int:
    """Approximate tokens as 1.3 times whitespace-separated words."""
    words = text.split()
    if not words:
        return 0
    return max(1, round(len(words) * TOKEN_PER_WORD))


def normalize_text(text: str) -> str:
    cleaned = text.replace("\r\n", "\n").replace("\r", "\n")
    cleaned = re.sub(r"[ \t]+", " ", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def ensure_indexable_path(path: Path) -> None:
    parts = set(path.resolve().parts)
    if "scenarios" in parts or "benchmarks" in parts:
        raise ValueError(f"refusing to index evaluation data: {path}")


def chunk_section(section: str, text: str) -> list[tuple[str, str]]:
    """Split one section. Short sections stay intact so the section name stays true."""
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


def document_summary(document: SourceDocument) -> str:
    """Short text already written for a seeded document. This is not a model call."""
    for name, text in document.sections:
        if name.lower() == "summary":
            return normalize_text(text)
    if not document.sections:
        return ""
    return normalize_text(document.sections[0][1])


def chunk_document(document: SourceDocument) -> list[dict[str, str]]:
    summary = document_summary(document)
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
                    "summary": summary,
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


def render_markdown(document: SourceDocument) -> str:
    header = "\n".join(
        [
            "---",
            f"document_id: {document.document_id}",
            f"title: {document.title}",
            f"source_url: {document.source_url}",
            f"document_type: {document.document_type}",
            f"taxonomy_version: {document.taxonomy_version}",
            f"license: {document.license}",
            "---",
            "",
        ]
    )
    body = "\n\n".join(f"## {name}\n\n{text}" for name, text in document.sections)
    return header + body + "\n"


def export_knowledge_markdown(directory: Path, settings: Settings | None = None) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for document in knowledge_documents(settings):
        path = directory / f"{document.document_id}.md"
        path.write_text(render_markdown(document), encoding="utf-8")


def load_markdown(path: Path, *, namespace: str) -> SourceDocument:
    ensure_indexable_path(path)
    raw = path.read_text(encoding="utf-8")
    if not raw.startswith("---\n"):
        raise ValueError(f"missing front matter: {path}")
    marker = raw.find("\n---\n", 4)
    if marker < 0:
        raise ValueError(f"unterminated front matter: {path}")
    meta: dict[str, str] = {}
    for line in raw[4:marker].splitlines():
        if not line.strip():
            continue
        key, value = line.split(": ", 1)
        meta[key] = value
    sections: list[tuple[str, str]] = []
    current = "Overview"
    buffer: list[str] = []
    for line in raw[marker + 5 :].splitlines():
        if line.startswith("## "):
            text = normalize_text("\n".join(buffer))
            if text:
                sections.append((current, text))
            current = line[3:].strip()
            buffer = []
        else:
            buffer.append(line)
    tail = normalize_text("\n".join(buffer))
    if tail:
        sections.append((current, tail))
    document_id = meta["document_id"]
    return SourceDocument(
        document_id=document_id,
        title=meta["title"],
        source_url=meta["source_url"],
        document_type=meta["document_type"],
        taxonomy_version=meta["taxonomy_version"],
        sections=tuple(sections),
        source_id=document_id,
        license=meta.get("license", ""),
        namespace=namespace,
    )


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


def content_hash(chunks: Sequence[Mapping[str, str]]) -> str:
    payload = json.dumps(list(chunks), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def write_local_index(
    directory: Path,
    chunks: Sequence[Mapping[str, str]],
    settings: Settings,
) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    jsonl_path = directory / "chunks.jsonl"
    lines = [json.dumps(chunk, sort_keys=True) for chunk in chunks]
    jsonl_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    manifest = {
        "chunk_count": len(chunks),
        "content_hash": content_hash(chunks),
        "embedding_dimension": settings.embedding_dimension,
        "embedding_model": settings.embedding_model,
        "namespaces": sorted({chunk["namespace"] for chunk in chunks}),
    }
    (directory / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def index_incoming(
    text: str,
    *,
    title: str,
    source_id: str,
    index_directory: Path,
    settings: Settings | None = None,
    summarizer: Any = None,
    push: bool | None = None,
) -> dict[str, Any]:
    """Store one new record. Qwen runs only when this text has no stored summary."""
    settings = settings or get_settings()
    body = normalize_text(text)
    if not body:
        raise ValueError("incoming text is empty")
    chunk_id = f"incoming-{source_id}"
    stored = {str(chunk["chunk_id"]): chunk for chunk in load_local_chunks(index_directory)}
    prior = stored.get(chunk_id)
    reused = bool(prior and prior.get("text") == body and str(prior.get("summary") or "").strip())
    if reused:
        summary = str(prior["summary"])
    else:
        if summarizer is None:
            raise RuntimeError("a new incoming record needs a summarizer")
        from security_investigator.llm import attach_chunk_summaries

        drafted = asyncio.run(
            attach_chunk_summaries(
                [{"chunk_id": chunk_id, "title": title, "text": body}],
                summarizer,
            )
        )
        summary = str(drafted[0].get("summary") or "")
    record = {
        "chunk_id": chunk_id,
        "document_id": chunk_id,
        "title": title,
        "source_url": f"internal://incoming/{source_id}",
        "section": "Incoming",
        "document_type": "alert_summary",
        "taxonomy_version": TOP10_FALLBACK,
        "text": body,
        "summary": summary,
        "source_id": source_id,
        "source_type": "incoming",
        "license": "internal synthetic record",
        "namespace": f"{settings.pinecone_namespace}-incoming",
    }
    stored[chunk_id] = record
    manifest = write_local_index(index_directory, list(stored.values()), settings)
    should_push = bool(settings.pinecone_api_key) if push is None else push
    if should_push:
        active_embedder = sentence_transformer_embedder(settings.embedding_model)
        embeddings = embed_passages(
            [passage_text(record, settings.embed_mode)],
            active_embedder,
        )
        upsert_chunks(
            PineconeVectorIndex(settings),
            [record],
            embeddings,
            dimension=settings.embedding_dimension,
        )
    return {
        "chunk_id": chunk_id,
        "summary": summary,
        "reused": reused,
        "embed_mode": settings.embed_mode,
        "content_hash": manifest["content_hash"],
    }


def load_local_chunks(directory: Path) -> list[dict[str, Any]]:
    path = directory / "chunks.jsonl"
    if not path.exists():
        return []
    chunks: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            chunks.append(json.loads(line))
    return chunks


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


def passage_text(chunk: Mapping[str, Any], mode: str = "original") -> str:
    """Text sent to the embedding model. The stored chunk text does not change."""
    original = str(chunk.get("text") or "")
    summary = str(chunk.get("summary") or "").strip()
    if mode == "original":
        return original
    if mode == "summary":
        return summary or original
    if mode == "contextual":
        return f"{summary}\n\n{original}" if summary else original
    raise ValueError("embed_mode must be original, summary, or contextual")


def embed_passages(texts: Sequence[str], embedder: Embedder) -> list[list[float]]:
    if not texts:
        return []
    return embedder(texts)


def embed_query(text: str, embedder: Embedder, settings: Settings | None = None) -> list[float]:
    settings = settings or get_settings()
    return embedder([f"{settings.query_instruction}{text}"])[0]


async def embed_passages_async(texts: Sequence[str], embedder: Embedder) -> list[list[float]]:
    return await asyncio.to_thread(embed_passages, texts, embedder)


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
        grouped.setdefault(chunk["namespace"], []).append(
            {"id": chunk["chunk_id"], "values": list(vector), "metadata": metadata}
        )
    return grouped


def upsert_chunks(
    index: VectorIndex,
    chunks: Sequence[Mapping[str, str]],
    embeddings: Sequence[Sequence[float]],
    *,
    dimension: int,
) -> None:
    for namespace, vectors in vectors_for_chunks(chunks, embeddings, dimension=dimension).items():
        index.upsert(namespace, vectors)


def _dense_dimension(description: Any) -> int | None:
    schema = getattr(description, "schema", None)
    fields = getattr(schema, "fields", None) or {}
    if isinstance(fields, dict):
        values = fields.values()
    else:
        values = []
    for field in values:
        dimension = getattr(field, "dimension", None)
        if dimension is None and isinstance(field, dict):
            dimension = field.get("dimension")
        if dimension:
            return int(dimension)
    legacy = getattr(description, "dimension", None)
    return int(legacy) if legacy else None


class PineconeVectorIndex:
    """Dense vector index. Uses upsert/query, not the document-index API."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._index: Any = None

    def ensure_index(self) -> Any:
        from pinecone import Pinecone, ServerlessSpec

        if not self.settings.pinecone_api_key:
            raise RuntimeError("PINECONE_API_KEY is empty")
        client = Pinecone(api_key=self.settings.pinecone_api_key)
        name = self.settings.pinecone_index
        if not client.has_index(name):
            client.create_index(
                name=name,
                vector_type="dense",
                dimension=self.settings.embedding_dimension,
                metric="cosine",
                spec=ServerlessSpec(
                    cloud=self.settings.pinecone_cloud,
                    region=self.settings.pinecone_region,
                ),
                deletion_protection="disabled",
            )
        description = client.describe_index(name)
        dimension = _dense_dimension(description)
        if dimension != self.settings.embedding_dimension:
            raise RuntimeError(
                f"index dimension {dimension} does not match embedding dimension "
                f"{self.settings.embedding_dimension}"
            )
        host = description.host
        if not host:
            raise RuntimeError("Pinecone index host is not ready")
        self._index = client.index(host=host)
        return self._index

    def upsert(self, namespace: str, vectors: Sequence[Mapping[str, Any]]) -> None:
        if self._index is None:
            self.ensure_index()
        self._index.upsert(
            vectors=list(vectors),
            namespace=namespace,
            batch_size=100,
            show_progress=False,
        )


def index_corpus(
    database_path: Path,
    index_directory: Path,
    *,
    settings: Settings | None = None,
    embedder: Embedder | None = None,
    vector_index: VectorIndex | None = None,
    push: bool = False,
    embed_mode: str | None = None,
) -> dict[str, Any]:
    settings = settings or get_settings()
    mode = embed_mode or settings.embed_mode
    documents = knowledge_documents(settings) + load_operational_documents(database_path, settings)
    chunks = build_chunks(documents)
    manifest = write_local_index(index_directory, chunks, settings)
    manifest["summarized_count"] = sum(1 for chunk in chunks if chunk.get("summary"))
    manifest["embed_mode"] = mode
    if push:
        active_embedder = embedder or sentence_transformer_embedder(settings.embedding_model)
        embeddings = embed_passages(
            [passage_text(chunk, mode) for chunk in chunks], active_embedder
        )
        upsert_chunks(
            vector_index or PineconeVectorIndex(settings),
            chunks,
            embeddings,
            dimension=settings.embedding_dimension,
        )
    return manifest
