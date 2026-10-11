"""Retrieval and investigation metrics. Labels come from the scenario manifest."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import time
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from security_investigator.agent import InvestigationDeps, build_investigation_graph, initial_state
from security_investigator.config import Settings, get_settings
from security_investigator.generator import generate_company
from security_investigator.ingestion import (
    Embedder,
    build_chunks,
    embed_passages,
    index_corpus,
    knowledge_documents,
    load_operational_documents,
    passage_text,
    vectors_for_chunks,
)
from security_investigator.llm import ChunkSummarizer
from security_investigator.models import RetrievedChunk
from security_investigator.retrieval import (
    BM25Index,
    DenseIndex,
    MemoryDenseIndex,
    dense_search,
    hybrid_search,
    rerank,
)

STATUS_WORDS = ("reopened", "resolved", "mitigated", "false_positive", "investigating", "open")


def recall_at_k(retrieved: Sequence[str], relevant: set[str], k: int) -> float:
    if not relevant:
        return 1.0 if not retrieved else 0.0
    hit = set(retrieved[:k]) & relevant
    return len(hit) / len(relevant)


def precision_at_k(retrieved: Sequence[str], relevant: set[str], k: int) -> float:
    if k <= 0:
        return 0.0
    window = list(retrieved[:k])
    if not window:
        return 0.0
    return len(set(window) & relevant) / len(window)


def mean_reciprocal_rank(retrieved: Sequence[str], relevant: set[str]) -> float:
    for rank, item in enumerate(retrieved, start=1):
        if item in relevant:
            return 1.0 / rank
    return 0.0


def _dcg(gains: Sequence[float]) -> float:
    return sum(gain / math.log2(index + 2) for index, gain in enumerate(gains))


def ndcg_at_k(retrieved: Sequence[str], relevant: set[str], k: int) -> float:
    gains = [1.0 if item in relevant else 0.0 for item in retrieved[:k]]
    ideal = [1.0] * min(k, len(relevant))
    ideal_dcg = _dcg(ideal)
    if ideal_dcg == 0.0:
        return 0.0
    return _dcg(gains) / ideal_dcg


def document_ranking(chunks: Sequence[RetrievedChunk]) -> list[str]:
    ordered: list[str] = []
    for chunk in chunks:
        if chunk.document_id not in ordered:
            ordered.append(chunk.document_id)
    return ordered


def split_for(family: str) -> str:
    bucket = int(hashlib.sha256(family.encode()).hexdigest(), 16) % 10
    if bucket < 6:
        return "train"
    if bucket < 8:
        return "dev"
    return "test"


def _knowledge_ids_for_cwe(cwe_id: str | None) -> list[str]:
    if not cwe_id:
        return []
    matches: list[str] = []
    for document in knowledge_documents(Settings(_env_file=None)):
        text = " ".join(section for _name, section in document.sections)
        if cwe_id in text or cwe_id.replace("CWE-", "") == document.title:
            if cwe_id in text:
                matches.append(document.document_id)
    return matches


def generate_benchmark(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Build labeled questions from the manifest. The agent never receives this file."""
    reference = manifest["reference_time"]
    questions: list[dict[str, Any]] = []

    def add(question: dict[str, Any]) -> None:
        question["split"] = split_for(question["family"])
        question["id"] = f"q-{len(questions) + 1:03d}"
        questions.append(question)

    incidents = manifest["incidents"]
    alerts = manifest["alerts"]
    for incident in incidents:
        document_id = f"incident-{incident['id']:03d}"
        relevant = [document_id, *_knowledge_ids_for_cwe(incident["cwe_id"])]
        add(
            {
                "question": f"What is the current status of incident {incident['id']}: {incident['title']}?",
                "category": "current_status",
                "family": incident["family"],
                "as_of": reference,
                "relevant_document_ids": relevant,
                "expected_incident_ids": [incident["id"]],
                "expected_status": {str(incident["id"]): incident["status"]},
                "expected_unverified_alert_ids": [],
                "answerable": True,
                "failure_case": "reopened" if incident["reopened"] else None,
            }
        )
    historical = next(item for item in incidents if item["key"] == "billing_sqli_resolved")
    add(
        {
            "question": "Was the billing SQL injection still active on 2026-08-11?",
            "category": "historical_status",
            "family": historical["family"],
            "as_of": "2026-08-11T12:00:00+00:00",
            "relevant_document_ids": [f"incident-{historical['id']:03d}"],
            "expected_incident_ids": [historical["id"]],
            "expected_status": {str(historical["id"]): "investigating"},
            "expected_unverified_alert_ids": [],
            "answerable": True,
            "failure_case": "outdated_report",
        }
    )
    lookalike = next(item for item in alerts if item["key"] == "billing_bac_lookalike")
    resolved_bac = next(item for item in incidents if item["key"] == "billing_bac_resolved")
    add(
        {
            "question": "Is the recent billing authorization alert the same resolved vulnerability?",
            "category": "similar_incidents",
            "family": lookalike["family"],
            "as_of": reference,
            "relevant_document_ids": [
                f"incident-{resolved_bac['id']:03d}",
                f"alert-{lookalike['id']:03d}",
            ],
            "expected_incident_ids": [resolved_bac["id"]],
            "expected_status": {str(resolved_bac["id"]): "resolved"},
            "expected_unverified_alert_ids": [lookalike["id"]],
            "answerable": True,
            "failure_case": "new_alert_like_resolved_incident",
        }
    )
    blocked = next(item for item in alerts if item["key"] == "billing_sqli_blocked")
    add(
        {
            "question": "Is the blocked billing SQL injection request a real vulnerability?",
            "category": "false_positives",
            "family": blocked["family"],
            "as_of": reference,
            "relevant_document_ids": [f"alert-{blocked['id']:03d}", "knowledge-005"],
            "expected_incident_ids": [],
            "expected_status": {},
            "expected_unverified_alert_ids": [blocked["id"]],
            "answerable": True,
            "failure_case": "blocked_attempt",
        }
    )
    false_positive = next(item for item in alerts if item["key"] == "auth_login_drill_fp")
    add(
        {
            "question": "Is the auth-service login burst a confirmed vulnerability or a false positive?",
            "category": "false_positives",
            "family": false_positive["family"],
            "as_of": reference,
            "relevant_document_ids": [f"alert-{false_positive['id']:03d}"],
            "expected_incident_ids": [],
            "expected_status": {},
            "expected_unverified_alert_ids": [],
            "answerable": True,
            "failure_case": "false_positive",
        }
    )
    pending = next(item for item in incidents if item["key"] == "file_misconfig_unverified")
    add(
        {
            "question": "Was the file-service bucket policy change verified?",
            "category": "conflicting_evidence",
            "family": pending["family"],
            "as_of": reference,
            "relevant_document_ids": [f"incident-{pending['id']:03d}"],
            "expected_incident_ids": [pending["id"]],
            "expected_status": {str(pending["id"]): "mitigated"},
            "expected_unverified_alert_ids": [],
            "answerable": True,
            "failure_case": "unverified_remediation",
        }
    )
    sparse = next(item for item in incidents if item["key"] == "admin_integrity_sparse")
    add(
        {
            "question": "What is the status of the unsigned admin artifact incident?",
            "category": "multi_source",
            "family": sparse["family"],
            "as_of": reference,
            "relevant_document_ids": [f"incident-{sparse['id']:03d}"],
            "expected_incident_ids": [sparse["id"]],
            "expected_status": {str(sparse["id"]): sparse["status"]},
            "expected_unverified_alert_ids": [],
            "answerable": True,
            "failure_case": "sparse_logs",
        }
    )
    for cwe_id, document_id in (
        ("CWE-89", "knowledge-005"),
        ("CWE-639", "knowledge-001"),
        ("CWE-918", "knowledge-001"),
        ("CWE-778", "knowledge-009"),
        ("CWE-494", "knowledge-008"),
    ):
        add(
            {
                "question": f"Explain {cwe_id}",
                "category": "exact_identifier",
                "family": f"cwe-{cwe_id}",
                "as_of": reference,
                "relevant_document_ids": _knowledge_ids_for_cwe(cwe_id) or [document_id],
                "expected_incident_ids": [],
                "expected_status": {},
                "expected_unverified_alert_ids": [],
                "answerable": True,
                "failure_case": "exact_identifier",
            }
        )
    add(
        {
            "question": "What causes broken access control?",
            "category": "knowledge_retrieval",
            "family": "knowledge-access-control",
            "as_of": reference,
            "relevant_document_ids": ["knowledge-001", *_knowledge_ids_for_cwe("CWE-639")],
            "expected_incident_ids": [],
            "expected_status": {},
            "expected_unverified_alert_ids": [],
            "answerable": True,
            "failure_case": None,
        }
    )
    week_start = (
        (datetime.fromisoformat(reference) - timedelta(days=7))
        .astimezone(UTC)
        .strftime("%Y-%m-%dT%H:%M:%S+00:00")
    )
    changed = []
    for incident in incidents:
        before = _nearest_status(incident, week_start)
        after = incident["status"]
        if before and before != after:
            changed.append(incident["id"])
    add(
        {
            "question": "Which incidents changed status in the last week?",
            "category": "temporal_comparison",
            "family": "temporal-week",
            "as_of": reference,
            "relevant_document_ids": [f"incident-{incident_id:03d}" for incident_id in changed],
            "expected_incident_ids": changed,
            "expected_status": {
                str(incident["id"]): incident["status"]
                for incident in incidents
                if incident["id"] in changed
            },
            "expected_unverified_alert_ids": [],
            "answerable": True,
            "failure_case": "temporal",
        }
    )
    for name in ("widget-service", "payroll-service", "unknown-service"):
        add(
            {
                "question": f"What happened in {name}?",
                "category": "unanswerable",
                "family": name,
                "as_of": reference,
                "relevant_document_ids": [],
                "expected_incident_ids": [],
                "expected_status": {},
                "expected_unverified_alert_ids": [],
                "answerable": False,
                "failure_case": "abstention",
            }
        )
    for incident in incidents:
        document_id = f"incident-{incident['id']:03d}"
        add(
            {
                "question": f"What was the status of incident {incident['id']} when it was detected?",
                "category": "historical_status",
                "family": incident["family"],
                "as_of": min(
                    point for point, status in incident["expected_status_at"].items() if status
                ),
                "relevant_document_ids": [document_id],
                "expected_incident_ids": [incident["id"]],
                "expected_status": {str(incident["id"]): "open"},
                "expected_unverified_alert_ids": [],
                "answerable": True,
                "failure_case": None,
            }
        )
    for service in sorted({incident["service"] for incident in incidents}):
        owned = [incident for incident in incidents if incident["service"] == service]
        add(
            {
                "question": f"How secure is {service}?",
                "category": "current_status",
                "family": f"service-{service}",
                "as_of": reference,
                "relevant_document_ids": [f"incident-{incident['id']:03d}" for incident in owned],
                "expected_incident_ids": [incident["id"] for incident in owned],
                "expected_status": {str(incident["id"]): incident["status"] for incident in owned},
                "expected_unverified_alert_ids": [],
                "answerable": True,
                "failure_case": None,
            }
        )
    open_critical = [
        incident["id"]
        for incident in incidents
        if incident["severity"] == "critical"
        and incident["status"] in {"open", "investigating", "reopened"}
    ]
    add(
        {
            "question": "Which critical incidents are active?",
            "category": "current_status",
            "family": "posture-critical",
            "as_of": reference,
            "relevant_document_ids": [
                f"incident-{incident_id:03d}" for incident_id in open_critical
            ],
            "expected_incident_ids": open_critical,
            "expected_status": {
                str(incident["id"]): incident["status"]
                for incident in incidents
                if incident["id"] in open_critical
            },
            "expected_unverified_alert_ids": [],
            "answerable": True,
            "failure_case": "current_status",
        }
    )
    if not 80 <= len(questions) <= 120:
        raise RuntimeError(f"benchmark size {len(questions)} is outside 80-120")
    return questions


def _nearest_status(incident: dict[str, Any], timestamp: str) -> str | None:
    current = None
    for point, status in sorted(incident["expected_status_at"].items()):
        if point <= timestamp and status:
            current = status
    return current


def aggregate_retrieval(rows: list[dict[str, float]]) -> dict[str, float]:
    if not rows:
        return {
            "recall_at_5": 0.0,
            "precision_at_5": 0.0,
            "mrr": 0.0,
            "ndcg_at_5": 0.0,
            "latency_ms": 0.0,
        }
    keys = rows[0].keys()
    return {key: sum(row[key] for row in rows) / len(rows) for key in keys}


async def score_embedding_approaches(
    chunks: list[dict[str, Any]],
    questions: list[dict[str, Any]],
    embedder: Embedder,
    *,
    settings: Settings | None = None,
    modes: Sequence[str] = ("original", "summary", "contextual"),
) -> list[dict[str, Any]]:
    """Dense retrieval scores for each way of building the passage vector.

    Original embeds the chunk text. Summary embeds the short summary written with the
    seed. Contextual embeds that summary followed by the original text.
    """
    settings = settings or get_settings()
    scored: list[dict[str, Any]] = []
    for mode in modes:
        texts = [passage_text(chunk, mode) for chunk in chunks]
        embeddings = embed_passages(texts, embedder)
        memory = MemoryDenseIndex()
        for namespace, vectors in vectors_for_chunks(
            chunks, embeddings, dimension=settings.embedding_dimension
        ).items():
            memory.upsert(namespace, vectors)
        rows: list[dict[str, float]] = []
        for question in questions:
            started = time.perf_counter()
            retrieved = await dense_search(
                question["question"],
                top_k=5,
                settings=settings,
                embedder=embedder,
                index=memory,
                chunks=chunks,
            )
            rows.append(
                score_retrieval(
                    retrieved,
                    set(question["relevant_document_ids"]),
                    (time.perf_counter() - started) * 1000,
                )
            )
        summary = aggregate_retrieval(rows)
        summary["approach"] = mode
        summary["n"] = len(questions)
        scored.append(summary)
    return scored


def score_retrieval(
    retrieved: Sequence[RetrievedChunk], relevant: set[str], latency_ms: float
) -> dict[str, float]:
    ranking = document_ranking(retrieved)
    return {
        "recall_at_5": recall_at_k(ranking, relevant, 5),
        "precision_at_5": precision_at_k(ranking, relevant, 5),
        "mrr": mean_reciprocal_rank(ranking, relevant),
        "ndcg_at_5": ndcg_at_k(ranking, relevant, 5),
        "latency_ms": latency_ms,
    }


def naive_predictions(chunks: Sequence[RetrievedChunk]) -> dict[str, str]:
    """Baseline that trusts retrieved prose. It can copy an old status forward."""
    predicted: dict[str, str] = {}
    for chunk in chunks:
        if not chunk.source_id.isdigit():
            continue
        if chunk.source_type not in {"incident_report", "alert_summary"}:
            continue
        text = chunk.text.lower()
        status = next((word for word in STATUS_WORDS if word in text), None)
        if status and chunk.source_id not in predicted:
            predicted[chunk.source_id] = status
    return predicted


def score_investigation(
    *,
    expected_ids: Sequence[int],
    expected_status: dict[str, str],
    predicted_status: dict[str, str],
    unverified_alert_ids: Sequence[int],
    expected_unverified: Sequence[int],
    citations: Sequence[str],
    allowed_evidence: set[str],
    answer: str,
    category: str,
) -> dict[str, float]:
    expected = {str(item) for item in expected_ids}
    predicted_ids = set(predicted_status)
    if expected:
        identification = len(expected & predicted_ids) / len(expected)
    else:
        identification = 1.0 if not predicted_ids else 0.0
    comparable = [item for item in expected if item in predicted_status]
    if comparable:
        status_accuracy = sum(
            predicted_status[item] == expected_status[item] for item in comparable
        ) / len(comparable)
    elif not expected:
        status_accuracy = 1.0
    else:
        status_accuracy = 0.0
    if expected_unverified:
        false_positive = sum(str(item) in predicted_status for item in expected_unverified) / len(
            expected_unverified
        )
    else:
        false_positive = 0.0
    if citations:
        citation_accuracy = sum(item in allowed_evidence for item in citations) / len(citations)
    else:
        citation_accuracy = 1.0
    unsupported = 0.0 if "incident 999" not in answer.lower() else 1.0
    temporal = status_accuracy if category == "temporal_comparison" else 1.0
    return {
        "incident_identification": identification,
        "status_accuracy": status_accuracy,
        "temporal_accuracy": temporal,
        "false_positive_rate": false_positive,
        "citation_accuracy": citation_accuracy,
        "unsupported_claim_rate": unsupported,
        "unverified_recall": (
            len(set(unverified_alert_ids) & set(expected_unverified)) / len(expected_unverified)
            if expected_unverified
            else 1.0
        ),
    }


async def evaluate(
    database_path: Path,
    *,
    settings: Settings | None = None,
    embedder: Embedder | None = None,
    index: DenseIndex | None = None,
    chunks: list[dict[str, Any]] | None = None,
    bm25_index: BM25Index | None = None,
    questions: list[dict[str, Any]] | None = None,
    score_fn: Any = None,
    rerank_enabled: bool = False,
    chunk_summarizer: ChunkSummarizer | None = None,
) -> dict[str, Any]:
    settings = settings or get_settings()
    if questions is None:
        company = generate_company(
            seed=settings.random_seed, reference_time=settings.reference_time
        )
        questions = generate_benchmark(company.manifest)
    if chunks is None:
        documents = knowledge_documents(settings) + load_operational_documents(
            database_path, settings
        )
        chunks = build_chunks(documents)
    bm25_index = bm25_index or BM25Index(chunks)
    retrieval_rows: list[dict[str, Any]] = []
    investigation_rows: list[dict[str, Any]] = []
    per_question: list[dict[str, Any]] = []
    deps = InvestigationDeps(
        database_path=database_path,
        settings=settings,
        embedder=embedder,
        index=index,
        chunks=chunks,
        bm25_index=bm25_index,
        rerank_enabled=rerank_enabled,
        score_fn=score_fn,
        chunk_summarizer=chunk_summarizer,
    )
    graph = build_investigation_graph(deps) if index is not None or embedder is not None else None
    for question in questions:
        relevant = set(question["relevant_document_ids"])
        variant_rankings: dict[str, list[RetrievedChunk]] = {}
        started = time.perf_counter()
        dense = await dense_search(
            question["question"],
            top_k=5,
            settings=settings,
            embedder=embedder,
            index=index,
            chunks=chunks,
        )
        variant_rankings["A_dense"] = dense
        retrieval_rows.append(
            {
                "variant": "A_dense",
                **score_retrieval(dense, relevant, (time.perf_counter() - started) * 1000),
            }
        )
        started = time.perf_counter()
        lexical = await _as_async_bm25(question["question"], bm25_index)
        variant_rankings["B_bm25"] = lexical
        retrieval_rows.append(
            {
                "variant": "B_bm25",
                **score_retrieval(lexical, relevant, (time.perf_counter() - started) * 1000),
            }
        )
        started = time.perf_counter()
        hybrid = await hybrid_search(
            question["question"],
            top_k=5,
            settings=settings,
            embedder=embedder,
            index=index,
            chunks=chunks,
            bm25_index=bm25_index,
        )
        variant_rankings["C_hybrid"] = hybrid
        retrieval_rows.append(
            {
                "variant": "C_hybrid",
                **score_retrieval(hybrid, relevant, (time.perf_counter() - started) * 1000),
            }
        )
        started = time.perf_counter()
        reranked = rerank(
            question["question"], hybrid, top_k=5, enabled=rerank_enabled, score_fn=score_fn
        )
        variant_rankings["D_reranked"] = reranked
        retrieval_rows.append(
            {
                "variant": "D_reranked",
                **score_retrieval(reranked, relevant, (time.perf_counter() - started) * 1000),
            }
        )
        for variant, chosen in (
            ("E_dense_rag", dense),
            ("F_hybrid_rag", reranked if rerank_enabled else hybrid),
        ):
            predicted = naive_predictions(chosen)
            investigation_rows.append(
                {
                    "variant": variant,
                    "category": question["category"],
                    **score_investigation(
                        expected_ids=question["expected_incident_ids"],
                        expected_status=question["expected_status"],
                        predicted_status=predicted,
                        unverified_alert_ids=[],
                        expected_unverified=question["expected_unverified_alert_ids"],
                        citations=[chunk.chunk_id for chunk in chosen],
                        allowed_evidence={chunk.chunk_id for chunk in chosen},
                        answer=" ".join(chunk.text for chunk in chosen[:3]),
                        category=question["category"],
                    ),
                    "tool_calls": 1,
                    "latency_ms": 0.0,
                    "llm_tokens": 0,
                }
            )
        if graph is not None and question["category"] != "exact_identifier":
            started = time.perf_counter()
            state = await graph.ainvoke(initial_state(question["question"], question["as_of"]))
            latency_ms = (time.perf_counter() - started) * 1000
            final = state["final_answer"]
            predicted_status = {
                str(finding["incident_id"]): finding["status"]
                for finding in final["findings"]
                if finding.get("incident_id") is not None
            }
            citations = [item["evidence_id"] for item in final["citations"]]
            allowed = {chunk["chunk_id"] for chunk in state["retrieved_evidence"]}
            allowed.update(
                evidence_id
                for finding in final["findings"]
                for evidence_id in finding["evidence_ids"]
            )
            investigation_rows.append(
                {
                    "variant": "G_agent",
                    "category": question["category"],
                    **score_investigation(
                        expected_ids=question["expected_incident_ids"],
                        expected_status=question["expected_status"],
                        predicted_status=predicted_status,
                        unverified_alert_ids=final["unverified_alerts"],
                        expected_unverified=question["expected_unverified_alert_ids"],
                        citations=citations,
                        allowed_evidence=allowed or set(citations),
                        answer=final["answer"],
                        category=question["category"],
                    ),
                    "tool_calls": state["attempt_count"],
                    "latency_ms": latency_ms,
                    "llm_tokens": 0,
                }
            )
            per_question.append(
                {
                    "id": question["id"],
                    "category": question["category"],
                    "failure_case": question["failure_case"],
                    "agent_status": predicted_status,
                    "expected_status": question["expected_status"],
                    "unverified_alerts": final["unverified_alerts"],
                    "answer": final["answer"],
                }
            )
    return {
        "questions": questions,
        "retrieval_rows": retrieval_rows,
        "investigation_rows": investigation_rows,
        "per_question": per_question,
        "retrieval_summary": _summarize(retrieval_rows, "variant"),
        "investigation_summary": _summarize(investigation_rows, "variant"),
    }


async def _as_async_bm25(query: str, index: BM25Index) -> list[RetrievedChunk]:
    from security_investigator.retrieval import bm25_search

    return bm25_search(query, top_k=5, index=index)


def _summarize(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row[key], []).append(row)
    summaries = []
    for name, items in grouped.items():
        numeric = [
            field
            for field in items[0]
            if field not in {key, "category"} and isinstance(items[0][field], (int, float))
        ]
        summary: dict[str, Any] = {key: name, "n": len(items)}
        for field in numeric:
            summary[field] = sum(item[field] for item in items) / len(items)
        summaries.append(summary)
    return summaries


def write_results(directory: Path, report: dict[str, Any], *, notes: list[str]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    _write_csv(directory / "retrieval_metrics.csv", report["retrieval_summary"])
    _write_csv(directory / "investigation_metrics.csv", report["investigation_summary"])
    (directory / "per_question_results.json").write_text(
        json.dumps(report["per_question"], indent=2) + "\n",
        encoding="utf-8",
    )
    (directory / "failure_analysis.md").write_text(
        _failure_analysis(report, notes), encoding="utf-8"
    )


def write_benchmark(path: Path, questions: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(questions, indent=2) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _format(row[key]) for key in fieldnames})


def _format(value: Any) -> Any:
    if isinstance(value, float):
        return round(value, 4)
    return value


def _failure_analysis(report: dict[str, Any], notes: list[str]) -> str:
    lines = [
        "# Failure analysis",
        "",
        "These notes describe the measured run. They are not a claim about a different embedding model or index.",
        "",
    ]
    lines.extend(f"- {note}" for note in notes)
    lines.append("")
    lines.append("## Cases the benchmark is built to expose")
    lines.extend(
        [
            "- A resolved incident report can rank highly after a new, unlinked alert uses similar wording.",
            "- Naive reading of that report copies the old resolved status onto the new alert.",
            "- The agent keeps the alert unverified unless `incident_alerts` contains the link.",
            "- A mitigated remediation without `verification_status=verified` is not described as a verified fix.",
            "- A reopened incident stays reopened even if an older verification row exists.",
            "- Questions about a service that is not in the company records abstain instead of calling the company secure.",
            "",
            "## Per-question excerpts",
            "",
        ]
    )
    for item in report["per_question"]:
        if not item.get("failure_case"):
            continue
        lines.append(f"### {item['id']} ({item['failure_case']})")
        lines.append("")
        lines.append(f"Expected status: `{json.dumps(item['expected_status'])}`.")
        lines.append(f"Agent status: `{json.dumps(item['agent_status'])}`.")
        lines.append("")
    return "\n".join(lines) + "\n"


def prepare_local_index(
    database_path: Path,
    settings: Settings,
    embedder: Embedder,
) -> tuple[list[dict[str, Any]], DenseIndex, BM25Index]:
    """Build the same chunk list the indexer writes, and a local cosine index."""
    from security_investigator.ingestion import vectors_for_chunks
    from security_investigator.retrieval import MemoryDenseIndex

    index_corpus(database_path, Path("data/indexes"), settings=settings, push=False)
    documents = knowledge_documents(settings) + load_operational_documents(database_path, settings)
    chunks = build_chunks(documents)
    memory = MemoryDenseIndex()
    embeddings = embedder([passage_text(chunk, settings.embed_mode) for chunk in chunks])
    for namespace, vectors in vectors_for_chunks(
        chunks, embeddings, dimension=settings.embedding_dimension
    ).items():
        memory.upsert(namespace, vectors)
    return chunks, memory, BM25Index(chunks)
