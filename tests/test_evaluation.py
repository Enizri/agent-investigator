"""Metric formulas and a small end-to-end benchmark run."""

import hashlib
from pathlib import Path

from security_investigator.config import Settings
from security_investigator.database import write_database
from security_investigator.evaluation import (
    evaluate,
    generate_benchmark,
    mean_reciprocal_rank,
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
    split_for,
)
from security_investigator.generator import generate_company
from security_investigator.ingestion import (
    build_chunks,
    knowledge_documents,
    load_operational_documents,
    vectors_for_chunks,
)
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


def test_metric_formulas() -> None:
    relevant = {"a", "c"}
    retrieved = ["b", "a", "c"]
    assert recall_at_k(retrieved, relevant, 2) == 0.5
    assert precision_at_k(retrieved, relevant, 2) == 0.5
    assert mean_reciprocal_rank(retrieved, relevant) == 0.5
    perfect = ndcg_at_k(["a", "c"], relevant, 2)
    worse = ndcg_at_k(["b", "a"], relevant, 2)
    assert perfect == 1.0
    assert worse < perfect
    assert recall_at_k([], set(), 5) == 1.0


def test_benchmark_is_large_split_and_hidden_from_runtime_paths() -> None:
    manifest = generate_company().manifest
    questions = generate_benchmark(manifest)
    assert 80 <= len(questions) <= 120
    splits = {item["split"] for item in questions}
    assert splits == {"train", "dev", "test"}
    families = {item["family"] for item in questions}
    assert all(
        split_for(family) == next(item["split"] for item in questions if item["family"] == family)
        for family in families
    )
    failure_cases = {item["failure_case"] for item in questions}
    assert "outdated_report" in failure_cases
    assert "new_alert_like_resolved_incident" in failure_cases
    assert "blocked_attempt" in failure_cases
    assert "unverified_remediation" in failure_cases
    assert "abstention" in failure_cases
    assert "reopened" in failure_cases
    assert "sparse_logs" in failure_cases


async def test_evaluate_runs_every_variant_on_the_same_questions(tmp_path: Path) -> None:
    company = generate_company()
    database_path = tmp_path / "security.db"
    write_database(database_path, company.tables)
    settings = Settings(_env_file=None)
    questions = generate_benchmark(company.manifest)[:4]
    documents = knowledge_documents(settings) + load_operational_documents(database_path, settings)
    chunks = build_chunks(documents)
    memory = MemoryDenseIndex()
    embeddings = _embed([chunk["text"] for chunk in chunks])
    for namespace, vectors in vectors_for_chunks(chunks, embeddings, dimension=384).items():
        memory.upsert(namespace, vectors)
    report = await evaluate(
        database_path,
        settings=settings,
        embedder=_embed,
        index=memory,
        chunks=chunks,
        bm25_index=BM25Index(chunks),
        questions=questions,
        rerank_enabled=False,
    )
    variants = {row["variant"] for row in report["retrieval_summary"]}
    assert variants == {"A_dense", "B_bm25", "C_hybrid", "D_reranked"}
    assert {row["variant"] for row in report["investigation_summary"]} >= {
        "E_dense_rag",
        "F_hybrid_rag",
        "G_agent",
    }
    assert report["retrieval_summary"][0]["n"] == len(questions)
