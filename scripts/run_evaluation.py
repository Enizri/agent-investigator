"""Measure retrieval and investigation variants and write results/."""

import asyncio
from pathlib import Path

from security_investigator.config import get_settings
from security_investigator.evaluation import (
    evaluate,
    generate_benchmark,
    prepare_local_index,
    write_benchmark,
    write_results,
)
from security_investigator.generator import generate_company
from security_investigator.ingestion import sentence_transformer_embedder


def _summarizer_note(model_name: str) -> str:
    return (
        f"Chunk summaries are written by {model_name} during indexing and stored with each chunk. "
        "This measurement did not call the model. Status still comes from SQLite. "
    )


def main() -> None:
    settings = get_settings()
    database_path = Path(settings.database_path)
    if not database_path.exists():
        raise SystemExit("database is missing; run scripts/seed_database.py first")
    company = generate_company(seed=settings.random_seed, reference_time=settings.reference_time)
    questions = generate_benchmark(company.manifest)
    write_benchmark(Path("data/benchmarks/questions.json"), questions)
    embedder = sentence_transformer_embedder(settings.embedding_model)
    chunks, index, bm25_index = prepare_local_index(database_path, settings, embedder)
    report = asyncio.run(
        evaluate(
            database_path,
            settings=settings,
            embedder=embedder,
            index=index,
            chunks=chunks,
            bm25_index=bm25_index,
            questions=questions,
            rerank_enabled=settings.rerank_enabled,
        )
    )
    by_variant = {row["variant"]: row for row in report["retrieval_summary"]}
    investigation = {row["variant"]: row for row in report["investigation_summary"]}
    notes = [
        f"Dense vectors were produced locally with {settings.embedding_model} "
        f"({settings.embedding_dimension} dimensions, cosine). "
        "This run did not send queries through Pinecone; the ranking is the same cosine "
        "ordering an isolated dense index would return for these vectors.",
        f"Reranker: {settings.reranker_model}. Enabled: {settings.rerank_enabled}.",
        "Variant G uses the LangGraph agent and SQLite status reconstruction. "
        + _summarizer_note(settings.local_summarizer_model)
        + " Variants E and F read status words from retrieved prose and can copy an older status forward.",
        f"Questions: {len(questions)}. "
        f"Hybrid nDCG@5={by_variant['C_hybrid']['ndcg_at_5']:.4f}. "
        f"Reranked nDCG@5={by_variant['D_reranked']['ndcg_at_5']:.4f}.",
    ]
    if by_variant["D_reranked"]["ndcg_at_5"] + 1e-9 < by_variant["C_hybrid"]["ndcg_at_5"]:
        notes.append("On this benchmark, reranking decreased nDCG@5 relative to hybrid RRF.")
    else:
        notes.append("On this benchmark, reranking did not decrease nDCG@5 relative to hybrid RRF.")
    if "G_agent" in investigation and "E_dense_rag" in investigation:
        notes.append(
            "Agent status accuracy "
            f"{investigation['G_agent']['status_accuracy']:.4f} versus dense-only prose "
            f"{investigation['E_dense_rag']['status_accuracy']:.4f}."
        )
    write_results(Path("results"), report, notes=notes)
    print("wrote results/")
    for row in report["retrieval_summary"]:
        print(
            row["variant"],
            "ndcg",
            round(row["ndcg_at_5"], 4),
            "recall",
            round(row["recall_at_5"], 4),
        )


if __name__ == "__main__":
    main()
