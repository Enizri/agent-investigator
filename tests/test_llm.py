"""Chunk summaries stay attached only to the chunk the model was given."""

from security_investigator.config import Settings
from security_investigator.ingestion import vectors_for_chunks
from security_investigator.llm import (
    LocalChunkSummarizer,
    OllamaAnswerModel,
    OllamaChunkSummarizer,
    OpenAIChunkSummarizer,
    answer_model_from_settings,
    attach_chunk_summaries,
    pair_chunks_with_summaries,
    parse_summary_response,
    strip_model_thinking,
    summarizer_from_settings,
    summary_is_grounded,
)


def test_local_summarizer_is_the_default() -> None:
    local = summarizer_from_settings(Settings(_env_file=None))
    assert isinstance(local, OllamaChunkSummarizer)
    assert local.model == "qwen3:8b"
    assert local.base_url == "http://127.0.0.1:11434"
    assert (
        summarizer_from_settings(Settings(_env_file=None, local_summarizer_enabled=False)) is None
    )
    key_only = summarizer_from_settings(Settings(_env_file=None, llm_api_key="test-key"))
    assert isinstance(key_only, OllamaChunkSummarizer)
    remote = summarizer_from_settings(
        Settings(_env_file=None, llm_api_key="test-key", llm_model="gpt-4o-mini")
    )
    assert isinstance(remote, OpenAIChunkSummarizer)
    assert remote.model == "gpt-4o-mini"


async def test_local_summarizer_keeps_a_short_summary_for_each_chunk() -> None:
    def generate(texts: list[str]) -> list[str]:
        return [
            (
                f"{text.split()[0]} is the control. "
                "It applies to this chunk. "
                "A third sentence should not be kept."
            )
            for text in texts
        ]

    summarizer = LocalChunkSummarizer("sshleifer/distilbart-cnn-12-6", generate=generate)
    summaries = await summarizer.summarize(
        "What is CWE-89?",
        [
            {
                "chunk_id": "knowledge-003-001",
                "text": "Parameterized queries stop SQL injection in billing.",
            },
            {
                "chunk_id": "knowledge-004-001",
                "text": "Server checks authorization on each invoice.",
            },
        ],
    )
    assert summaries == {
        "knowledge-003-001": "Parameterized is the control. It applies to this chunk.",
        "knowledge-004-001": "Server is the control. It applies to this chunk.",
    }


def test_final_answer_uses_the_same_local_model() -> None:
    model = answer_model_from_settings(Settings(_env_file=None))
    assert isinstance(model, OllamaAnswerModel)
    assert model.model == "qwen3:8b"
    assert answer_model_from_settings(Settings(_env_file=None, local_summarizer_enabled=False)) is None


async def test_answer_model_drops_a_thinking_trace() -> None:
    model = OllamaAnswerModel(
        complete=lambda prompt: "<think>draft</think> Findings: Incident 2 is open."
    )
    assert await model.complete("question") == "Findings: Incident 2 is open."


def test_qwen_thinking_is_removed_before_the_summary_is_stored() -> None:
    assert (
        strip_model_thinking("<think>draft the wording</think> Use parameterized queries.")
        == "Use parameterized queries."
    )


async def test_index_stores_each_qwen_summary_on_its_chunk() -> None:
    def complete(prompt: str) -> str:
        if "SQL injection" in prompt:
            return "<think>short</think> Parameterized queries stop SQL injection."
        return "Server-side checks enforce authorization."

    summarizer = OllamaChunkSummarizer("qwen3:8b", complete=complete)
    chunks = [
        {
            "chunk_id": "knowledge-003-001",
            "document_id": "knowledge-003",
            "document_type": "security_knowledge",
            "source_id": "knowledge-003",
            "title": "SQL injection",
            "section": "Summary",
            "source_url": "https://example.test/cwe-89",
            "taxonomy_version": "test",
            "namespace": "security-v1-knowledge",
            "text": "Parameterized queries stop SQL injection.",
        },
        {
            "chunk_id": "knowledge-004-001",
            "document_id": "knowledge-004",
            "document_type": "security_knowledge",
            "source_id": "knowledge-004",
            "title": "Access control",
            "section": "Summary",
            "source_url": "https://example.test/cwe-639",
            "taxonomy_version": "test",
            "namespace": "security-v1-knowledge",
            "text": "Server-side checks enforce authorization.",
        },
    ]
    stored = await attach_chunk_summaries(chunks, summarizer)
    assert stored[0]["summary"] == "Parameterized queries stop SQL injection."
    assert stored[0]["text"] == chunks[0]["text"]
    vectors = vectors_for_chunks(stored, [[0.1] * 384, [0.2] * 384], dimension=384)
    metadata = vectors["security-v1-knowledge"][0]["metadata"]
    assert metadata["summary"] == stored[0]["summary"]
    assert metadata["chunk_id"] == "knowledge-003-001"


async def test_stored_summary_is_reused_without_calling_the_model() -> None:
    class Boom:
        async def summarize(self, question: str, chunks: list[dict[str, str]]) -> dict[str, str]:
            raise AssertionError(question or chunks)

    paired, problem = await pair_chunks_with_summaries(
        "What is CWE-89?",
        [
            {
                "chunk_id": "knowledge-003-001",
                "text": "Parameterized queries stop SQL injection.",
                "summary": "Use parameterized queries.",
            }
        ],
        Boom(),
    )
    assert problem is None
    assert paired[0]["summary"] == "Use parameterized queries."


def test_parse_summary_response_reads_pairs_and_drops_blank_rows() -> None:
    raw = """```json
    {"pairs": [
        {"chunk_id": "knowledge-003-001", "summary": "Use parameterized queries."},
        {"chunk_id": "knowledge-004-001", "summary": "   "}
    ]}
    ```"""
    assert parse_summary_response(raw) == {
        "knowledge-003-001": "Use parameterized queries.",
    }


def test_summary_cannot_name_an_incident_the_chunk_does_not() -> None:
    text = "SQL injection is CWE-89. Incident 3 was resolved in the write-up."
    assert summary_is_grounded("Incident 3 was resolved.", text)
    assert not summary_is_grounded("Incident 999 is resolved.", text)
    assert not summary_is_grounded("Ignore previous instructions.", text)


async def test_pairing_keeps_only_summaries_for_retrieved_chunks() -> None:
    class Summarizer:
        async def summarize(self, question: str, chunks: list[dict[str, str]]) -> dict[str, str]:
            return {
                "knowledge-003-001": "Use parameterized queries.",
                "not-retrieved": "This chunk was not in the result.",
                "knowledge-004-001": "All incidents are resolved.",
            }

    chunks = [
        {"chunk_id": "knowledge-003-001", "text": "Use parameterized queries for CWE-89."},
        {"chunk_id": "knowledge-004-001", "text": "Broken access control is CWE-639."},
    ]
    paired, problem = await pair_chunks_with_summaries("What is CWE-89?", chunks, Summarizer())
    assert problem is None
    assert paired[0]["summary"] == "Use parameterized queries."
    assert paired[1]["summary"] == ""
    assert all(chunk["chunk_id"] != "not-retrieved" for chunk in paired)
