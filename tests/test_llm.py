"""Local situating context and the final answer model."""

from security_investigator.config import Settings
from security_investigator.llm import (
    OllamaAnswerModel,
    answer_model_from_settings,
    situate_context,
    situate_context_async,
    strip_model_thinking,
)


async def test_situate_context_uses_the_supplied_writer() -> None:
    def complete(document: str, chunk: str) -> str:
        assert "billing" in document
        assert "admin" in chunk
        return "<think>draft</think> This chunk is the billing admin check."

    context = situate_context("billing document", "admin chunk", complete=complete)
    assert context == "This chunk is the billing admin check."
    again = await situate_context_async("billing document", "admin chunk", complete=complete)
    assert again == context


def test_final_answer_uses_the_local_model() -> None:
    model = answer_model_from_settings(Settings(_env_file=None))
    assert isinstance(model, OllamaAnswerModel)
    assert model.model == "qwen3:8b"
    assert answer_model_from_settings(Settings(_env_file=None, local_summarizer_enabled=False)) is None


async def test_answer_model_drops_a_thinking_trace() -> None:
    model = OllamaAnswerModel(
        complete=lambda prompt: "<think>draft</think> Findings: Incident 2 is open."
    )
    assert await model.complete("question") == "Findings: Incident 2 is open."
    assert strip_model_thinking("<think>hidden</think> kept") == "kept"
