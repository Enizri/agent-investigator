"""Security investigation agent: retrieve evidence, then verify it in SQLite."""

__version__ = "0.1.0"


def main() -> None:
    import uvicorn

    from security_investigator.api import app
    from security_investigator.llm import LocalChunkSummarizer, load_local_summarizer

    summarizer = app.state.deps.chunk_summarizer
    if isinstance(summarizer, LocalChunkSummarizer):
        load_local_summarizer(summarizer.model)
    uvicorn.run(app, host="127.0.0.1", port=8000)
