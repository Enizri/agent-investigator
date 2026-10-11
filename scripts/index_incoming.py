"""Summarize one new record with the local model and store it beside the seeded index."""

import argparse
import sys
from pathlib import Path

from security_investigator.config import get_settings
from security_investigator.ingestion import index_incoming
from security_investigator.llm import OllamaChunkSummarizer


def main() -> None:
    parser = argparse.ArgumentParser(description="Index one new incoming record")
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--text", default="")
    args = parser.parse_args()
    text = args.text or sys.stdin.read()
    settings = get_settings()
    summarizer = None
    if settings.local_summarizer_enabled:
        summarizer = OllamaChunkSummarizer(
            model=settings.local_summarizer_model,
            base_url=settings.ollama_base_url,
        )
    try:
        stored = index_incoming(
            text,
            title=args.title,
            source_id=args.source_id,
            index_directory=Path("data/indexes"),
            settings=settings,
            summarizer=summarizer,
        )
    except (RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    action = "reused the stored summary" if stored["reused"] else "wrote a new summary"
    print(f"{stored['chunk_id']}: {action}")
    if stored["summary"]:
        print(stored["summary"])


if __name__ == "__main__":
    main()
