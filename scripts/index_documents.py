"""Chunk the seeded database, situate each chunk, and write the local index."""

import argparse
import asyncio
from pathlib import Path

from security_investigator.config import get_settings
from security_investigator.preprocess import preprocess_corpus


def main() -> None:
    parser = argparse.ArgumentParser(description="Index the seeded documents.")
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Situate and embed only the first N chunks. Use this to try the model.",
    )
    args = parser.parse_args()
    settings = get_settings()
    database_path = Path(settings.database_path)
    if not database_path.exists():
        raise SystemExit("database is missing; run scripts/seed_database.py first")
    manifest = asyncio.run(
        preprocess_corpus(
            database_path,
            Path("data/indexes"),
            settings=settings,
            limit=args.limit,
            progress=True,
        )
    )
    print(
        f"indexed {manifest['chunk_count']} seeded chunks "
        f"(hash {manifest['content_hash'][:12]})"
    )
    print(
        f"situating context was written by {settings.local_summarizer_model} "
        f"on {settings.situate_workers} workers"
    )


if __name__ == "__main__":
    main()
