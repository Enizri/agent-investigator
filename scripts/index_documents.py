"""Write the seeded chunk store. Summaries come from the seed, not from a model."""

from pathlib import Path

from security_investigator.config import get_settings
from security_investigator.ingestion import export_knowledge_markdown, index_corpus


def main() -> None:
    settings = get_settings()
    export_knowledge_markdown(Path("data/knowledge"), settings)
    push = bool(settings.pinecone_api_key)
    manifest = index_corpus(
        Path(settings.database_path),
        Path("data/indexes"),
        settings=settings,
        push=push,
    )
    destination = "Pinecone and the local chunk store" if push else "the local chunk store"
    print(
        f"indexed {manifest['chunk_count']} chunks into {destination} "
        f"with embed mode {manifest['embed_mode']} "
        f"(hash {manifest['content_hash'][:12]})"
    )
    print(
        f"used {manifest['summarized_count']} summaries already written with the seed; "
        "Qwen was not called"
    )
    if not push:
        print("PINECONE_API_KEY is empty, so remote upsert was skipped")


if __name__ == "__main__":
    main()
