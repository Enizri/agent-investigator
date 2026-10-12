# Security Investigation Agent

A local agent for a fictional SaaS company. It answers security questions from a seeded record. It does not scan or change a real environment.

SQLite is the authority for incident status. Status at a time is replayed from `incident_events`, not copied from a similar document. Retrieval follows the contextual-retrieval order: raw dense search, contextual dense search, contextual BM25 blended at 0.8/0.2, then a cross-encoder. A local Qwen model writes each chunk's situating sentence once, and writes the final reply only from incidents the tools already returned.

## Setup

Python 3.12 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
cp .env.example .env
uv run python scripts/seed_database.py
uv run python scripts/index_documents.py --limit 8
```

`seed_database.py` writes the full `data/security.db` and returns. `index_documents.py` is the slow step: it asks local `qwen3:8b` for one situating sentence per chunk. `--limit 8` indexes the first 8 chunks so you can see that load finish. Omit `--limit` to index every chunk. Set `OLLAMA_BASE_URL=http://127.0.0.1:11434` before indexing.

## How an answer is made

```text
question
  -> classify and plan (at most 6 tool steps)
  -> read-only SQLite tools
  -> contextual hybrid retrieval, then rerank
  -> verify status in incident_events
  -> Qwen reply from those records
```

The company has six services, 90 days of history, and planted cases for a resolved bug, an open bug, a reopened bug, a blocked attempt, and a lookalike alert. Knowledge briefs are short notes attributed to OWASP Top 10:2025, OWASP WSTG 4.2, and CWE. The agent does not read `data/scenarios/manifest.json`.

## Checks

```bash
uv run pytest
```

Retrieval scores live in `notebooks/contextual_rag_01.ipynb`. Run the cells from the project root. The first cell indexes 145 documents and shows a tqdm bar while Qwen writes each situating sentence. The next cells print Pass@5, Pass@10, and Pass@20 in this order: basic dense, contextual dense, contextual BM25 hybrid, rerank. The questions mix incidents with similar alerts and do not repeat the document title. Raise `DOCUMENT_LIMIT` in that first cell when you want a larger set. A later cell calls the LangGraph agent and prints the SQLite status. It does not score the agent. Ollama must be running at `http://127.0.0.1:11434` with `qwen3:8b`.
