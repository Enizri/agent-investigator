# Security Investigation Agent

A local agent for a fictional SaaS company. It answers security questions from a synthetic record. It does not scan or change a real environment.

SQLite is the authority for incident status. Status at a time is replayed from `incident_events`, not copied from a similar document. Dense search, BM25, and a cross-encoder supply text. A local Qwen model writes the final reply only from incidents the tools already returned.

## Setup

Python 3.12 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
cp .env.example .env
uv run python scripts/seed_database.py
uv run python scripts/index_documents.py
uv run security-investigator
```

`seed_database.py` writes `data/security.db`. The same seed writes the same rows. `index_documents.py` writes `data/indexes/chunks.jsonl` and uses the short summaries already stored with those documents. It upserts to Pinecone only when `PINECONE_API_KEY` is set. Qwen is not called for the seeded index.

Ask a question:

```bash
curl -s localhost:8000/investigate \
  -H 'content-type: application/json' \
  -d '{"question":"Which critical incidents are active?"}'
```

Set `OLLAMA_BASE_URL=http://127.0.0.1:11434` so the reply can use local `qwen3:8b`. The answer has four parts: what was found, whether a matching incident was seen before, how that earlier record says it was fixed, and a recommendation when no fix is on record.

A new alert that is not in the seed is summarized once:

```bash
uv run python scripts/index_incoming.py \
  --source-id alert-new \
  --title "New admin alert" \
  --text "GET /admin returned 200 for a user role."
```

## How an answer is made

```text
question
  -> classify and plan (at most 6 tool steps)
  -> read-only SQLite tools
  -> hybrid retrieval (dense + BM25, optional reranker)
  -> verify status in incident_events
  -> Qwen reply from those records
```

The company has six services, 90 days of history, and planted cases for a resolved bug, an open bug, a reopened bug, a blocked attempt, and a lookalike alert. Knowledge briefs are short notes attributed to OWASP Top 10:2025, OWASP WSTG 4.2, and CWE. The agent does not read `data/scenarios/manifest.json` or `data/benchmarks/questions.json`.

`EMBED_MODE` chooses what is embedded: `original`, `summary`, or `contextual` (summary, then the chunk). The default is `contextual`. Compare them in `notebooks/embedding_approaches.ipynb`.

## Checks and evaluation

```bash
uv run pytest
uv run python scripts/run_evaluation.py
```

`scripts/run_evaluation.py` writes `results/`. Retrieval is scored with Recall@5, Precision@5, MRR, and nDCG@5. The agent is scored on whether it names the expected incidents and whether those statuses match the timeline. A reader that trusts retrieved prose can copy an old resolved status onto a new alert. The agent does not.
