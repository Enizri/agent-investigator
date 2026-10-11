# Failure analysis

These notes describe the measured run. They are not a claim about a different embedding model or index.

- Dense vectors were produced locally with BAAI/bge-small-en-v1.5 (384 dimensions, cosine). This run did not send queries through Pinecone; the ranking is the same cosine ordering an isolated dense index would return for these vectors.
- Reranker: cross-encoder/ms-marco-MiniLM-L6-v2. Enabled: True.
- Variant G uses the LangGraph agent and SQLite status reconstruction. It did not call an LLM, so token usage is 0. Variants E and F read status words from retrieved prose and can copy an older status forward.
- Questions: 83. Hybrid nDCG@5=0.5373. Reranked nDCG@5=0.5607.
- On this benchmark, reranking did not decrease nDCG@5 relative to hybrid RRF.
- Agent status accuracy 1.0000 versus dense-only prose 0.4357.

## Cases the benchmark is built to expose
- A resolved incident report can rank highly after a new, unlinked alert uses similar wording.
- Naive reading of that report copies the old resolved status onto the new alert.
- The agent keeps the alert unverified unless `incident_alerts` contains the link.
- A mitigated remediation without `verification_status=verified` is not described as a verified fix.
- A reopened incident stays reopened even if an older verification row exists.
- Questions about a service that is not in the company records abstain instead of calling the company secure.

## Per-question excerpts

### q-004 (reopened)

Expected status: `{"4": "reopened"}`.
Agent status: `{"11": "resolved", "3": "resolved", "26": "resolved", "17": "resolved", "7": "resolved", "22": "reopened", "14": "reopened", "13": "resolved", "28": "resolved", "21": "resolved", "1": "resolved", "12": "false_positive", "15": "resolved", "4": "reopened", "10": "mitigated", "24": "resolved", "20": "false_positive", "19": "mitigated", "29": "false_positive", "27": "mitigated", "6": "investigating", "9": "investigating", "5": "mitigated", "25": "investigating", "18": "investigating", "2": "open", "23": "open", "8": "open", "30": "open", "16": "open"}`.

### q-014 (reopened)

Expected status: `{"14": "reopened"}`.
Agent status: `{"11": "resolved", "3": "resolved", "26": "resolved", "17": "resolved", "7": "resolved", "22": "reopened", "14": "reopened", "13": "resolved", "28": "resolved", "21": "resolved", "1": "resolved", "12": "false_positive", "15": "resolved", "4": "reopened", "10": "mitigated", "24": "resolved", "20": "false_positive", "19": "mitigated", "29": "false_positive", "27": "mitigated", "6": "investigating", "9": "investigating", "5": "mitigated", "25": "investigating", "18": "investigating", "2": "open", "23": "open", "8": "open", "30": "open", "16": "open"}`.

### q-022 (reopened)

Expected status: `{"22": "reopened"}`.
Agent status: `{"11": "resolved", "3": "resolved", "26": "resolved", "17": "resolved", "7": "resolved", "22": "reopened", "14": "reopened", "13": "resolved", "28": "resolved", "21": "resolved", "1": "resolved", "12": "false_positive", "15": "resolved", "4": "reopened", "10": "mitigated", "24": "resolved", "20": "false_positive", "19": "mitigated", "29": "false_positive", "27": "mitigated", "6": "investigating", "9": "investigating", "5": "mitigated", "25": "investigating", "18": "investigating", "2": "open", "23": "open", "8": "open", "30": "open", "16": "open"}`.

### q-031 (outdated_report)

Expected status: `{"1": "investigating"}`.
Agent status: `{"11": "resolved", "3": "resolved", "22": "resolved", "28": "open", "1": "investigating"}`.

### q-032 (new_alert_like_resolved_incident)

Expected status: `{"3": "resolved"}`.
Agent status: `{"11": "resolved", "3": "resolved", "22": "reopened", "28": "resolved", "1": "resolved", "16": "open"}`.

### q-033 (blocked_attempt)

Expected status: `{}`.
Agent status: `{"11": "resolved", "3": "resolved", "22": "reopened", "28": "resolved", "1": "resolved", "16": "open"}`.

### q-034 (false_positive)

Expected status: `{}`.
Agent status: `{"26": "resolved", "14": "reopened", "4": "reopened", "20": "false_positive", "8": "open"}`.

### q-035 (unverified_remediation)

Expected status: `{"5": "mitigated"}`.
Agent status: `{"12": "false_positive", "24": "resolved", "5": "mitigated", "18": "investigating", "30": "open"}`.

### q-036 (sparse_logs)

Expected status: `{"6": "investigating"}`.
Agent status: `{"17": "resolved", "10": "mitigated", "29": "false_positive", "6": "investigating", "23": "open"}`.

### q-043 (temporal)

Expected status: `{"4": "reopened", "5": "mitigated", "22": "reopened"}`.
Agent status: `{"11": "resolved", "3": "resolved", "26": "resolved", "17": "resolved", "7": "resolved", "22": "reopened", "14": "reopened", "13": "resolved", "28": "resolved", "21": "resolved", "1": "resolved", "12": "false_positive", "15": "resolved", "4": "reopened", "10": "mitigated", "24": "resolved", "20": "false_positive", "19": "mitigated", "29": "false_positive", "27": "mitigated", "6": "investigating", "9": "investigating", "5": "mitigated", "25": "investigating", "18": "investigating", "2": "open", "23": "open", "8": "open", "30": "open", "16": "open"}`.

### q-044 (abstention)

Expected status: `{}`.
Agent status: `{}`.

### q-045 (abstention)

Expected status: `{}`.
Agent status: `{}`.

### q-046 (abstention)

Expected status: `{}`.
Agent status: `{}`.

### q-083 (current_status)

Expected status: `{"2": "open", "23": "open"}`.
Agent status: `{"2": "open", "23": "open"}`.

