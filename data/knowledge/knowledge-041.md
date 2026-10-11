---
document_id: knowledge-041
title: Path Traversal
source_url: https://cwe.mitre.org/data/definitions/22.html
document_type: security_knowledge
taxonomy_version: CWE 4.17
license: MITRE CWE, attributed summary, not a verbatim copy
---
## Summary

CWE-22 is path traversal. A download handler that joins a caller-supplied prefix can leave the storage root. Confirmation is a file outside that root, not a dot-dot string that was rejected.

## Prevention

When a record cites CWE-22, retrieve this note for the definition and then verify the live status in SQLite. The CWE page does not know whether this company's incident is open.
