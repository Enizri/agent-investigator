---
document_id: knowledge-039
title: Insufficient Verification of Data Authenticity
source_url: https://cwe.mitre.org/data/definitions/345.html
document_type: security_knowledge
taxonomy_version: CWE 4.17
license: MITRE CWE, attributed summary, not a verbatim copy
---
## Summary

CWE-345 is insufficient verification of data authenticity. Unsigned payment webhooks are an example. Accepting the body because the source IP looked familiar is not a verification.

## Prevention

When a record cites CWE-345, retrieve this note for the definition and then verify the live status in SQLite. The CWE page does not know whether this company's incident is open.
