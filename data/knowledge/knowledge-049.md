---
document_id: knowledge-049
title: Use of Hard-coded Credentials
source_url: https://cwe.mitre.org/data/definitions/798.html
document_type: security_knowledge
taxonomy_version: CWE 4.17
license: MITRE CWE, attributed summary, not a verbatim copy
---
## Summary

CWE-798 is use of hard-coded credentials. It sits next to default-password scanner hits. A report that the default password is absent should stay a false positive unless a new record contradicts it.

## Prevention

When a record cites CWE-798, retrieve this note for the definition and then verify the live status in SQLite. The CWE page does not know whether this company's incident is open.
