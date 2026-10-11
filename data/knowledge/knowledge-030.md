---
document_id: knowledge-030
title: Improper Restriction of Excessive Authentication Attempts
source_url: https://cwe.mitre.org/data/definitions/307.html
document_type: security_knowledge
taxonomy_version: CWE 4.17
license: MITRE CWE, attributed summary, not a verbatim copy
---
## Summary

CWE-307 is unrestricted authentication attempts. Bursts of failed logins during a password-rotation drill can trip this rule. Closure as a false positive is valid when the notes say the activity was a drill.

## Prevention

When a record cites CWE-307, retrieve this note for the definition and then verify the live status in SQLite. The CWE page does not know whether this company's incident is open.
