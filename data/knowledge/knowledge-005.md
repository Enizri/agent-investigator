---
document_id: knowledge-005
title: Injection
source_url: https://owasp.org/Top10/2025/A05_2025-Injection/
document_type: security_knowledge
taxonomy_version: OWASP Top 10:2025
license: CC BY-SA 4.0
---
## Summary

Injection is A05:2025. It was A03:2021. Untrusted input is interpreted as a query, command, or template. CWE-89 is SQL injection. A blocked request that never reached the query executor is a suspicious or blocked attempt, not by itself a confirmed vulnerability.

## Prevention

Use parameterized queries and keep interpreters from receiving concatenated input. Confirm a fix by checking the incident timeline and the verification record, not by finding an older writeup that says the bug was fixed.
