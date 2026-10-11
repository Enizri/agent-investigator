---
document_id: knowledge-008
title: Software or Data Integrity Failures
source_url: https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/
document_type: security_knowledge
taxonomy_version: OWASP Top 10:2025
license: CC BY-SA 4.0
---
## Summary

Software or data integrity failures are A08:2025. The 2021 title said software and data integrity failures. Unsigned artifacts, unsigned webhooks, and updates that skip a signature check belong here. CWE-494 and CWE-345 are related. Sparse logs do not erase a confirmed integrity incident; they limit how much of the timeline can be reconstructed.

## Prevention

Verify signatures before deploy and before accepting webhook bodies. If the only evidence is one audit line, say the record is incomplete instead of inventing the missing steps.
