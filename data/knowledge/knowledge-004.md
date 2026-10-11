---
document_id: knowledge-004
title: Cryptographic Failures
source_url: https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/
document_type: security_knowledge
taxonomy_version: OWASP Top 10:2025
license: CC BY-SA 4.0
---
## Summary

Cryptographic failures are A04:2025. They were A02:2021. The class covers missing encryption, weak algorithms, and secrets stored where application logs can read them. CWE-327 and CWE-326 are common members. A retired cipher suite or a token signed with a broken algorithm belongs here.

## Prevention

Use current, reviewed algorithms and rotate keys. Do not invent a cipher. Verification of a crypto fix is a recorded test, not a statement that the incident text looks resolved.
