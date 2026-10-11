---
document_id: knowledge-002
title: Security Misconfiguration
source_url: https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/
document_type: security_knowledge
taxonomy_version: OWASP Top 10:2025
license: CC BY-SA 4.0
---
## Summary

Security misconfiguration is A02:2025. It moved up from A05:2021. Default settings, open cloud policies, verbose errors, and unnecessary services sit in this class. CWE-16 is the broad configuration weakness. A bucket that allows anonymous listing is a misconfiguration even when no HTTP exploit payload appears in the logs.

## Prevention

Ship hardened baselines and review infrastructure diffs. Applying a tighter policy is mitigation. It is a verified fix only after verification_status is verified.
