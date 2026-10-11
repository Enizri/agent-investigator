---
document_id: knowledge-007
title: Authentication Failures
source_url: https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/
document_type: security_knowledge
taxonomy_version: OWASP Top 10:2025
license: CC BY-SA 4.0
---
## Summary

Authentication failures are A07:2025. The 2021 name was identification and authentication failures. Weak session handling, missing revocation, and credential stuffing indicators live here. CWE-287, CWE-307, and CWE-613 are related. A password-rotation drill that produces failed logins can be a false positive when the alert was closed for that reason.

## Prevention

Revoke sessions on password reset, rate-limit failures, and require MFA where the policy says so. Distinguish a drill from an attack by the alert status and the investigation notes.
