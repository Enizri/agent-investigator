---
document_id: knowledge-009
title: Security Logging and Alerting Failures
source_url: https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/
document_type: security_knowledge
taxonomy_version: OWASP Top 10:2025
license: CC BY-SA 4.0
---
## Summary

Security logging and alerting failures are A09:2025. The 2021 name emphasized monitoring. Privileged actions or denied requests that never reach the audit trail are the finding, and a log that nobody alerts on does not finish the control. CWE-778 is insufficient logging. This class is often found by an audit, not by reading a successful HTTP 200 as if it were an exploit.

## Prevention

Log security-relevant denials and privileged changes with a stable request id, and alert on those events. Do not log secrets, session tokens, or raw credentials.
