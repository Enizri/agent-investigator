---
document_id: knowledge-006
title: Insecure Design
source_url: https://owasp.org/Top10/2025/A06_2025-Insecure_Design/
document_type: security_knowledge
taxonomy_version: OWASP Top 10:2025
license: CC BY-SA 4.0
---
## Summary

Insecure design is A06:2025. It was A04:2021. The weakness is in the business rule itself, such as a refund path that skips a second approver. CWE-840 is a related business-logic class. These findings often come from design review or audit notes rather than from a single HTTP status code.

## Prevention

Threat-model the workflow and add the missing control. An audit finding is confirmed only when the incident record says so.
