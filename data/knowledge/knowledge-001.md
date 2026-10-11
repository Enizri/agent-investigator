---
document_id: knowledge-001
title: Broken Access Control
source_url: https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/
document_type: security_knowledge
taxonomy_version: OWASP Top 10:2025
license: CC BY-SA 4.0
---
## Summary

Broken access control is A01:2025 and remains the top risk. A caller supplies an object id and the service returns or changes another principal's data. CWE-639 covers insecure direct object references. In the 2025 list, server-side request forgery, CWE-918, is part of this category rather than its own item. Rank this as a confirmed vulnerability only when an authorization record shows the foreign object was actually reached. A resolved historical SSRF incident does not classify a new, unlinked alert as the same incident.

## Prevention

Authorize every object by owner or role on the server. Deny by default. For fetches the server makes, allow-list destinations and block link-local ranges. Regression tests should request a foreign id and expect a denial rather than a payload.
