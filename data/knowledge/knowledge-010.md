---
document_id: knowledge-010
title: Mishandling of Exceptional Conditions
source_url: https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/
document_type: security_knowledge
taxonomy_version: OWASP Top 10:2025
license: CC BY-SA 4.0
---
## Summary

Mishandling of exceptional conditions is A10:2025, a new category. The program fails to prevent, detect, or recover from an abnormal state, including failing open and leaking internals in an error. CWE-209 is an error message that contains sensitive information, and CWE-636 is not failing securely. A stack trace shown to a caller is not, by itself, proof that an older incident is still open.

## Prevention

Handle the error where it occurs, roll the whole transaction back, and avoid returning internal details to the caller. Status still comes from the incident timeline.
