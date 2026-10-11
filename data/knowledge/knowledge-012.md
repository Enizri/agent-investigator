---
document_id: knowledge-012
title: Testing for Insecure Direct Object References
source_url: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
document_type: security_knowledge
taxonomy_version: OWASP WSTG 4.2
license: CC BY-SA 4.0
---
## Summary

WSTG-ATHZ-04 covers insecure direct object references, aligned with CWE-639 and broken access control. The tester substitutes another object's id. The finding is confirmed when the response contains the other object's data or applies a change. A 403 with an empty body is a denial, not confirmation.

## Prevention

Compare the caller, the object owner, and the response. Keep the incident id when several alerts describe the same object-reference defect.
