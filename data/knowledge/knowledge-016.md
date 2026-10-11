---
document_id: knowledge-016
title: Testing Session Timeout
source_url: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/07-Testing_Session_Timeout
document_type: security_knowledge
taxonomy_version: OWASP WSTG 4.2
license: CC BY-SA 4.0
---
## Summary

WSTG-SESS-07 checks that sessions expire. CWE-613 is insufficient session expiration. A regression that brings back sessions after password reset is an authentication failure even if an older incident was once marked resolved.

## Prevention

Bind revocation to password reset and to explicit logout. Reconstruct status from incident events when a resolved case is reopened.
