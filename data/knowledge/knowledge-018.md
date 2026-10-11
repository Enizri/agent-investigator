---
document_id: knowledge-018
title: Testing for Server-Side Request Forgery
source_url: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery
document_type: security_knowledge
taxonomy_version: OWASP WSTG 4.2
license: CC BY-SA 4.0
---
## Summary

WSTG-INPV-19 tests SSRF. The interesting case is a webhook or invoice fetcher that accepts a link-local or metadata URL. CWE-918 applies. Blocked destinations and successful internal fetches are different outcomes and should not share a status.

## Prevention

Record the destination that was requested and whether the fetch was blocked. Do not copy a resolved SSRF incident's status onto a new alert.
