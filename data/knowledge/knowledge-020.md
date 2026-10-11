---
document_id: knowledge-020
title: Testing for Error Handling
source_url: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Improper_Error_Handling
document_type: security_knowledge
taxonomy_version: OWASP WSTG 4.2
license: CC BY-SA 4.0
---
## Summary

WSTG-ERRH-01 looks for errors that reveal internals. CWE-209 is generation of an error message containing sensitive information. A debug route that exposes invoice totals is closer to misconfiguration, but the error text itself is still sensitive data.

## Prevention

Return stable error ids to clients and keep stack traces in private logs. Do not put secrets in either place.
