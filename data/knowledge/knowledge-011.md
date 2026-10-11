---
document_id: knowledge-011
title: Testing for SQL Injection
source_url: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection
document_type: security_knowledge
taxonomy_version: OWASP WSTG 4.2
license: CC BY-SA 4.0
---
## Summary

WSTG-INPV-05 describes how testers look for SQL injection. Useful evidence is a query that changes result sets or error behavior because input was concatenated. A gateway 403 that stops the request before the query executor is a blocked attempt under this test, not a confirmed CWE-89 finding.

## Prevention

Prefer evidence from the application query path. Record the request id, the HTTP status, and whether the statement was parameterized.
