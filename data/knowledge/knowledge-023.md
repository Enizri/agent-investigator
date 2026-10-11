---
document_id: knowledge-023
title: Testing Privilege Escalation
source_url: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation
document_type: security_knowledge
taxonomy_version: OWASP WSTG 4.2
license: CC BY-SA 4.0
---
## Summary

WSTG-ATHZ-03 tests privilege escalation. Mass assignment of a role field, CWE-915, is one path: a profile update sets an attribute the user interface never offered. Confirmation is a persisted role change, not the presence of the field name in a request.

## Prevention

Bind writable fields to an allow list. Check the stored role after the request before calling it a confirmed escalation.
