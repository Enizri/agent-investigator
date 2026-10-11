---
document_id: knowledge-013
title: Testing for Bypassing Authorization Schema
source_url: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema
document_type: security_knowledge
taxonomy_version: OWASP WSTG 4.2
license: CC BY-SA 4.0
---
## Summary

WSTG-ATHZ-02 tests whether a lower-privileged caller can invoke an administrative path. A viewer receiving HTTP 403 on an admin page can be expected RBAC behavior. Repeated denials are not automatically an incident.

## Prevention

Map each route to a required role. Treat expected denials as noise unless a lower role receives a successful privileged response.
