---
document_id: knowledge-025
title: Testing Logout and Session Revocation
source_url: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality
document_type: security_knowledge
taxonomy_version: OWASP WSTG 4.2
license: CC BY-SA 4.0
---
## Summary

WSTG-SESS-06 checks logout. A session that still works after logout or after password reset is an authentication failure. If the fix was verified and a later config rollback reopens the incident, the current status is reopened, not resolved.

## Prevention

Invalidate the server-side session and refresh tokens. Read the latest incident event before answering whether the weakness is still active.
