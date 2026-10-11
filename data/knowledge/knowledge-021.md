---
document_id: knowledge-021
title: Testing CORS
source_url: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing
document_type: security_knowledge
taxonomy_version: OWASP WSTG 4.2
license: CC BY-SA 4.0
---
## Summary

WSTG-CLNT-07 tests cross-origin resource sharing. CWE-942 is an overly permissive cross-domain policy. A reflected origin on an internal route is a misconfiguration. Browser errors alone do not show whether another site could read the response.

## Prevention

Allow only named origins. Verify the deployed policy, not just the pull request text.
