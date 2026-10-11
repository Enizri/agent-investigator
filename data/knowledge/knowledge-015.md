---
document_id: knowledge-015
title: Testing for Default Credentials
source_url: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials
document_type: security_knowledge
taxonomy_version: OWASP WSTG 4.2
license: CC BY-SA 4.0
---
## Summary

WSTG-ATHN-02 looks for default credentials. Scanners often report them on admin services. Close the alert as a false positive when the investigation shows the default secret is not configured. CWE-1392 and CWE-798 are the related weakness names.

## Prevention

Remove vendor defaults before exposure. Record the negative check so a later reader does not reopen the alert from the scanner text alone.
