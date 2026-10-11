---
document_id: knowledge-014
title: Testing Directory Traversal
source_url: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include
document_type: security_knowledge
taxonomy_version: OWASP WSTG 4.2
license: CC BY-SA 4.0
---
## Summary

WSTG-ATHZ-01 describes directory traversal and local file include testing. CWE-22 is the weakness that appears when a caller-supplied prefix is joined onto a filesystem path. Confirmation requires evidence that a file outside the intended root was read or written.

## Prevention

Resolve paths on the server and reject prefixes that escape the storage root. A suspicious path string that was rejected is not the same as a successful read.
