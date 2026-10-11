---
document_id: knowledge-017
title: Testing for Command Injection
source_url: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection
document_type: security_knowledge
taxonomy_version: OWASP WSTG 4.2
license: CC BY-SA 4.0
---
## Summary

WSTG-INPV-12 covers OS command injection. CWE-78 applies when a filename or argument is passed through a shell. Export jobs and admin tools are typical places. HTTP 500 after metacharacters is a signal, not proof, until the incident confirms the shell was invoked.

## Prevention

Call the program with an argument array and refuse shell interpolation. Keep the finding tied to the incident id.
