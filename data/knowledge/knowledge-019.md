---
document_id: knowledge-019
title: Testing for Weak TLS
source_url: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security
document_type: security_knowledge
taxonomy_version: OWASP WSTG 4.2
license: CC BY-SA 4.0
---
## Summary

WSTG cryptography tests include weak transport protection. A listener that still allows TLS 1.0 is a cryptographic failure, CWE-326, usually found by a configuration scan. It is not established by an ordinary HTTP 200 from a client.

## Prevention

Disable obsolete protocol versions and record the scan that verified the listener. An unverified config change stays mitigated, not verified.
