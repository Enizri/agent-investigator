---
document_id: knowledge-024
title: Testing Business Logic
source_url: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation
document_type: security_knowledge
taxonomy_version: OWASP WSTG 4.2
license: CC BY-SA 4.0
---
## Summary

WSTG-BUSL-01 covers business-logic data validation. Insecure design such as a refund that skips a second approver will not always raise an HTTP error. The audit note is the evidence. CWE-840 is a useful label when the workflow itself is the defect.

## Prevention

Write the intended control down and test the negative path. Do not infer a design flaw from traffic volume alone.
