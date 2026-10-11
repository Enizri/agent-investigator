---
document_id: knowledge-003
title: Software Supply Chain Failures
source_url: https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/
document_type: security_knowledge
taxonomy_version: OWASP Top 10:2025
license: CC BY-SA 4.0
---
## Summary

Software supply chain failures are A03:2025. This expands A06:2021, vulnerable and outdated components, to compromises in dependencies, build systems, and distribution. CWE-1104 covers unmaintained third-party components. The evidence is usually a dependency scan or an inventory, not an HTTP 500. A fictional advisory identifier such as CVE-2099-10042 can be indexed for exact lookup and must not be treated as a public CVE.

## Prevention

Track component versions, pin builds, and record which advisory the scanner matched. The scan row is the evidence. Semantic similarity to a different CVE does not confirm this one.
