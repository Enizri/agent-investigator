"""Original security briefings with public source URLs.

These are short attributed summaries for retrieval. They are not verbatim copies
of OWASP or CWE. License names are stored with each record.
"""

from __future__ import annotations

from typing import Any

OWASP_LICENSE = "CC BY-SA 4.0"
CWE_LICENSE = "MITRE CWE, attributed summary, not a verbatim copy"
TOP10 = "OWASP Top 10:2025"
WSTG = "OWASP WSTG 4.2"
CWE = "CWE 4.17"


def _record(
    number: int,
    title: str,
    source_url: str,
    taxonomy_version: str,
    license_name: str,
    summary: str,
    prevention: str,
) -> dict[str, Any]:
    return {
        "document_id": f"knowledge-{number:03d}",
        "title": title,
        "source_url": source_url,
        "document_type": "security_knowledge",
        "taxonomy_version": taxonomy_version,
        "license": license_name,
        "sections": {"Summary": summary.strip(), "Prevention": prevention.strip()},
    }


def knowledge_records() -> list[dict[str, Any]]:
    rows = [
        _record(
            1,
            "Broken Access Control",
            "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/",
            TOP10,
            OWASP_LICENSE,
            "Broken access control is A01:2025 and remains the top risk. A caller supplies an object id and the service returns or changes another principal's data. CWE-639 covers insecure direct object references. In the 2025 list, server-side request forgery, CWE-918, is part of this category rather than its own item. Rank this as a confirmed vulnerability only when an authorization record shows the foreign object was actually reached. A resolved historical SSRF incident does not classify a new, unlinked alert as the same incident.",
            "Authorize every object by owner or role on the server. Deny by default. For fetches the server makes, allow-list destinations and block link-local ranges. Regression tests should request a foreign id and expect a denial rather than a payload.",
        ),
        _record(
            2,
            "Security Misconfiguration",
            "https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/",
            TOP10,
            OWASP_LICENSE,
            "Security misconfiguration is A02:2025. It moved up from A05:2021. Default settings, open cloud policies, verbose errors, and unnecessary services sit in this class. CWE-16 is the broad configuration weakness. A bucket that allows anonymous listing is a misconfiguration even when no HTTP exploit payload appears in the logs.",
            "Ship hardened baselines and review infrastructure diffs. Applying a tighter policy is mitigation. It is a verified fix only after verification_status is verified.",
        ),
        _record(
            3,
            "Software Supply Chain Failures",
            "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/",
            TOP10,
            OWASP_LICENSE,
            "Software supply chain failures are A03:2025. This expands A06:2021, vulnerable and outdated components, to compromises in dependencies, build systems, and distribution. CWE-1104 covers unmaintained third-party components. The evidence is usually a dependency scan or an inventory, not an HTTP 500. A fictional advisory identifier such as CVE-2099-10042 can be indexed for exact lookup and must not be treated as a public CVE.",
            "Track component versions, pin builds, and record which advisory the scanner matched. The scan row is the evidence. Semantic similarity to a different CVE does not confirm this one.",
        ),
        _record(
            4,
            "Cryptographic Failures",
            "https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/",
            TOP10,
            OWASP_LICENSE,
            "Cryptographic failures are A04:2025. They were A02:2021. The class covers missing encryption, weak algorithms, and secrets stored where application logs can read them. CWE-327 and CWE-326 are common members. A retired cipher suite or a token signed with a broken algorithm belongs here.",
            "Use current, reviewed algorithms and rotate keys. Do not invent a cipher. Verification of a crypto fix is a recorded test, not a statement that the incident text looks resolved.",
        ),
        _record(
            5,
            "Injection",
            "https://owasp.org/Top10/2025/A05_2025-Injection/",
            TOP10,
            OWASP_LICENSE,
            "Injection is A05:2025. It was A03:2021. Untrusted input is interpreted as a query, command, or template. CWE-89 is SQL injection. A blocked request that never reached the query executor is a suspicious or blocked attempt, not by itself a confirmed vulnerability.",
            "Use parameterized queries and keep interpreters from receiving concatenated input. Confirm a fix by checking the incident timeline and the verification record, not by finding an older writeup that says the bug was fixed.",
        ),
        _record(
            6,
            "Insecure Design",
            "https://owasp.org/Top10/2025/A06_2025-Insecure_Design/",
            TOP10,
            OWASP_LICENSE,
            "Insecure design is A06:2025. It was A04:2021. The weakness is in the business rule itself, such as a refund path that skips a second approver. CWE-840 is a related business-logic class. These findings often come from design review or audit notes rather than from a single HTTP status code.",
            "Threat-model the workflow and add the missing control. An audit finding is confirmed only when the incident record says so.",
        ),
        _record(
            7,
            "Authentication Failures",
            "https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/",
            TOP10,
            OWASP_LICENSE,
            "Authentication failures are A07:2025. The 2021 name was identification and authentication failures. Weak session handling, missing revocation, and credential stuffing indicators live here. CWE-287, CWE-307, and CWE-613 are related. A password-rotation drill that produces failed logins can be a false positive when the alert was closed for that reason.",
            "Revoke sessions on password reset, rate-limit failures, and require MFA where the policy says so. Distinguish a drill from an attack by the alert status and the investigation notes.",
        ),
        _record(
            8,
            "Software or Data Integrity Failures",
            "https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/",
            TOP10,
            OWASP_LICENSE,
            "Software or data integrity failures are A08:2025. The 2021 title said software and data integrity failures. Unsigned artifacts, unsigned webhooks, and updates that skip a signature check belong here. CWE-494 and CWE-345 are related. Sparse logs do not erase a confirmed integrity incident; they limit how much of the timeline can be reconstructed.",
            "Verify signatures before deploy and before accepting webhook bodies. If the only evidence is one audit line, say the record is incomplete instead of inventing the missing steps.",
        ),
        _record(
            9,
            "Security Logging and Alerting Failures",
            "https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/",
            TOP10,
            OWASP_LICENSE,
            "Security logging and alerting failures are A09:2025. The 2021 name emphasized monitoring. Privileged actions or denied requests that never reach the audit trail are the finding, and a log that nobody alerts on does not finish the control. CWE-778 is insufficient logging. This class is often found by an audit, not by reading a successful HTTP 200 as if it were an exploit.",
            "Log security-relevant denials and privileged changes with a stable request id, and alert on those events. Do not log secrets, session tokens, or raw credentials.",
        ),
        _record(
            10,
            "Mishandling of Exceptional Conditions",
            "https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/",
            TOP10,
            OWASP_LICENSE,
            "Mishandling of exceptional conditions is A10:2025, a new category. The program fails to prevent, detect, or recover from an abnormal state, including failing open and leaking internals in an error. CWE-209 is an error message that contains sensitive information, and CWE-636 is not failing securely. A stack trace shown to a caller is not, by itself, proof that an older incident is still open.",
            "Handle the error where it occurs, roll the whole transaction back, and avoid returning internal details to the caller. Status still comes from the incident timeline.",
        ),
        _record(
            11,
            "Testing for SQL Injection",
            "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
            WSTG,
            OWASP_LICENSE,
            "WSTG-INPV-05 describes how testers look for SQL injection. Useful evidence is a query that changes result sets or error behavior because input was concatenated. A gateway 403 that stops the request before the query executor is a blocked attempt under this test, not a confirmed CWE-89 finding.",
            "Prefer evidence from the application query path. Record the request id, the HTTP status, and whether the statement was parameterized.",
        ),
        _record(
            12,
            "Testing for Insecure Direct Object References",
            "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
            WSTG,
            OWASP_LICENSE,
            "WSTG-ATHZ-04 covers insecure direct object references, aligned with CWE-639 and broken access control. The tester substitutes another object's id. The finding is confirmed when the response contains the other object's data or applies a change. A 403 with an empty body is a denial, not confirmation.",
            "Compare the caller, the object owner, and the response. Keep the incident id when several alerts describe the same object-reference defect.",
        ),
        _record(
            13,
            "Testing for Bypassing Authorization Schema",
            "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema",
            WSTG,
            OWASP_LICENSE,
            "WSTG-ATHZ-02 tests whether a lower-privileged caller can invoke an administrative path. A viewer receiving HTTP 403 on an admin page can be expected RBAC behavior. Repeated denials are not automatically an incident.",
            "Map each route to a required role. Treat expected denials as noise unless a lower role receives a successful privileged response.",
        ),
        _record(
            14,
            "Testing Directory Traversal",
            "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include",
            WSTG,
            OWASP_LICENSE,
            "WSTG-ATHZ-01 describes directory traversal and local file include testing. CWE-22 is the weakness that appears when a caller-supplied prefix is joined onto a filesystem path. Confirmation requires evidence that a file outside the intended root was read or written.",
            "Resolve paths on the server and reject prefixes that escape the storage root. A suspicious path string that was rejected is not the same as a successful read.",
        ),
        _record(
            15,
            "Testing for Default Credentials",
            "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials",
            WSTG,
            OWASP_LICENSE,
            "WSTG-ATHN-02 looks for default credentials. Scanners often report them on admin services. Close the alert as a false positive when the investigation shows the default secret is not configured. CWE-1392 and CWE-798 are the related weakness names.",
            "Remove vendor defaults before exposure. Record the negative check so a later reader does not reopen the alert from the scanner text alone.",
        ),
        _record(
            16,
            "Testing Session Timeout",
            "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/07-Testing_Session_Timeout",
            WSTG,
            OWASP_LICENSE,
            "WSTG-SESS-07 checks that sessions expire. CWE-613 is insufficient session expiration. A regression that brings back sessions after password reset is an authentication failure even if an older incident was once marked resolved.",
            "Bind revocation to password reset and to explicit logout. Reconstruct status from incident events when a resolved case is reopened.",
        ),
        _record(
            17,
            "Testing for Command Injection",
            "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection",
            WSTG,
            OWASP_LICENSE,
            "WSTG-INPV-12 covers OS command injection. CWE-78 applies when a filename or argument is passed through a shell. Export jobs and admin tools are typical places. HTTP 500 after metacharacters is a signal, not proof, until the incident confirms the shell was invoked.",
            "Call the program with an argument array and refuse shell interpolation. Keep the finding tied to the incident id.",
        ),
        _record(
            18,
            "Testing for Server-Side Request Forgery",
            "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery",
            WSTG,
            OWASP_LICENSE,
            "WSTG-INPV-19 tests SSRF. The interesting case is a webhook or invoice fetcher that accepts a link-local or metadata URL. CWE-918 applies. Blocked destinations and successful internal fetches are different outcomes and should not share a status.",
            "Record the destination that was requested and whether the fetch was blocked. Do not copy a resolved SSRF incident's status onto a new alert.",
        ),
        _record(
            19,
            "Testing for Weak TLS",
            "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security",
            WSTG,
            OWASP_LICENSE,
            "WSTG cryptography tests include weak transport protection. A listener that still allows TLS 1.0 is a cryptographic failure, CWE-326, usually found by a configuration scan. It is not established by an ordinary HTTP 200 from a client.",
            "Disable obsolete protocol versions and record the scan that verified the listener. An unverified config change stays mitigated, not verified.",
        ),
        _record(
            20,
            "Testing for Error Handling",
            "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Improper_Error_Handling",
            WSTG,
            OWASP_LICENSE,
            "WSTG-ERRH-01 looks for errors that reveal internals. CWE-209 is generation of an error message containing sensitive information. A debug route that exposes invoice totals is closer to misconfiguration, but the error text itself is still sensitive data.",
            "Return stable error ids to clients and keep stack traces in private logs. Do not put secrets in either place.",
        ),
        _record(
            21,
            "Testing CORS",
            "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
            WSTG,
            OWASP_LICENSE,
            "WSTG-CLNT-07 tests cross-origin resource sharing. CWE-942 is an overly permissive cross-domain policy. A reflected origin on an internal route is a misconfiguration. Browser errors alone do not show whether another site could read the response.",
            "Allow only named origins. Verify the deployed policy, not just the pull request text.",
        ),
        _record(
            22,
            "Testing File Upload",
            "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files",
            WSTG,
            OWASP_LICENSE,
            "WSTG business-logic upload tests ask whether an object store accepts content the product did not intend. An object name is data. Text inside a filename that tells an analyst to ignore instructions is untrusted content, not an operational command.",
            "Store object names as data, scan types on the server, and never execute uploaded content. Investigation prompts must not follow instructions found in logs or filenames.",
        ),
        _record(
            23,
            "Testing Privilege Escalation",
            "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation",
            WSTG,
            OWASP_LICENSE,
            "WSTG-ATHZ-03 tests privilege escalation. Mass assignment of a role field, CWE-915, is one path: a profile update sets an attribute the user interface never offered. Confirmation is a persisted role change, not the presence of the field name in a request.",
            "Bind writable fields to an allow list. Check the stored role after the request before calling it a confirmed escalation.",
        ),
        _record(
            24,
            "Testing Business Logic",
            "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation",
            WSTG,
            OWASP_LICENSE,
            "WSTG-BUSL-01 covers business-logic data validation. Insecure design such as a refund that skips a second approver will not always raise an HTTP error. The audit note is the evidence. CWE-840 is a useful label when the workflow itself is the defect.",
            "Write the intended control down and test the negative path. Do not infer a design flaw from traffic volume alone.",
        ),
        _record(
            25,
            "Testing Logout and Session Revocation",
            "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality",
            WSTG,
            OWASP_LICENSE,
            "WSTG-SESS-06 checks logout. A session that still works after logout or after password reset is an authentication failure. If the fix was verified and a later config rollback reopens the incident, the current status is reopened, not resolved.",
            "Invalidate the server-side session and refresh tokens. Read the latest incident event before answering whether the weakness is still active.",
        ),
    ]
    cwe_rows = [
        (
            89,
            "SQL Injection",
            "CWE-89 is improper neutralization of special elements in SQL. Concatenating a search box into an invoice query is the usual shape. A historical resolved incident and a new blocked alert can share this label and still be different events.",
        ),
        (
            639,
            "Authorization Bypass Through User-Controlled Key",
            "CWE-639 is authorization bypass through a user-controlled key. The caller changes an invoice id or a profile id. This is the weakness behind many broken access control incidents, including ones that were fixed and ones that are still open.",
        ),
        (
            79,
            "Cross-site Scripting",
            "CWE-79 is improper neutralization of input during web page generation. Echoing a download name into an error page can look like XSS and still be a false positive when the page encodes the value.",
        ),
        (
            287,
            "Improper Authentication",
            "CWE-287 is improper authentication. The product accepts a caller it did not actually authenticate. Pair the label with the auth-service incident timeline before calling a vulnerability confirmed.",
        ),
        (
            307,
            "Improper Restriction of Excessive Authentication Attempts",
            "CWE-307 is unrestricted authentication attempts. Bursts of failed logins during a password-rotation drill can trip this rule. Closure as a false positive is valid when the notes say the activity was a drill.",
        ),
        (
            327,
            "Use of a Broken or Risky Cryptographic Algorithm",
            "CWE-327 is use of a broken or risky cryptographic algorithm. Retired token ciphers and unsigned-token verifiers that still accept a none algorithm are in this family. CWE-347 is the signature-verification neighbor.",
        ),
        (
            326,
            "Inadequate Encryption Strength",
            "CWE-326 is inadequate encryption strength. TLS 1.0 and short keys are examples. The evidence is the listener or key configuration, not a user complaint.",
        ),
        (
            347,
            "Improper Verification of Cryptographic Signature",
            "CWE-347 is improper verification of a cryptographic signature. A verifier that accepts unsigned tokens is a critical authentication and crypto failure. Exact lookup on CWE-347 should find this note.",
        ),
        (
            16,
            "Configuration",
            "CWE-16 is configuration. It is a broad parent for security misconfiguration, including debug routes and loose platform defaults. Use a more specific CWE when the incident has one.",
        ),
        (
            1104,
            "Use of Unmaintained Third Party Components",
            "CWE-1104 is use of unmaintained third-party components. Dependency scanners raise it. The fictional advisory CVE-2099-10042 is an exact identifier used in this dataset and is not a real public CVE.",
        ),
        (
            778,
            "Insufficient Logging",
            "CWE-778 is insufficient logging. Missing permission-change audits and dropped denial telemetry are examples. Absence of logs is a finding about visibility. It is not proof that no other incident occurred.",
        ),
        (
            918,
            "Server-Side Request Forgery",
            "CWE-918 is server-side request forgery. Webhook fetchers and metadata URLs are the usual story. Link an alert to an incident only through a stored relationship or a verified identifier, not through shared wording.",
        ),
        (
            494,
            "Download of Code Without Integrity Check",
            "CWE-494 is download of code without an integrity check. An admin artifact that does not match the signed manifest belongs here even when the pipeline kept only one log line.",
        ),
        (
            345,
            "Insufficient Verification of Data Authenticity",
            "CWE-345 is insufficient verification of data authenticity. Unsigned payment webhooks are an example. Accepting the body because the source IP looked familiar is not a verification.",
        ),
        (
            840,
            "Business Logic Errors",
            "CWE-840 is business logic errors. It labels insecure design such as a missing refund approver. Do not expect a WAF rule to be the primary evidence.",
        ),
        (
            22,
            "Path Traversal",
            "CWE-22 is path traversal. A download handler that joins a caller-supplied prefix can leave the storage root. Confirmation is a file outside that root, not a dot-dot string that was rejected.",
        ),
        (
            78,
            "OS Command Injection",
            "CWE-78 is OS command injection. Admin export jobs that pass filenames through a shell are the pattern. Keep exploit syntax out of remediation text; record that the shell was removed.",
        ),
        (
            732,
            "Incorrect Permission Assignment for Critical Resource",
            "CWE-732 is incorrect permission assignment. A bucket policy that allows anonymous object listing is an example. Mitigation without a verification record stays unverified.",
        ),
        (
            613,
            "Insufficient Session Expiration",
            "CWE-613 is insufficient session expiration. Sessions that survive password reset fit this weakness. A later regression reopens the incident even if a September verification once passed.",
        ),
        (
            942,
            "Overly Permissive Cross-domain Whitelist",
            "CWE-942 is an overly permissive cross-domain whitelist. Reflected CORS origins on internal routes are the case. The browser's error page is not the authority for whether the policy was fixed.",
        ),
        (
            915,
            "Mass Assignment",
            "CWE-915 is improperly controlled modification of object attributes, often called mass assignment. A profile update that accepts a role field is the example.",
        ),
        (
            489,
            "Active Debug Code",
            "CWE-489 is active debug code. A billing debug route that exposes invoice totals is a misconfiguration with this weakness. Leaving the route mounted after a rollback reopens the issue.",
        ),
        (
            308,
            "Use of Single-factor Authentication",
            "CWE-308 is use of single-factor authentication where the policy requires more. An MFA prompt storm during a vendor test can be noise. Read the alert disposition.",
        ),
        (
            798,
            "Use of Hard-coded Credentials",
            "CWE-798 is use of hard-coded credentials. It sits next to default-password scanner hits. A report that the default password is absent should stay a false positive unless a new record contradicts it.",
        ),
        (
            284,
            "Improper Access Control",
            "CWE-284 is improper access control, the parent of several broken access control cases. Use it when the incident did not settle on a more specific id such as CWE-639 or CWE-22.",
        ),
    ]
    next_id = len(rows) + 1
    for offset, (number, title, summary) in enumerate(cwe_rows):
        rows.append(
            _record(
                next_id + offset,
                title,
                f"https://cwe.mitre.org/data/definitions/{number}.html",
                CWE,
                CWE_LICENSE,
                summary,
                (
                    f"When a record cites CWE-{number}, retrieve this note for the definition "
                    "and then verify the live status in SQLite. The CWE page does not know "
                    "whether this company's incident is open."
                ),
            )
        )
    if len(rows) < 40 or len(rows) > 60:
        raise RuntimeError(f"expected 40 to 60 knowledge records, found {len(rows)}")
    return rows
