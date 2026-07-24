# Operation Bastion — Detection & Response Coverage Matrix

**Owner:** Saif Alblooshi  
**Purpose:** Show which known attack techniques from Sentinel, Crossfire, and Ironclad are detected, partially detected, or still a gap.

## Coverage Definitions

| Status | Meaning |
|---|---|
| Detected | The attack creates visible evidence in available logs or telemetry and has a linked detection rule. |
| Partial | The attack can be partly identified, but logs are incomplete, noisy, or missing important fields. |
| Gap | The attack cannot be reliably detected with current logs and requires new telemetry or controls. |

## Coverage Matrix

| Attack Technique | MITRE ATT&CK ID | Source Sprint(s) | Detection Rule | Response Runbook | Coverage | Reason | Hardening Fix |
|---|---|---|---|---|---|---|---|
| Reconnaissance / Route Probing | T1595 / T1595.003 | Sentinel, Crossfire | RECON-001 | IR-RECON-001 | Partial | Unusual routes and 403/404/500 errors are visible, but basic Docker logs lack full request context. | Rate limit probing, remove unused routes, reduce verbose errors. |
| Directory Listing / Restricted File Probing | T1595.003 | Sentinel | FILE-001 | IR-FILE-001 | Detected | `/ftp` and restricted file-style requests create visible URL and status-code evidence. | Disable directory listing and remove internal files from public folders. |
| Authentication Abuse / Failed Login Attempts | T1110 / T1110.001 | Sentinel | AUTH-001 | IR-AUTH-001 | Detected | Repeated `POST /rest/user/login` failures create a clear 401 pattern. | Rate limiting, account lockout, MFA for privileged users, breached-password checks. |
| SQL Injection Login Bypass | T1190 | Sentinel, Crossfire, Ironclad | SQLI-001 | IR-SQLI-001 | Detected | SQL-like payloads in login request body and successful response create strong indicators. | Parameterized queries, server-side validation, generic error handling. |
| UNION SQL Injection Exfiltration | T1190 / T1020 | Crossfire, Ironclad | SQLI-002 | IR-SQLI-002 | Detected | `UNION SELECT` patterns in search/query parameters can be detected, especially after URL decoding. | Prepared statements, typed input validation, response review. |
| Cross-Site Scripting Payload | T1190 | Sentinel | XSS-001 | IR-XSS-001 | Partial | Script payloads are visible in browser evidence, but SPA routes may not always appear clearly in backend logs. | Context-aware output encoding, sanitization, CSP, XSS regression tests. |
| Broken Access Control / IDOR | T1190 | Sentinel, Ironclad | IDOR-001 | IR-IDOR-001 | Gap / Partial | Requires application-level authorization logs showing user, resource, owner, role, and decision. | Object-level authorization, owner checks, authorization decision logging. |
| BOLA / Basket IDOR | T1190 | Ironclad | IDOR-001 | IR-IDOR-001 | Partial | Can only be reliably detected if the app logs resource ownership mismatch. | Server-side ownership checks using authenticated identity, not client-provided IDs. |
| JWT `alg:none` Bypass | T1550.004 | Ironclad | JWT-001 | IR-JWT-001 | Partial | JWT header manipulation can be detected only when token validation failures or parsed JWT header fields are logged. Without those application-level authentication logs, this attack may not be visible enough. | Reject `alg:none`, enforce approved algorithms, audit signing key strength. |
| User-Agent Spoofing / WAF Evasion | T1036 / T1027 | Crossfire | EVASION-001 | IR-EVASION-001 | Partial | Spoofed user-agent values are visible, but they can cause false positives without correlation to exploit payloads. | Decode payloads before inspection, do not trust user-agent values, tune WAF/SIEM rules. |
| URL-Encoding SQLi Evasion | T1027 / T1190 | Crossfire | EVASION-001 + SQLI-002 | IR-EVASION-001 + IR-SQLI-002 | Partial / Detected after decoding | Encoded payloads can bypass weak detections if raw strings are not decoded first. | Normalize and decode before detection, inspect raw and decoded request values. |

## Strongest Coverage Areas

The strongest coverage is for pattern-based attacks. SQL injection, UNION SQL injection, authentication abuse, route probing, and file probing all create visible indicators in URLs, request bodies, status codes, or authentication events. These attacks can be detected with a combination of web request logs, authentication logs, application logs, and decoded request inspection.

## Weakest Coverage Area

The weakest coverage area remains broken access control and IDOR. These attacks can look like normal requests unless the application logs ownership and authorization decisions. For Sohail, this is the most important gap because student submissions, evaluations, profiles, certificates, files, and payment-related records must not be accessible across users.

## Highest-Priority Gap

The highest-priority gap is missing application-level authorization logging. Sohail should log:

- user ID
- role
- requested resource ID
- resource owner ID
- endpoint
- authorization result
- denial reason
- timestamp
- source IP

Without these fields, the defensive platform cannot reliably prove who accessed what or whether student data was exposed.

## Coverage Summary

| Coverage Status | Count | Main Examples |
|---|---:|---|
| Detected | 4 | SQLi login bypass, UNION SQLi, authentication abuse, directory probing |
| Partial | 6 | Recon, XSS, BOLA/IDOR, JWT `alg:none`, user-agent spoofing, encoded payload evasion |
| Gap | 1 | Full IDOR / broken access-control visibility without app authorization logs |

## Platform Readiness Conclusion

The Bastion defense platform is reusable and portfolio-ready, but it should be considered a pre-production defensive package. It demonstrates detection logic, response actions, and business-risk reasoning, but production deployment would require field mapping, centralized logging, SIEM tuning, false-positive testing, and real application authorization logs.
