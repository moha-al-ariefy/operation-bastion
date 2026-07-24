# Operation Bastion — Incident Response Runbook

**Owner:** Saif Alblooshi  
**Linked Library:** `detection-rule-library.md`  
**Methodology:** Prepare → Detect → Contain → Eradicate → Recover → Lessons Learned  
**Scope:** OWASP Juice Shop local lab mapped to Sohail platform risk

## Runbook Index

| Runbook ID | Linked Rule | Incident Type | Severity |
|---|---|---|---|
| IR-RECON-001 | RECON-001 | Reconnaissance and route probing | Medium |
| IR-FILE-001 | FILE-001 | Directory listing or restricted file probing | Medium-High |
| IR-AUTH-001 | AUTH-001 | Authentication abuse | High |
| IR-SQLI-001 | SQLI-001 | SQL injection login bypass | Critical |
| IR-SQLI-002 | SQLI-002 | UNION SQL injection exfiltration attempt | Critical |
| IR-XSS-001 | XSS-001 | Cross-site scripting payload | Medium-High |
| IR-IDOR-001 | IDOR-001 | Broken access control / IDOR | Critical |
| IR-JWT-001 | JWT-001 | JWT manipulation / authentication bypass | Critical |
| IR-EVASION-001 | EVASION-001 | Encoded payload or user-agent evasion | Medium-High |

---

## IR-RECON-001 — Reconnaissance and Route Probing

**Linked Detection Rule:** RECON-001  
**Severity:** Medium

**Triage**
- Confirm source IP, timestamp, requested paths, status codes, user-agent, and request rate.
- Check whether the same source later attempted SQL injection, XSS, authentication abuse, or file probing.
- Review whether exposed routes returned stack traces, directory listings, or application errors.

**Containment**
- Rate-limit the source if probing continues.
- Block the source if the traffic is clearly malicious and repeated.
- Restrict exposed admin, API, REST, or FTP-style routes.

**Eradication**
- Disable unused routes.
- Remove public directory listings.
- Replace verbose error pages with generic errors.
- Review web routing and public endpoint exposure.

**Recovery**
- Re-test the probed routes to confirm they no longer expose unnecessary information.
- Continue monitoring for follow-up exploitation attempts.
- Tune thresholds to reduce false positives.

**Business Impact**
- Reconnaissance gives attackers a map of the platform. For Sohail, this could help attackers discover admin dashboards, student file areas, or API endpoints before exploitation.

---

## IR-FILE-001 — Directory Listing or Restricted File Probing

**Linked Detection Rule:** FILE-001  
**Severity:** Medium-High

**Triage**
- Identify the requested files or folders.
- Confirm whether access was allowed or blocked.
- Review whether files contained student data, internal documents, credentials, configuration references, or client material.

**Containment**
- Disable public directory listing immediately.
- Restrict affected folders to authenticated and authorized users.
- Remove backup/configuration files from public web paths.

**Eradication**
- Move internal files to private storage.
- Add server rules blocking backup, key, database, and configuration file extensions.
- Remove sensitive files from the repository or deployment artifact.

**Recovery**
- Rotate any exposed secrets if sensitive files were downloaded.
- Restore correct folder permissions.
- Verify that only approved public files are reachable.

**Business Impact**
- File exposure could leak internship tasks, student submissions, internal documents, or client materials. This would damage trust with students and universities.

---

## IR-AUTH-001 — Authentication Abuse

**Linked Detection Rule:** AUTH-001  
**Severity:** High

**Triage**
- Identify source IP, target account/email, failed attempt count, and time window.
- Check whether any login eventually succeeded.
- Review password reset activity, MFA activity, and new-device login alerts.

**Containment**
- Rate-limit the source.
- Temporarily block the source if abuse continues.
- Lock the targeted account if the volume is high or account takeover is suspected.

**Eradication**
- Enforce rate limits and account lockout thresholds.
- Require MFA for admin, mentor, and operations accounts.
- Add breached-password checks and stronger password policy.

**Recovery**
- Reset credentials if compromise is suspected.
- Revoke active sessions for affected accounts.
- Notify affected users or administrators if needed.

**Business Impact**
- Account takeover could allow attackers to access student dashboards, mentor tools, evaluations, or admin features. Privileged account compromise is especially high risk before launch.

---

## IR-SQLI-001 — SQL Injection Login Bypass

**Linked Detection Rule:** SQLI-001  
**Severity:** Critical

**Triage**
- Confirm endpoint, payload, source IP, timestamp, status code, and response body.
- Check whether the request created a privileged session or returned an authentication token.
- Review post-login activity from the same source.
- Check whether student records, evaluations, files, or payment-related data were accessed.

**Containment**
- Revoke attacker sessions and tokens.
- Temporarily restrict the affected login endpoint if exploitation is confirmed.
- Force privileged users to re-authenticate.

**Eradication**
- Replace unsafe query construction with parameterized queries or safe ORM methods.
- Add server-side validation.
- Remove verbose database errors and stack traces.
- Review other authentication and search endpoints for the same weakness.

**Recovery**
- Test the patched login endpoint with negative security tests.
- Review database integrity and restore modified records if needed.
- Monitor for repeat injection attempts.

**Business Impact**
- For Sohail, a login bypass could allow unauthorized admin or mentor access, exposing student records, submissions, evaluation data, and future payment-related records.

---

## IR-SQLI-002 — UNION SQL Injection Exfiltration Attempt

**Linked Detection Rule:** SQLI-002  
**Severity:** Critical

**Triage**
- Confirm the query parameter, raw URL, decoded URL, source IP, and response size.
- Check whether the payload targeted tables such as users, passwords, tokens, student records, or evaluations.
- Review whether response content included unexpected database data.

**Containment**
- Temporarily restrict or disable the affected search endpoint.
- Block or rate-limit the source.
- Preserve logs and response evidence for investigation.

**Eradication**
- Replace dynamic search queries with prepared statements.
- Enforce strict typed input validation for search parameters.
- Ensure errors do not reveal database schema or query structure.

**Recovery**
- Verify that the payload is treated as a literal search string, not executable SQL.
- Review database access logs and restore exposed/modified data if needed.
- Re-test with safe encoded payloads to confirm filtering and query safety.

**Business Impact**
- UNION SQL injection could expose a complete user database, including student PII, mentor accounts, and password hashes. This is one of the most serious business risks for Sohail.

---

## IR-XSS-001 — Cross-Site Scripting Payload

**Linked Detection Rule:** XSS-001  
**Severity:** Medium-High

**Triage**
- Identify where the payload was submitted.
- Determine whether the payload was reflected or stored.
- Check whether any student, mentor, or admin viewed the affected page.
- Review session cookies, tokens, and account activity if session theft is suspected.

**Containment**
- Remove or neutralize the malicious input.
- Temporarily disable the affected input field if the payload is stored.
- Invalidate sessions if token theft is suspected.

**Eradication**
- Apply context-aware output encoding.
- Sanitize rich text only where rich text is required.
- Add Content Security Policy where possible.
- Add automated XSS regression tests.

**Recovery**
- Re-enable the affected feature after testing.
- Confirm the payload renders as text, not executable code.
- Monitor for repeat attempts.

**Business Impact**
- XSS in Sohail dashboards, comments, evaluations, or feedback could affect trusted users and may lead to session theft, unauthorized actions, or content manipulation.

---

## IR-IDOR-001 — Broken Access Control / IDOR

**Linked Detection Rule:** IDOR-001  
**Severity:** Critical

**Triage**
- Identify user ID, role, requested resource ID, resource owner ID, endpoint, and authorization result.
- Determine whether access was blocked or allowed.
- Review whether submissions, evaluations, profiles, certificates, files, or payment records were accessed.

**Containment**
- Disable the affected endpoint or account if unauthorized access is confirmed.
- Restrict access to the affected resource type.
- Rotate exposed file links if file access is involved.

**Eradication**
- Enforce backend object-level authorization on every request.
- Add role, ownership, and assignment checks.
- Remove reliance on frontend button hiding or hidden routes.
- Add tests for horizontal and vertical access control.

**Recovery**
- Review affected records.
- Notify leadership if student data was exposed.
- Re-enable endpoint only after authorization tests pass.
- Keep additional monitoring in place for owner mismatch events.

**Business Impact**
- IDOR is one of the most important risks for Sohail because one student must never access another student's submission, evaluation, profile, or certificate record.

---

## IR-JWT-001 — JWT Manipulation / Authentication Bypass

**Linked Detection Rule:** JWT-001  
**Severity:** Critical

**Triage**
- Inspect JWT header, algorithm, claims, token issuer, subject, and validation result.
- Check whether the token was accepted or rejected.
- Review whether the account or role claim was altered.
- Identify any actions performed after the token was presented.

**Containment**
- Reject malformed or unsigned tokens.
- Revoke suspicious sessions.
- Temporarily rotate tokens if token misuse is confirmed.

**Eradication**
- Enforce a strict allowlist of approved algorithms.
- Reject `alg:none` and unexpected algorithms.
- Verify token signatures server-side.
- Audit signing key strength and storage.

**Recovery**
- Rotate keys if compromise is suspected.
- Reissue valid tokens.
- Re-test token validation with manipulated headers and claims.

**Business Impact**
- JWT manipulation could allow attackers to impersonate students, mentors, or admins. This could compromise account integrity and trust in platform authorization.

---

## IR-EVASION-001 — Encoded Payload or User-Agent Evasion

**Linked Detection Rule:** EVASION-001  
**Severity:** Medium-High

**Triage**
- Decode the URL and request body before analysis.
- Review user-agent value and determine whether it matches normal behavior.
- Check whether the evasion attempt was paired with SQL injection, XSS, scanning, or data access.

**Containment**
- Rate-limit or block the source if evasion is part of exploitation.
- Temporarily add inspection for decoded payloads.
- Preserve original raw and decoded requests.

**Eradication**
- Normalize and decode inputs before detection inspection.
- Avoid trusting user-agent values.
- Tune WAF or SIEM rules to inspect encoded payloads.

**Recovery**
- Re-test encoded payloads.
- Update detection rules and documentation.
- Review missed alerts to improve coverage.

**Business Impact**
- Evasion attempts show that attackers may adapt after detections are deployed. Sohail should expect detections to need tuning and validation, not one-time setup.

---

## Final Runbook Notes

The runbooks are designed to be practical for a pre-launch platform. The most urgent improvement remains structured logging, especially authentication events, request bodies where safe, file access, admin actions, and authorization decisions. Without these logs, even a good playbook cannot reliably determine what happened during a real incident.
