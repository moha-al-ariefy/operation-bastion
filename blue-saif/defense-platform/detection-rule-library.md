# Operation Bastion — Detection Rule Library

**Owner:** Saif Alblooshi  
**Format:** Sigma-style / pseudo-SIEM  
**Source Sprints:** Operation Sentinel, Operation Crossfire, Operation Ironclad  
**Scope:** OWASP Juice Shop local Docker lab and Sohail-style EdTech platform mapping

## Rule Library Index

| Rule ID | Rule Name | Attack Class | MITRE ATT&CK ID | Severity | Coverage |
|---|---|---|---|---|---|
| RECON-001 | Reconnaissance and Unexpected Route Access | Route probing / scanning | T1595 / T1595.003 | Medium | Detected / Partial |
| FILE-001 | Directory Listing or Restricted File Probing | File exposure / directory listing | T1595.003 | Medium-High | Detected |
| AUTH-001 | Repeated Failed Login Attempts | Authentication abuse / brute force | T1110 / T1110.001 | High | Detected |
| SQLI-001 | SQL Injection Login Bypass | SQL injection / authentication bypass | T1190 | Critical | Detected |
| SQLI-002 | UNION SQL Injection Exfiltration Attempt | SQL injection / data exfiltration | T1190 / T1020 | Critical | Detected |
| XSS-001 | Cross-Site Scripting Payload Submitted | XSS / script injection | T1190 | Medium-High | Detected / Partial |
| IDOR-001 | Possible IDOR or Broken Access Control Attempt | Broken access control / BOLA | T1190 | Critical | Partial / Requires app logs |
| JWT-001 | JWT `alg:none` Manipulation Attempt | Token forgery / authentication bypass | T1550.004 | Critical | Detected if JWT fields are logged |
| EVASION-001 | Encoded Payload or User-Agent Evasion Attempt | Evasion / WAF bypass attempt | T1027 / T1036 | Medium-High | Partial |

---

## RECON-001 — Reconnaissance and Unexpected Route Access

```yaml
title: Reconnaissance and Unexpected Route Access
id: RECON-001
description: Detects probing of uncommon, hidden, or backend-style routes such as admin, API, REST, and FTP paths.
logsource:
  category: web
detection:
  selection_paths:
    url|contains:
      - "/admin"
      - "/api"
      - "/rest"
      - "/ftp"
      - "/backup"
      - "/config"
  selection_errors:
    status_code:
      - 403
      - 404
      - 500
  timeframe: 2m
  condition: selection_paths and count(source_ip) >= 4
fields:
  - timestamp
  - source_ip
  - method
  - url
  - status_code
  - user_agent
level: medium
tags:
  - attack.T1595
  - attack.T1595.003
```

**Notes:** This rule is useful as an early-warning signal. Reconnaissance alone may not be damaging, but it often appears before SQL injection, login abuse, or file probing.

---

## FILE-001 — Directory Listing or Restricted File Probing

```yaml
title: Directory Listing or Restricted File Probing
id: FILE-001
description: Detects public directory browsing and probing for backup, configuration, or restricted file types.
logsource:
  category: web
detection:
  selection:
    url|contains:
      - "/ftp"
      - ".bak"
      - ".yml"
      - ".yaml"
      - ".kdbx"
      - "package.json"
      - "suspicious_errors"
      - ".env"
      - ".sql"
  condition: selection
fields:
  - timestamp
  - source_ip
  - method
  - url
  - status_code
level: medium-high
tags:
  - attack.T1595.003
```

**Notes:** In Sohail, public folder exposure could reveal internship documents, task files, client material, or configuration references.

---

## AUTH-001 — Repeated Failed Login Attempts

```yaml
title: Repeated Failed Login Attempts
id: AUTH-001
description: Detects possible password guessing or authentication abuse against the login endpoint.
logsource:
  category: authentication
detection:
  selection:
    url|contains: "/rest/user/login"
    method: "POST"
    status_code: 401
  timeframe: 5m
  condition: count(source_ip) >= 5 or count(username) >= 5
fields:
  - timestamp
  - source_ip
  - username
  - method
  - url
  - status_code
  - user_agent
level: high
tags:
  - attack.T1110
  - attack.T1110.001
```

**Notes:** This rule requires authentication logs that include attempted username or email, source IP, status code, and timestamp.

---

## SQLI-001 — SQL Injection Login Bypass

```yaml
title: SQL Injection Login Bypass Attempt
id: SQLI-001
description: Detects SQL injection patterns submitted to authentication fields, especially login bypass attempts.
logsource:
  category: web
detection:
  selection_endpoint:
    method: "POST"
    url|contains: "/rest/user/login"
  selection_payload:
    request_body|contains:
      - "' OR"
      - "\" OR"
      - "1=1"
      - "--"
      - "#"
      - "/*"
  condition: selection_endpoint and selection_payload
fields:
  - timestamp
  - source_ip
  - method
  - url
  - request_body
  - status_code
  - user_agent
level: critical
tags:
  - attack.T1190
```

**Notes:** This rule should be treated as Critical when followed by HTTP 200, token issuance, or a privileged session.

---

## SQLI-002 — UNION SQL Injection Exfiltration Attempt

```yaml
title: UNION SQL Injection Data Exfiltration Attempt
id: SQLI-002
description: Detects UNION SELECT patterns in search or query parameters that may indicate database extraction attempts.
logsource:
  category: web
detection:
  selection_endpoint:
    url|contains:
      - "/rest/products/search"
      - "/search"
      - "q="
  selection_payload:
    url|re: "(?i)(UNION(\\s+|%20|\\+)+SELECT|SELECT(\\s+|%20|\\+)+.*FROM)"
  condition: selection_endpoint and selection_payload
fields:
  - timestamp
  - source_ip
  - method
  - url
  - query_string
  - status_code
level: critical
tags:
  - attack.T1190
  - attack.T1020
```

**Notes:** This rule should inspect both decoded and raw URL-encoded payloads. Crossfire showed that encoded payloads can bypass weak string-matching defenses.

---

## XSS-001 — Cross-Site Scripting Payload Submitted

```yaml
title: Cross-Site Scripting Payload Submitted
id: XSS-001
description: Detects script-like input in search, review, profile, comment, or evaluation fields.
logsource:
  category: web
detection:
  selection:
    request_body|contains:
      - "<script"
      - "onerror="
      - "javascript:"
      - "alert("
      - "%3Cscript"
      - "%3Cimg"
      - "onload="
  condition: selection
fields:
  - timestamp
  - source_ip
  - user_id
  - url
  - request_body
  - status_code
level: medium-high
tags:
  - attack.T1190
```

**Notes:** XSS detection may be partial for single-page applications because some payloads appear in client-side routes rather than clean backend requests. Output encoding tests are still required.

---

## IDOR-001 — Possible IDOR or Broken Access Control Attempt

```yaml
title: Possible IDOR or Broken Access Control Attempt
id: IDOR-001
description: Detects a user requesting a resource they do not own or are not assigned to access.
logsource:
  category: application
detection:
  selection:
    authorization_result: "denied"
    reason|contains:
      - "owner_mismatch"
      - "unauthorized_resource"
      - "invalid_resource_scope"
      - "role_scope_violation"
  condition: selection
fields:
  - timestamp
  - source_ip
  - user_id
  - role
  - endpoint
  - requested_resource_id
  - resource_owner_id
  - authorization_result
  - reason
level: critical
tags:
  - attack.T1190
```

**Notes:** This is the most important visibility gap. The rule cannot work with only basic web or Docker logs. Sohail must log authorization decisions, owner mismatches, and denied object-level access.

---

## JWT-001 — JWT `alg:none` Manipulation Attempt

```yaml
title: JWT alg none Manipulation Attempt
id: JWT-001
description: Detects tokens that attempt to disable signature verification by setting JWT header algorithm to none.
logsource:
  category: application
detection:
  selection:
    jwt.header.alg: "none"
  condition: selection
fields:
  - timestamp
  - source_ip
  - user_id
  - endpoint
  - jwt.header.alg
  - authorization_result
level: critical
tags:
  - attack.T1550.004
```

**Notes:** Detection is useful, but hardening must enforce approved signing algorithms and strong key management. Algorithm enforcement alone does not prove the signing key is safe.

---

## EVASION-001 — Encoded Payload or User-Agent Evasion Attempt

```yaml
title: Encoded Payload or User-Agent Evasion Attempt
id: EVASION-001
description: Detects suspicious encoded SQLi-style payloads or user-agent spoofing used to bypass weak filtering.
logsource:
  category: web
detection:
  encoded_payload:
    url|contains:
      - "%27"
      - "%2D%2D"
      - "%55%4E%49%4F%4E"
      - "%53%45%4C%45%43%54"
      - "%20OR%20"
  suspicious_user_agent:
    user_agent|contains:
      - "Googlebot"
      - "bingbot"
      - "crawler"
  condition: encoded_payload or suspicious_user_agent
fields:
  - timestamp
  - source_ip
  - url
  - decoded_url
  - user_agent
  - status_code
level: medium-high
tags:
  - attack.T1027
  - attack.T1036
```

**Notes:** User-agent spoofing should not automatically be blocked without tuning, but it should be investigated when paired with exploit payloads or unusual request patterns.

---

## Library Limitation Notes

1. These rules are intentionally written as Sigma-style / pseudo-SIEM content and require field mapping before deployment.
2. IDOR detection requires application-level authorization logs.
3. XSS detection should be paired with output encoding tests, not only payload matching.
4. SQL injection detection should inspect decoded payloads, request bodies, and query strings.
5. Production alerting should include false-positive tuning and severity escalation rules.
