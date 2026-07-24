# Detection & Response Platform
**Lead Engineer:** Saif Alblooshi

## 1. Coverage Matrix
| Threat Playbook ID | Detection Status | Telemetry Source | Residual Risk |
| :--- | :--- | :--- | :--- |
| RED-01 (SQLi Auth) | **Detected** | Web Server Access Logs | Low (ORM Implemented) |
| RED-02 (BOLA Basket) | **Detected** | Application Logs | Low (Strict Auth Checks) |
| RED-03 (JWT Forgery) | **Detected** | Application Logs | Low (Algorithm Hardcoded) |
| RED-04 (UNION SQLi) | **Detected** | Web/WAF Logs | Low (Prepared Statements) |
| RED-05 (DOM XSS) | **Gap** | N/A (Client-Side) | High (Requires UI Encoding) |

---

## 2. Sigma Rule Library

### SIGMA-01: SQL Injection Probing (Auth)
```yaml
title: Detect SQLi in Authentication Portal
logsource:
    category: webserver
detection:
    selection:
        http.method: POST
        http.uri: '/rest/user/login'
        http.request.body|re: '(--|#|/\*|'' OR|" OR)'
    condition: selection
level: high

```

### SIGMA-03: JWT `alg:none` Manipulation

```yaml
title: Detect Insecure JWT Algorithm Fallback
logsource:
    category: application
detection:
    selection:
        jwt.header.alg: 'none'
    condition: selection
level: critical

```

---

## 3. Incident Response (IR) Runbook

**IR-01: Response to Validated SQLi or BOLA Probing**

1. **Triage:** Verify if the endpoint returned a `200 OK` (success) or `4xx/5xx` (failure/blocked).
2. **Containment:** If a `200 OK` is observed alongside a SQLi payload on `/rest/user/login`, immediately revoke all active JWTs for the targeted account to sever the attacker's session.
3. **Eradication:** Block the offending IP at the WAF level.
4. **Recovery:** Force a password reset for the compromised account.
5. **Post-Incident:** Verify that the ORM and parameterized query patches are intact and have not been regressed in the latest CI/CD pipeline deployment.

```

