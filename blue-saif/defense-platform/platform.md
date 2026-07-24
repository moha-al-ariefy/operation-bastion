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
