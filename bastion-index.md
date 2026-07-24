# Operation Bastion: Master Index

**Target:** OWASP Juice Shop (Local Docker - `127.0.0.1:3000`)
**Red Operator:** Mohammed Al Ariefy (Offensive Playbook)
**Blue Lead:** Saif Alblooshi (Defense & Response Platform)

This index cross-references the Red Team's reproducible attack templates with the Blue Team's detection rules and remediation runbooks.

| Playbook ID | Attack Technique | MITRE ATT&CK | Blue Detection Rule | Coverage Status | Hardening Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **RED-01** | SQLi Authentication Bypass | T1190 | **SIGMA-01** (Auth Probing) | Detected | Hardened (ORM) |
| **RED-02** | BOLA/IDOR Basket Access | T1210 | **SIGMA-02** (BOLA Mismatch) | Detected | Hardened (JWT Claims) |
| **RED-03** | JWT `alg:none` Forgery | T1550.004 | **SIGMA-03** (JWT Alg None) | Detected | Hardened (Strict RS256) |
| **RED-04** | UNION SQLi Exfiltration | T1020 | **SIGMA-04** (UNION SQLi) | Detected | Hardened (Prepared Statements) |
| **RED-05** | DOM-Based XSS | T1189 | **N/A** (Client-Side) | **Gap** | Unmitigated |
