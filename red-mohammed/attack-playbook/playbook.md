# Red Team Attack Playbook
**Engineer:** Mohammed Al Ariefy

## RED-01: SQLi Authentication Bypass
* **Objective:** Bypass the login portal to hijack the administrator account without a password.
* **MITRE ATT&CK ID:** T1190 (Exploit Public-Facing Application)
* **Prerequisites:** Accessible authentication endpoint (`/rest/user/login`).
* **Steps:**
  1. Navigate to the login portal.
  2. Intercept the authentication `POST` request.
  3. Inject the payload into the `email` JSON parameter.
  4. Submit a dummy password.
* **Payload:** `admin@juice-sh.op'--`
* **Expected Indicators:** HTTP `200 OK` response containing a valid session JWT for the admin user.
* **Cleanup:** Log out immediately to terminate the hijacked session and clear local JWTs.

## RED-02: BOLA/IDOR on Shopping Baskets
* **Objective:** Access another user's proprietary shopping basket data.
* **MITRE ATT&CK ID:** T1210 (Exploitation of Remote Services)
* **Prerequisites:** A valid authenticated session (Standard User).
* **Steps:**
  1. Authenticate and navigate to the shopping basket.
  2. Intercept the `GET /rest/basket/[id]` request.
  3. Modify the predictable sequential `[id]` parameter to a target user's ID.
* **Payload:** Change `/rest/basket/1` to `/rest/basket/2`
* **Expected Indicators:** HTTP `200 OK` exposing JSON data of items not belonging to the attacker.
* **Cleanup:** Revert the request ID to the assigned user ID.

## RED-03: JWT Signature Stripping (`alg:none`)
* **Objective:** Elevate privileges to Administrator by forging a stateless session token.
* **MITRE ATT&CK ID:** T1550.004 (Use Alternate Authentication Material: Web Session Cookie)
* **Prerequisites:** A valid JWT from a standard user account.
* **Steps:**
  1. Decode the JWT payload.
  2. Modify the `sub` or `email` claim to match the administrator.
  3. Modify the header to set `"alg": "none"`.
  4. Re-encode the token and strip the trailing cryptographic signature, leaving the final dot `.`.
* **Payload:** `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbmlzdHJhdG9yIn0.`
* **Expected Indicators:** Access granted to `/admin` endpoints.
* **Cleanup:** Delete the forged token from the browser's `localStorage` or cookies.

## RED-04: UNION SQLi Data Exfiltration
* **Objective:** Dump the backend `Users` database table directly to the frontend UI.
* **MITRE ATT&CK ID:** T1020 (Automated Exfiltration) / T1190
* **Prerequisites:** An unparameterized search or filter API endpoint.
* **Steps:**
  1. Identify a vulnerable GET parameter (e.g., `?q=`).
  2. Inject a UNION SELECT query matching the exact column count of the original table.
  3. URL-encode the payload if necessary.
* **Payload:** `')) UNION SELECT id, email, password, null, null, null, null, null, null FROM Users--`
* **Expected Indicators:** The application renders user hashes and emails inside the product grid/JSON response.
* **Cleanup:** N/A (Stateless attack).
