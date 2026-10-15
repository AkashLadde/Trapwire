# TRAPWIRE — Local Demo (Company + Attacker Portals)

Educational cybersecurity capstone demo. Everything runs locally — the
"attacker" side only ever talks to this same local server; nothing here
touches the real internet or any real system.

## Setup

```
pip install -r requirements.txt
```

## Run

```
uvicorn app.main:app --reload --port 8000
```

Open http://127.0.0.1:8000/

## Supported Attack Simulation Vectors (Honeypot Deception Engine)

The project includes built-in offensive simulation modules on the **Attacker Pentest Console (Port 9000)** and corresponding deception & intrusion detection honeypots on the **Company Defender Server (Port 8000)**:

| Attack Vector | Attacker Command / Action | Defender Endpoint | Deception / Honeypot Defense Response |
| :--- | :--- | :--- | :--- |
| **Credential Brute-Force** | `bruteforce --user admin` | `POST /api/login` | Flags session as suspicious after failed attempts; switches to synthetic honeypot data view. |
| **SQL Injection (SQLi)** | `sqli [payload]` | `GET /api/search-customer` | Evaluates SQL syntax, quarantines query to fake SQLite/MySQL tables, returns decoy admin records, and auto-files preliminary DPB report. |
| **IDOR / BOLA** | `idor 9901` | `GET /api/customer/{id}` | Detects unauthorized sequential ID traversal; serves synthetic customer profile with embedded canary beacon. |
| **LFI / Path Traversal** | `lfi ../../.env` | `GET /api/download?file=...` | Detects directory navigation attempts; serves decoy `.env` file containing planted AWS/DB honeytokens. |
| **Server-Side Request Forgery (SSRF)** | `ssrf http://169.254.169.254` | `GET /api/preview-url?url=...` | Detects cloud metadata probes; serves decoy AWS IMDSv2 IAM credentials. |
| **Remote Command Execution (RCE)** | `rce 127.0.0.1; whoami` | `GET /api/diagnostics/ping` | Detects shell metacharacters; quarantines execution inside isolated deception container. |
| **Canary Honeytoken Leak** | `honeytoken` | `GET /api/v1/internal/admin-dump` | Detects use of planted canary API key; executes high-confidence attacker de-anonymization and files final report. |
| **Decoy Data Exfiltration** | `export data` | `GET /api/export` | Replaces sensitive fields with one-way SHA-256 hashes, embeds canary token, and files preliminary statutory DPB report. |
| **Canary Attribution Beacon** | Opening invoice link | `GET /canary/{token}` | Executes client-side JavaScript fingerprinting (screen, timezone, platform, cores) and submits final DPB report. |

## What's real vs simulated (be upfront about this in your viva)

- Real / working: brute-force detection heuristic, honeypot data
  switching, canary-token attribution with live browser-fingerprint capture
  (screen, timezone, platform — a real technique used by actual security
  teams, no malware involved), live alerting via WebSocket, automated PDF
  compliance report generation, and a working (simulated) Data Protection
  Board portal that receives, stores, and acknowledges every submission.
- Simulated for the demo: the "VPN" is a cosmetic label; the DPB portal is
  clearly marked as an educational simulation and is not a real government
  system (no official emblem is used, and every page carries a visible
  disclaimer banner); the geolocation lookup falls back to a labeled
  simulated result if there's no internet access to ip-api.com; there's no
  real network packet capture (that's listed as future work in your own
  P1 slide).
- Deliberately NOT included: no actual malware/virus payload, and no
  generic credential-cracking tool aimed at third-party systems — the
  brute-force here only ever targets this app's own demo login endpoint,
  and attacker-detail capture is ordinary client-side JavaScript in a
  browser tab, not code that runs on or infects the attacker's system.
  This keeps the project in "legitimate security research / defensive
  simulation" territory instead of building actual attack tooling.

## Statutory Compliance — Digital Personal Data Protection (DPDP) Act, 2023

> [!IMPORTANT]
> **Correct Statutory Title & Enactment Year**:  
> The governing Indian data protection law is the **Digital Personal Data Protection (DPDP) Act, 2023** (*Act No. 22 of 2023, enacted by the Parliament of India on August 11, 2023*).  
> Ensure all project slides (P1/P2) and documentation cite **DPDP Act, 2023** (never "2013", which was the Companies Act).

### Key DPDP Act, 2023 Provisions Implemented in TRAPWIRE

1. **Section 8(5) — Reasonable Security Safeguards**:
   - TRAPWIRE deploys deception honeypots, canary honeytokens, and dynamic routing isolation to proactively safeguard customer PII data stores.
2. **Section 8(6) — Mandatory Breach Notification**:
   - In the event of an exfiltration attempt or personal data breach, TRAPWIRE automatically generates statutory PDF reports and files them directly with the **Data Protection Board (DPB) of India**.
3. **Data Minimization & Masking (Section 4 & 6)**:
   - All Aadhaar, PAN, phone numbers, and payment card details are masked by default across all SOC views to adhere strictly to the principle of data minimization.
4. **Strict 72-Hour Compliance Clock**:
   - Real-time countdown tracking is maintained from incident detection timestamp (`detected_at`) to ensure immediate compliance reporting.
