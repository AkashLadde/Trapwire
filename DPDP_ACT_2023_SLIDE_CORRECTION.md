# Digital Personal Data Protection (DPDP) Act, 2023 — Slide Correction & Viva Defense Guide

---

## 1. Critical Slide Correction (P1 / P2 / Final Presentation)

### ❌ Incorrect Citation
> *"DPDP Act, 2013"* or *"Digital Personal Data Protection Act, 2013"*

### ✅ Correct Statutory Citation
> **Digital Personal Data Protection (DPDP) Act, 2023**  
> *(Act No. 22 of 2023 · Enacted by Parliament of India on August 11, 2023)*

---

## 2. Why "2013" Was a Mistake & How to Explain in Viva

| Aspect | The 2013 Law (Wrong Context) | DPDP Act, 2023 (Correct Law) |
| :--- | :--- | :--- |
| **Official Title** | Companies Act, 2013 | **Digital Personal Data Protection Act, 2023** |
| **Jurisdiction** | Corporate governance, incorporation & finance | **Digital personal data protection, privacy & breach notification** |
| **Regulatory Authority**| Ministry of Corporate Affairs (MCA) / ROC | **Data Protection Board of India (DPB)** |
| **Max Penalty** | Corporate fines / director disqualifications | **Up to ₹250 Crores per data breach violation** |

> **Viva Pro-Tip**: If the evaluator asks about the law:
> *"The Indian Parliament passed the Digital Personal Data Protection Act in August 2023 (Act No. 22 of 2023). Any earlier reference to 2013 in initial drafts was a typographical confusion with the Companies Act 2013. TRAPWIRE is architected specifically around the DPDP Act, 2023 compliance guidelines."*

---

## 3. Copy-Paste Slide Text for Your PPT

### Slide Title: **Legal & Statutory Framework — DPDP Act, 2023 Compliance**

- **Governing Law**: Digital Personal Data Protection (DPDP) Act, 2023 (Act No. 22 of 2023).
- **Applicability**:
  - Processing of digital personal data within India.
  - Role of Company: **Data Fiduciary** under Section 8.
- **Section 8(5) — Reasonable Security Safeguards**:
  - Implementation of active cyber deception honeypots to isolate unauthorized intrusions before real databases are impacted.
- **Section 8(6) — Mandatory Breach Notification**:
  - Immediate automated dispatch of statutory incident reports to the **Data Protection Board (DPB) of India**.
  - 72-hour automated compliance tracking clock.
- **Data Minimization (Section 4 & 6)**:
  - Default masking of sensitive PII (Aadhaar, PAN, Card Numbers, Phone) across all internal SOC views.

---

## 4. Key Viva Questions & Bulletproof Answers

### Q1: What is a Data Fiduciary and Data Principal under the DPDP Act, 2023?
- **Data Principal**: The individual citizen whose personal data is collected and processed (e.g., customers placing orders on TrapWire).
- **Data Fiduciary**: The entity/company that determines the purpose and means of processing personal data (e.g., TrapWire Enterprise).

### Q2: What are the consequences of failing to report a breach under DPDP Act, 2023?
- Under the First Schedule of the DPDP Act, 2023, failure to take reasonable security safeguards to prevent personal data breaches under Section 8(5) carries penalties up to **₹250 Crores**.
- Failure to notify the Data Protection Board and affected Data Principals under Section 8(6) carries penalties up to **₹200 Crores**.

### Q3: How does TRAPWIRE automate DPDP compliance?
1. **Intrusion Detection**: When SQLi, Brute-Force, or Data Exfiltration is detected, TRAPWIRE quarantines the attacker to synthetic decoy datasets.
2. **Preliminary Report Generation**: Automatically builds a PDF breach report capturing timestamp, attacker IP, carrier ISP, attack vector, and affected records.
3. **Automated DPB Filing**: Submits the report directly to the simulated national Data Protection Board registry, returning an immutable acknowledgment number (e.g., `DPB-20261016-XXXXXX`).
4. **Hardware SOC Escalation**: Dispatches real-time serial signals to the physical ESP32 threat strobe and OLED monitor.
