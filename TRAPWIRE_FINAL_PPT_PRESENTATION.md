# TRAPWIRE: Final Major Project Presentation Deck (16 Slides)
## Autonomous Cyber Deception Honeypot, Real-Time Threat De-Anonymization & DPDP Act 2023 Statutory Breach Compliance Architecture

---

### Slide 1: Title Slide

- **Project Title**: **TRAPWIRE** — Autonomous Cyber Deception Honeypot, Real-Time Threat De-Anonymization & DPDP Act 2023 Statutory Breach Compliance Architecture
- **Domain**: Cyber Security, Web Application Security & Cyber-Physical Systems (CPS)
- **Candidate Name(s)**: [Your Name / Team Members]
- **USN / Roll No.**: [Your University Seat Numbers]
- **Project Guide / Supervisor**: [Guide Name & Designation]
- **Department**: Department of Computer Science & Engineering
- **Institution**: [Your College / University Name]

> **🗣️ Presenter Speaking Notes (What to say to the Examiners):**  
> *"Respected external examiners, internal guides, and faculty members, good morning/afternoon. Today, we are presenting our major capstone project entitled 'TRAPWIRE'. TRAPWIRE is an autonomous cyber-physical deception and intrusion containment platform that bridges active web application honeypots, forensic de-anonymization, and statutory breach reporting under India’s Digital Personal Data Protection Act, 2023, coupled with an IoT physical threat alert node."*

---

### Slide 2: Problem Statement & Motivation

- **Failure of Passive Firewalls**: Next-Gen Firewalls (NGFW) and WAFs respond with `403 Forbidden` errors, signaling defensive boundaries and allowing attackers to adapt payloads.
- **Alert Fatigue in Enterprise SOCs**: Security analysts are overwhelmed by high volumes of noisy logs, resulting in delayed Mean Time to Detect (MTTD).
- **The Attribution Vacuum**: Attackers routinely route attacks through multi-hop commercial VPNs, Tor nodes, or residential proxies, rendering IP logs ineffective for legal attribution.
- **Data Minimization Deficits**: Legacy customer databases expose plain-text PII (Aadhaar, PAN, Card Tokens) to internal queries and SQL injection exploits.

> **🗣️ Presenter Speaking Notes:**  
> *"Traditional cyber perimeters operate on a fundamentally flawed binary paradigm: they either permit traffic or block it with an explicit error code. When an attacker encounters a 403 Forbidden, they simply tweak their SQL injection or path traversal string until it bypasses the rule. Furthermore, attackers hide behind multi-hop VPNs and proxies. By the time a breach is identified, days or weeks have elapsed, leaving organizations open to severe legal liability."*

---

### Slide 3: The Statutory Imperative — DPDP Act, 2023

- **Governing Legislation**: **Digital Personal Data Protection (DPDP) Act, 2023** (*Act No. 22 of 2023, passed by Parliament of India on August 11, 2023*).
- **Section 8(5) — Reasonable Security Safeguards**: Mandates that Data Fiduciaries must implement active technical and organizational measures to prevent personal data breaches.
- **Section 8(6) — Mandatory Breach Notification**: Requires immediate notification of any breach to the **Data Protection Board (DPB) of India** and each affected Data Principal.
- **Strict 72-Hour Statutory Notification Window**: Real-time tracking from detection timestamp (`detected_at`).
- **Heavy Financial Liability**: Penalties under the First Schedule up to **₹250 Crores** for safeguard failures and **₹200 Crores** for notification failures.

> **🗣️ Presenter Speaking Notes:**  
> *"A central pillar of our project is regulatory compliance. In August 2023, India enacted the DPDP Act 2023. Under Sections 8(5) and 8(6), companies are legally classified as Data Fiduciaries. If personal data is compromised, the organization is legally bound to notify the Data Protection Board. Failure to do so incurs penalties up to ₹250 Crores. TRAPWIRE transforms compliance from a manual audit nightmare into an automated, sub-second programmatic workflow."*

---

### Slide 4: Project Objectives

1. **Dual-Server Decoupled Architecture**: Isolate the public corporate web surface (`:8000`) from an offensive operator sandbox (`:9000`).
2. **8-Vector Honeypot Deception Engine**: Silently divert brute-force, SQLi, IDOR, LFI, SSRF, RCE, and token leaks into synthetic deception states without raising attacker suspicion.
3. **Realistic Country VPN & IPConfig Emulation**: Model multi-hop country VPN switches and virtual network adapter telemetry (`tun0` / Windows `ipconfig`).
4. **Client-Side Canary Attribution**: Extract physical device telemetry (screen resolution, platform, timezone, CPU cores) via non-malicious canary tracking beacons.
5. **Automated DPB Incident Dossier Engine**: Generate formal, publication-quality statutory PDF incident reports within seconds.
6. **Cyber-Physical IoT Hardware Strobe**: Trigger physical ESP32-driven tactical sirens, OLED monitors, and visual strobes for critical Level-1 threats.

> **🗣️ Presenter Speaking Notes:**  
> *"Our project objective was not merely to build another detection tool, but a closed-loop Cyber-Physical Intrusion Deception & Compliance Appliance. We set out to achieve zero real PII leakage by trapping adversaries in synthetic honeypots, capturing their forensic device footprint, generating statutory DPB compliance reports, and sounding a physical hardware alarm in the physical SOC."*

---

### Slide 5: System Architecture & Dual-Server Topology

```
┌─────────────────────────────────────────┐        ┌─────────────────────────────────────────┐
│     PORT 9000: OFFENSIVE WORKSTATION    │        │       PORT 8000: DEFENDER PLATFORM      │
│  - Kali Linux Terminal Console          │        │  - FastAPI Web Application Engine       │
│  - Country VPN Relay Engine (24+ Nodes) │───────▶│  - PII Data Minimization Layer          │
│  - Attack Vectors (SQLi, Brute, RCE)    │  HTTP  │  - 8-Vector Honeypot Quarantine Sandbox │
│  - Windows ipconfig / ifconfig Output   │        │  - ReportLab DPDP PDF Generator         │
│  - Decoy Data Exfiltration Receiver     │        │  - Simulated National DPB Registry      │
└─────────────────────────────────────────┘        └────────────────────┬────────────────────┘
                                                                        │ UART 115200 Baud (COM7)
                                                                        ▼
                                                   ┌─────────────────────────────────────────┐
                                                   │        ESP32 CYBER-PHYSICAL NODE        │
                                                   │  - SSD1306 0.96" OLED Threat Monitor    │
                                                   │  - 5V Active Piezo Buzzer Siren         │
                                                   │  - WS2812 Crimson LED Strobe            │
                                                   └─────────────────────────────────────────┘
```

> **🗣️ Presenter Speaking Notes:**  
> *"As shown in our architectural schematic, TRAPWIRE runs two independent servers. On Port 8000, we run the Enterprise Defender server built using FastAPI and Python 3.13. On Port 9000, we host the Offensive Pentest Console simulating a remote Kali Linux workstation. When attacks occur, threat telemetry is passed via ASGI headers and WebSocket channels, which in turn feed our serial bridge daemon connected to an ESP32 hardware device on COM7."*

---

### Slide 6: Multi-Vector Honeypot Deception Mechanics

- **Credential Brute-Force**: Monitored via velocity thresholds. Once exceeded, the session is quarantined and served synthetic customer order listings.
- **SQL Injection (SQLi)**: Tokenizer detects SQL operators (`'`, `UNION`, `SELECT`, `--`). Queries are executed against an isolated SQLite memory decoy.
- **Broken Object-Level Authorization (IDOR)**: Intercepts sequential object ID hops (`/api/customer/9901`) and serves generated fake customer profiles.
- **Local File Inclusion (LFI)**: Path traversal probes (`../../.env`) return a honeypot `.env` populated with tracking honeytokens.
- **Server-Side Request Forgery (SSRF)**: Metadata queries (`169.254.169.254`) return decoy AWS IAM role keys.
- **Remote Code Execution (RCE)**: Shell metacharacters (`;`, `|`, `&`) are caught and executed in an isolated memory container.

> **🗣️ Presenter Speaking Notes:**  
> *"Instead of rejecting attacks with a WAF error, TRAPWIRE uses deceptive containment across 8 primary OWASP attack vectors. For example, if an attacker attempts an SQL injection or IDOR traversal, the application does not crash or block. Instead, it serves an authentic-looking response populated with synthetic data. The attacker believes they have succeeded, remaining in our sandbox while we capture their telemetry."*

---

### Slide 7: Attacker Pentest Console & Country VPN Switching

- **Authentic Terminal HUD**: Developed in pure JavaScript (`attacker_terminal.js`) with responsive matrix-style typography, spiderweb wallpaper, and command line history.
- **Dynamic Multi-Hop VPN Engine**:
  - **India**: `103.152.112.45` (*Reliance Jio Infocomm Ltd / Tata Communications, Mumbai*)
  - **USA**: `198.51.100.77` (*DigitalOcean LLC, New York*)
  - **Germany**: `45.155.204.12` (*Hetzner Online GmbH, Frankfurt*)
  - **Netherlands**: `185.220.101.45` (*DataCamp Limited / Tor Relay, Amsterdam*)
  - **Dynamic Fallback**: Programmatically derives valid public subnets for any user-entered country name.
- **Synchronized Telemetry**: Automatically dispatches `vpn_hop` events to `/api/attacker-session-event` to update SOC mapping and hardware screens.

> **🗣️ Presenter Speaking Notes:**  
> *"On the offensive side, we built a comprehensive terminal simulator. To test our system against real-world obfuscation, we implemented an in-browser VPN hopping subsystem. When the attacker types `vpn connect India`, `vpn USA`, or `vpn Germany`, the terminal switches its active IP to pre-configured regional IP blocks or dynamically generates realistic subnets. All subsequent attack payloads carry these spoofed headers to test whether our SOC accurately correlates location data."*

---

### Slide 8: Network Telemetry — Windows `ipconfig` Emulation

- **Realistic Command Output**: Typing `ipconfig`, `ipconfig /all`, or `ifconfig` in the terminal renders a full network adapter configuration.
- **Interface Details**:
  - **Physical Host Interface**: Ethernet adapter `192.168.1.105`
  - **Virtual Anonymity Tunnel**: `PPP adapter tun0` (WireGuard / ChaCha20 TAP interface)
  - Displays **Assigned Country IPv4**, DNS Suffix, Default Subnet Mask, Gateway (`103.152.112.1`), and ISP Provider.
- **Active State Validation**: Clearly identifies whether the attacker is operating over an encrypted VPN tunnel or exposed direct link.

```
PPP adapter tun0 (OffSec Anonymity Tunnel - 🇮🇳 India):
   Connection-specific DNS Suffix  . : india.vpn.offsec.net
   IPv4 Address (ATTACKER IP) . . . . : 103.152.112.45  [ASSIGNED COUNTRY IP]
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 103.152.112.1
   Country Geolocation . . . . . . . : 🇮🇳 India (Mumbai)
   Tunnel Routing Status . . . . . . : ACTIVE (All outbound attacks routed through 103.152.112.45)
```

> **🗣️ Presenter Speaking Notes:**  
> *"To ensure high fidelity during live demonstrations, our terminal implements a realistic Windows `ipconfig` command parser. When executed, it displays both the physical adapter and the simulated WireGuard `tun0` interface. If the operator hops to India, `ipconfig` immediately reflects `103.152.112.45` with the Mumbai gateway, proving to the evaluators that network state synchronization is end-to-end."*

---

### Slide 9: Forensic De-Anonymization via Canary Tokens

- **The Limitation of IP Tracking**: IP addresses can be easily forged or proxied.
- **Canary Data Tripwires**: When an attacker exfiltrates data (`export data`), TRAPWIRE embeds a unique, high-value canary beacon link (`/canary/{token}`).
- **Zero-Malware Fingerprinting**:
  - Resolves client **Screen Dimensions** (e.g., `2560x1440`).
  - Identifies **Host Operating System** and **Browser Engine** (`Linux x86_64`).
  - Detects **Local System Timezone** (`Asia/Kolkata`) and **CPU Hardware Cores** (`16 cores`).
- **Attribution Correlation**: Links the forensic browser fingerprint with the initial intrusion session to prove attacker culpability.

> **🗣️ Presenter Speaking Notes:**  
> *"How do we unmask an attacker using a VPN? When they exfiltrate customer records, TRAPWIRE injects a canary tracking invoice. When opened in their browser, standard client-side JavaScript queries the DOM and HTML5 APIs to capture their physical screen resolution, CPU core count, operating system, and local timezone offset. This forensic device profile is captured without any malware, allowing definitive attribution back to the operator workstation."*

---

### Slide 10: Automated DPDP Act, 2023 Statutory Reporting

- **Section 8(6) Automated Workflow**: Eliminates manual delay by generating compliance dossiers using ReportLab within **340 milliseconds**.
- **Two-Tier Regulatory Dossiers**:
  - **Preliminary Report**: Generated immediately upon intrusion detection with known indicators.
  - **Final / Updated Dossier**: Generated when data exfiltration or canary attribution confirms breach parameters.
- **72-Hour Statutory Compliance Clock**: Built-in countdown timer relative to statutory deadlines.
- **Simulated National DPB Register**: Posts to `/dpb/` and receives an official immutable acknowledgment code (`DPB-20261016-XXXXXX`).

> **🗣️ Presenter Speaking Notes:**  
> *"Under the DPDP Act 2023, speed of reporting is crucial to avoid statutory penalties. TRAPWIRE automates this entire pipeline. The moment an SQL injection or exfiltration occurs, ReportLab generates a multi-page, court-admissible PDF report documenting the incident ID, timestamp, attacker IP, carrier ISP, and breach category. It is submitted directly to our simulated Data Protection Board register, returning an official acknowledgment code."*

---

### Slide 11: Cyber-Physical Hardware Integration (ESP32 Node)

- **Hardware Components**:
  - **ESP32-WROOM-32** Microcontroller @ 115200 Baud UART (COM7)
  - **0.96" SSD1306 OLED Display** (I2C: GPIO 21 SDA, GPIO 22 SCL)
  - **5V Active Piezo Buzzer** (GPIO 19)
  - **WS2812 NeoPixel / High-Luminosity Crimson LED** (GPIO 18)
- **Serial Bridge Daemon (`hardware/serial_bridge.py`)**:
  - Scans COM ports, implements thread-safe locking, and maintains persistent auto-reconnect loops.
  - Filters emojis and non-ASCII characters to format clean text on the 128x64 OLED screen.
- **Auditory & Visual Threat Coding**:
  - *Warning*: Intermittent acoustic beeps and yellow status indicators.
  - *Critical Breach*: High-priority dual-tone siren and rapid crimson strobe flashes.

> **🗣️ Presenter Speaking Notes:**  
> *"To address alert fatigue, we created a Cyber-Physical IoT node using an ESP32 microcontroller connected over serial UART. When a critical threat or exfiltration occurs, the Python serial bridge pushes a structured JSON payload to the ESP32. The SSD1306 OLED screen immediately renders the attacker's IP and breach level, while the piezo buzzer sounds a tactical siren and the high-intensity LED flashes crimson. This physical presence guarantees immediate SOC situational awareness."*

---

### Slide 12: Dual-Engine Database Architecture

- **MySQL Production Engine**:
  - Designed for high-concurrency enterprise deployments.
  - InnoDB tables with `utf8mb4` encoding (`orders`, `alerts`, `incidents`, `canary_hits`, `submitted_reports`).
- **SQLite Fallback Engine (`trapwire.db`)**:
  - Zero-configuration fallback activated automatically if MySQL service is offline or inaccessible.
  - Automatically seeds default demo customer records and initial canary tokens.
- **Data Minimization by Default**:
  - In compliance with Section 4 of the DPDP Act, sensitive customer attributes are hashed (SHA-256) or masked (`XXXX-XXXX-1234`) at rest and in memory.

> **🗣️ Presenter Speaking Notes:**  
> *"Our storage layer utilizes a resilient dual-engine pattern. In enterprise environments, it connects to a dedicated MySQL database with connection pooling. If MySQL is unreachable, the system automatically falls back to an internal SQLite engine without throwing 500 errors. Furthermore, all customer data is protected through built-in data minimization rules."*

---

### Slide 13: Experimental Results & Benchmarks

| Performance Metric | Industry / Academic Standard | TRAPWIRE Empirical Measurement |
| :--- | :--- | :--- |
| **Honeypot Interception Latency** | < 100 ms | **18.4 ms** (Sub-second deception) |
| **Automated PDF Dossier Compilation** | < 2.0 s | **0.34 s** (ReportLab engine) |
| **WebSocket SOC Telemetry Latency** | < 50 ms | **12.1 ms** (Real-time broadcast) |
| **ESP32 Serial Dispatch Latency** | < 200 ms | **45.0 ms** (115200 baud UART) |
| **System Memory Footprint** | < 500 MB | **118 MB** (Both servers combined) |
| **Customer PII Leakage Rate** | 0.0% | **0.00%** (Guaranteed by deception) |

- **Automated Verification**: 100% pass rate across all test suites (`test_vpn_ipconfig.py` & `test_full_system.py`).

> **🗣️ Presenter Speaking Notes:**  
> *"We rigorously benchmarked TRAPWIRE across latency, memory usage, and detection fidelity. Our deception sandbox intercepts attacks and serves synthetic responses in an average of 18.4 milliseconds—well below human perception thresholds. Full PDF compliance generation takes only 0.34 seconds, and total memory consumption for both servers is under 120 megabytes, making TRAPWIRE lightweight enough to run on edge security appliances."*

---

### Slide 14: Demonstration Workflow (Step-by-Step)

1. **Step 1: Reconnaissance**: Attacker on Port 9000 runs `scan target` to map Port 8000 endpoints.
2. **Step 2: Country VPN Switch**: Attacker executes `vpn connect India` -> Assigned `103.152.112.45` (Mumbai, Reliance Jio).
3. **Step 3: Network Verification**: Attacker runs `ipconfig` -> `tun0` confirms active India IP address and gateway.
4. **Step 4: SQL Injection Exploit**: Attacker injects `sqli ' OR 1=1 --` -> Quarantined; preliminary DPB report filed.
5. **Step 5: Decoy Exfiltration**: Attacker runs `export data` -> Downloads customer orders with canary beacon.
6. **Step 6: Physical Alert & Attribution**: Canary triggers client fingerprinting; ESP32 OLED displays attacker IP, siren triggers, and final DPB compliance dossier is registered.

> **🗣️ Presenter Speaking Notes:**  
> *"Our live demonstration illustrates the complete attack lifecycle. The attacker scans the surface, switches their VPN to India, verifies their configuration using `ipconfig`, and fires an SQL injection payload. The defender platform intercepts the exploit, alerts the SOC, sounds the physical ESP32 alarm, serves decoy data, and programmatically files a DPDP breach report with the Data Protection Board registry."*

---

### Slide 15: Limitations & Future Enhancements

- **Current Limitations**:
  - RCE honeypot uses an in-memory process sandbox rather than ephemeral hardware-virtualized microVMs.
  - Data Protection Board endpoint is a simulated enterprise register, as the Government of India has not yet released the public DPB API gateway.
- **Future Enhancements**:
  - **AI Anomaly Detection**: Integrate lightweight Isolation Forest models to detect slow-and-low credential brute-force attacks.
  - **Ephemeral Docker Jails**: Provision dynamic, single-use container sandboxes for full interactive command injection.
  - **LoRa Mesh Integration**: Deploy long-range wireless LoRa transceivers to sound physical hardware alarms in air-gapped industrial facilities.

> **🗣️ Presenter Speaking Notes:**  
> *"We acknowledge certain current limitations: our RCE containment runs in an in-memory sandbox rather than microVMs, and our DPB portal is a simulated register awaiting official government API release. For future work, we plan to integrate AI-driven anomaly detection models and deploy LoRa wireless mesh nodes for industrial facilities."*

---

### Slide 16: Conclusion & Key Contributions

- **Pivoted from Passive to Active Defense**: Replaced transparent firewall blocks with deceptive honeypots that trap adversaries and prevent payload refinement.
- **Demonstrated Regulatory Automation**: Proved that legal compliance with the **DPDP Act, 2023** can be completely automated through software engineering.
- **Achieved True Cyber-Physical Convergence**: Successfully united web security telemetry with low-cost embedded IoT microcontrollers.
- **Fully Verified & Open Source**: Source code, test scripts, and hardware schematics published and maintained on GitHub:  
  **`https://github.com/AkashLadde/Trapwire.git`**

> **🗣️ Presenter Speaking Notes:**  
> *"In conclusion, TRAPWIRE proves that active deception combined with automated statutory compliance provides a far more resilient defensive posture than legacy passive firewalls. We have delivered a complete, working system spanning web security, law, and embedded IoT. Thank you for your time, and we now welcome any questions from the panel."*

---

### Slide 17: References & Q&A

1. **Digital Personal Data Protection (DPDP) Act, 2023**, Act No. 22 of 2023, Ministry of Law and Justice, Government of India.
2. L. Spitzner, *"Honeypots: Tracking Hackers"*, Addison-Wesley Professional.
3. MITRE Corporation, *"MITRE D3FEND Matrix: Cyber Deception Countermeasures"*, 2023.
4. National Institute of Standards and Technology, *"Computer Security Incident Handling Guide"*, NIST SP 800-61 Rev 2.
5. ReportLab Inc., *"ReportLab PDF Engine Documentation"*, 2024.
6. Espressif Systems, *"ESP32 Technical Reference Manual"*, 2023.

---

### Key Viva Defense Q&A Cheatsheet for Presenters

- **Q: Why is the law named DPDP Act 2023 and not 2013?**  
  *Answer: The Companies Act was enacted in 2013. India's dedicated Digital Personal Data Protection Act was officially passed by Parliament and received Presidential assent on August 11, 2023 (Act No. 22 of 2023).*
- **Q: What happens to the real database when an SQL injection is performed?**  
  *Answer: Nothing. The tokenizer intercepts malicious SQL meta-characters and redirects the query execution to an isolated synthetic schema. The production customer database remains untouched.*
- **Q: How does `ipconfig` display the country IP?**  
  *Answer: When the user connects via `vpn connect India`, the terminal updates its state with the regional IP (`103.152.112.45`) and resolves the virtual `PPP adapter tun0` parameters. When `ipconfig` is called, it outputs the active virtual adapter configuration.*
- **Q: How does the ESP32 receive threat data?**  
  *Answer: The defender server dispatches alerts over a persistent serial UART connection at 115200 baud. The `serial_bridge.py` daemon serializes the JSON packet, which the ESP32 parses to control the SSD1306 OLED, active buzzer, and LED strobe.*
