/**
 * TRAPWIRE — Attacker Workstation Command Interpreter & Simulation Engine
 * Kali Linux / Pentest Console Experience (Purely Simulated & Safe)
 * Targets Defender Server at http://127.0.0.1:8000
 */

(function () {
  "use strict";

  const API_BASE = window.TARGET_API_BASE || "http://127.0.0.1:8000";

  // --- Virtual Filesystem Model ---
  const VIRTUAL_FS = {
    "shadow_vault": {
      "leak_database.enc": {
        size: "12.4 MB",
        type: "encrypted",
        content: `╔══════════════════════════════════════════════════════════════════════╗
║                    SIMULATED ENCRYPTED DATABASE                      ║
╠══════════════════════════════════════════════════════════════════════╣
║ FILE: leak_database.enc                                              ║
║ SIZE: 12.4 MB                                                        ║
║ ENCRYPTION: AES-256 [SIMULATED]                                      ║
║ RECORDS: 14                                                          ║
║ CLASSIFICATION: HONEYPOT DECOY DATA                                  ║
║ STATUS: READY FOR EXPORT                                             ║
╚══════════════════════════════════════════════════════════════════════╝

Sample Record Preview (Decoy Synthetic Data):
+---------------+---------------------+-----------------------------+-------------------+
| Order ID      | Customer Name       | Email                       | Phone             |
+---------------+---------------------+-----------------------------+-------------------+
| ORD-749201    | Aarav Sharma        | aarav.s82@example.test      | +91-90000-00001   |
| ORD-839104    | Ananya Reddy        | ananya.r14@example.test     | +91-90000-00002   |
| ORD-194820    | Kabir Verma         | kabir.v55@example.test      | +91-90000-00003   |
| ORD-402918    | Meera Iyer          | meera.i99@example.test      | +91-90000-00004   |
+---------------+---------------------+-----------------------------+-------------------+
[!] Sensitive fields (Aadhaar/PAN/Card) are isolated in honeypot vault.`
      },
      "client_records.enc": {
        size: "4.8 MB",
        type: "encrypted",
        content: `[ENCRYPTED CLIENT ARCHIVE]
FORMAT: JSON-LINES (GZIP/AES)
DATASET: E-Commerce Customer Profiles
TOTAL OBJECTS: 14 records
INTEGRITY HASH: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
USE 'export data' TO EXTRACT PAYLOAD.`
      },
      "master_keys.bak": {
        size: "1.2 KB",
        type: "key",
        content: `-----BEGIN SIMULATED RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0wJd8tQ4Wb5z9Q5vK9f2z7l0wY3k8J4m7p8q2r6t9u0v1w3x
y5z7a9b1c3d5e7f9g1h3j5k7m9n1p3q5r7s9t1u3v5w7x9y1z3a5b7c9d1e3f5g7
[SIMULATED RSA KEY - EDUCATIONAL CAPSTONE PURPOSES ONLY]
-----END SIMULATED RSA PRIVATE KEY-----`
      }
    },
    "onion_links": {
      "hidden_markets.lst": {
        size: "840 B",
        type: "text",
        content: `[SIMULATED DARKNET REPOSITORIES]
http://trapwire2837492jsdflkjwoeir093284.onion/vault
http://shadowdump893472938472938472938.onion/intel
http://zerodaybroker998237492837492834.onion/exploits
[NOTE: Synthetic fictional URIs for educational UI realism]`
      }
    },
    "malware_kits": {
      "payloads.sh": {
        size: "2.1 KB",
        type: "script",
        content: `#!/bin/bash
# ==========================================================
# TRAPWIRE EDUCATIONAL LAB - BENIGN TEST PAYLOAD
# Safe demonstration wrapper for ethical intrusion testing
# ==========================================================
echo "[+] Initializing simulated breach testing agent..."
echo "[+] Target environment: Localhost Sandbox (127.0.0.1:8000)"
echo "[+] Mode: Intrusion Detection & DPDP Compliance Verification"`
      },
      "ransom_notes.txt": {
        size: "620 B",
        type: "text",
        content: `===============================================================
[SIMULATION NOTICE]
This system is protected by TRAPWIRE Autonomous Threat Deception.
All intrusion attempts are quarantined to decoy honeypot environments.
Canary tracking tokens auto-report breach telemetry to India's DPB.
===============================================================`
      }
    },
    "stolen_creds": {
      "hash_dump.txt": {
        size: "1.8 KB",
        type: "hashes",
        content: `[CAPTURED SHA-256 HASHES (SIMULATED)]
8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92 : 123456
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 : password
65e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5 : qwerty123
a94a8fe5ccb19ba61c4c0873d391e987982fbbd3fc964b97a2243d578ee192b0 : letmein123
c897bf1277a06f34e6e66cf533b769ea8d407670733d3d622f6d2f36b6d51012 : Admin@2026!`
      }
    },
    "zero_logs": {
      "session_logs.log": {
        size: "5.1 KB",
        type: "log",
        content: `[SESSION LOGS — SIMULATED SECURITY AUDIT]
08:41:02 [AUTH] Authentication module initialized on :8000
08:41:08 [AUTH] Failed login attempt from 127.0.0.1 (user: admin)
08:41:11 [AUTH] Failed login attempt from 127.0.0.1 (user: admin)
08:41:14 [AUTH] Failed login attempt from 127.0.0.1 (user: admin)
08:41:16 [WARN] Anomaly detection threshold exceeded (>3 failed attempts)
08:41:20 [HONEYPOT] Deception engine armed for suspicious source
08:41:22 [CANARY] Canary token generator seeded`
      }
    }
  };

  // --- Comprehensive Country-to-VPN Relay Registry ---
  const COUNTRY_NODES = {
    "india": {
      country: "India", flag: "🇮🇳", city: "Mumbai",
      ip: "103.152.112.45", gateway: "103.152.112.1",
      isp: "Reliance Jio Infocomm Ltd (Fiber Broadband)",
      org: "Reliance Jio Infocomm", region: "Maharashtra", as: "AS55836 Jio Broadband",
      aliases: ["india", "in", "bharat", "mumbai", "delhi", "bangalore"]
    },
    "united states": {
      country: "United States", flag: "🇺🇸", city: "New York",
      ip: "198.51.100.77", gateway: "198.51.100.1",
      isp: "DigitalOcean LLC (US-East Datacenter)",
      org: "DigitalOcean Cloud Infrastructure", region: "New York", as: "AS14061 DigitalOcean",
      aliases: ["usa", "us", "united states", "united states of america", "america", "new york", "california"]
    },
    "netherlands": {
      country: "Netherlands", flag: "🇳🇱", city: "Amsterdam",
      ip: "185.220.101.45", gateway: "185.220.101.1",
      isp: "DataCamp Limited - Anonymous Tor/VPN Relay",
      org: "DataCamp Global Relays", region: "North Holland", as: "AS60068 DataCamp",
      aliases: ["netherlands", "holland", "amsterdam", "nl", "dutch"]
    },
    "germany": {
      country: "Germany", flag: "🇩🇪", city: "Frankfurt",
      ip: "45.155.204.12", gateway: "45.155.204.1",
      isp: "Hetzner Online GmbH (Frankfurt DC)",
      org: "Hetzner Cloud Infrastructure", region: "Hesse", as: "AS24940 Hetzner Online",
      aliases: ["germany", "deutschland", "de", "frankfurt", "berlin"]
    },
    "singapore": {
      country: "Singapore", flag: "🇸🇬", city: "Singapore",
      ip: "103.253.24.19", gateway: "103.253.24.1",
      isp: "Singtel Cyber Security Subnet",
      org: "Singapore Telecommunications Limited", region: "Central Singapore", as: "AS7473 Singtel",
      aliases: ["singapore", "sg"]
    },
    "japan": {
      country: "Japan", flag: "🇯🇵", city: "Tokyo",
      ip: "103.4.17.88", gateway: "103.4.17.1",
      isp: "Sakura Internet Tokyo Datacenter",
      org: "Sakura Internet Inc.", region: "Kanto", as: "AS9370 SAKURA-BGP",
      aliases: ["japan", "jp", "tokyo", "osaka", "nippon"]
    },
    "united kingdom": {
      country: "United Kingdom", flag: "🇬🇧", city: "London",
      ip: "185.220.101.5", gateway: "185.220.101.1",
      isp: "M247 Ltd London Relay",
      org: "M247 Europe Backbone", region: "England", as: "AS9009 M247 Ltd",
      aliases: ["uk", "united kingdom", "gb", "great britain", "britain", "england", "london"]
    },
    "canada": {
      country: "Canada", flag: "🇨🇦", city: "Montreal",
      ip: "198.50.200.41", gateway: "198.50.200.1",
      isp: "OVH Hosting Canada Inc.",
      org: "OVH Canada Cloud", region: "Quebec", as: "AS16276 OVH",
      aliases: ["canada", "ca", "montreal", "toronto"]
    },
    "france": {
      country: "France", flag: "🇫🇷", city: "Paris",
      ip: "51.255.45.10", gateway: "51.255.45.1",
      isp: "OVH SAS Paris Datacenter",
      org: "OVH Groupe", region: "Ile-de-France", as: "AS16276 OVH",
      aliases: ["france", "fr", "paris"]
    },
    "australia": {
      country: "Australia", flag: "🇦🇺", city: "Sydney",
      ip: "139.99.130.20", gateway: "139.99.130.1",
      isp: "Telstra Internet Australia Backbone",
      org: "Telstra Corporation", region: "New South Wales", as: "AS1221 Telstra",
      aliases: ["australia", "au", "sydney", "melbourne"]
    },
    "russia": {
      country: "Russia", flag: "🇷🇺", city: "Moscow",
      ip: "95.173.136.25", gateway: "95.173.136.1",
      isp: "Rostelecom Moscow Relay",
      org: "PJSC Rostelecom", region: "Moscow Federal City", as: "AS12389 Rostelecom",
      aliases: ["russia", "ru", "moscow", "saint petersburg", "russian federation"]
    },
    "china": {
      country: "China", flag: "🇨🇳", city: "Beijing",
      ip: "114.114.114.114", gateway: "114.114.114.1",
      isp: "China Telecom Backbone Relay",
      org: "China Telecom", region: "Beijing", as: "AS4134 CHINANET",
      aliases: ["china", "cn", "beijing", "shanghai"]
    },
    "switzerland": {
      country: "Switzerland", flag: "🇨🇭", city: "Zurich",
      ip: "185.107.56.23", gateway: "185.107.56.1",
      isp: "ProtonVPN AG / Private Layer Zurich",
      org: "Proton AG", region: "Zurich", as: "AS51852 Private Layer",
      aliases: ["switzerland", "ch", "swiss", "zurich", "geneva"]
    },
    "sweden": {
      country: "Sweden", flag: "🇸🇪", city: "Stockholm",
      ip: "193.180.119.2", gateway: "193.180.119.1",
      isp: "Mullvad VPN / Bahnhof AB",
      org: "Bahnhof AB", region: "Stockholm", as: "AS8473 Bahnhof",
      aliases: ["sweden", "se", "stockholm"]
    },
    "brazil": {
      country: "Brazil", flag: "🇧🇷", city: "São Paulo",
      ip: "177.54.144.10", gateway: "177.54.144.1",
      isp: "Claro Brasil Backbone Subnet",
      org: "Claro NXT Telecomunicacoes", region: "Sao Paulo", as: "AS28573 Claro Brasil",
      aliases: ["brazil", "brasil", "br", "sao paulo"]
    },
    "united arab emirates": {
      country: "United Arab Emirates", flag: "🇦🇪", city: "Dubai",
      ip: "94.200.12.18", gateway: "94.200.12.1",
      isp: "Etisalat Telecommunications Dubai",
      org: "Emirates Telecommunications Group", region: "Dubai", as: "AS8966 Emirates Telecom",
      aliases: ["uae", "united arab emirates", "dubai", "ae", "abu dhabi"]
    },
    "south korea": {
      country: "South Korea", flag: "🇰🇷", city: "Seoul",
      ip: "211.234.118.50", gateway: "211.234.118.1",
      isp: "KT Corporation Telecom Relay",
      org: "KT Corporation", region: "Seoul", as: "AS4766 Korea Telecom",
      aliases: ["south korea", "korea", "kr", "seoul"]
    },
    "italy": {
      country: "Italy", flag: "🇮🇹", city: "Milan",
      ip: "185.25.204.10", gateway: "185.25.204.1",
      isp: "Telecom Italia Sparkle Milan",
      org: "Telecom Italia", region: "Lombardy", as: "AS6762 Sparkle",
      aliases: ["italy", "italia", "it", "milan", "rome"]
    },
    "spain": {
      country: "Spain", flag: "🇪🇸", city: "Madrid",
      ip: "84.120.50.15", gateway: "84.120.50.1",
      isp: "Telefonica de España Madrid",
      org: "Telefonica de Espana S.A.U.", region: "Madrid", as: "AS3352 Telefonica",
      aliases: ["spain", "espana", "es", "madrid"]
    },
    "norway": {
      country: "Norway", flag: "🇳🇴", city: "Oslo",
      ip: "185.125.204.5", gateway: "185.125.204.1",
      isp: "Telenor Norge AS Oslo",
      org: "Telenor Norge", region: "Oslo", as: "AS2119 Telenor",
      aliases: ["norway", "no", "oslo"]
    },
    "finland": {
      country: "Finland", flag: "🇫🇮", city: "Helsinki",
      ip: "185.100.86.12", gateway: "185.100.86.1",
      isp: "Telia Finland Oy Helsinki",
      org: "Telia Finland", region: "Uusimaa", as: "AS1759 Telia",
      aliases: ["finland", "fi", "helsinki"]
    },
    "ireland": {
      country: "Ireland", flag: "🇮🇪", city: "Dublin",
      ip: "185.145.128.4", gateway: "185.145.128.1",
      isp: "Amazon Ireland Datacenter",
      org: "Amazon Data Services Ireland", region: "Leinster", as: "AS16509 Amazon",
      aliases: ["ireland", "ie", "dublin"]
    },
    "poland": {
      country: "Poland", flag: "🇵🇱", city: "Warsaw",
      ip: "185.240.244.15", gateway: "185.240.244.1",
      isp: "Orange Polska S.A.",
      org: "Orange Polska", region: "Mazovia", as: "AS5617 Orange Polska",
      aliases: ["poland", "pl", "warsaw", "polska"]
    },
    "israel": {
      country: "Israel", flag: "🇮🇱", city: "Tel Aviv",
      ip: "185.191.171.12", gateway: "185.191.171.1",
      isp: "Bezeq International Tel Aviv",
      org: "Bezeq The Israel Telecommunication", region: "Tel Aviv", as: "AS8551 Bezeq",
      aliases: ["israel", "il", "tel aviv"]
    },
    "hong kong": {
      country: "Hong Kong", flag: "🇭🇰", city: "Hong Kong",
      ip: "103.214.144.8", gateway: "103.214.144.1",
      isp: "HKBN Enterprise Solutions",
      org: "Hong Kong Broadband Network", region: "Hong Kong", as: "AS9269 HKBN",
      aliases: ["hong kong", "hk"]
    },
    "mexico": {
      country: "Mexico", flag: "🇲🇽", city: "Mexico City",
      ip: "189.240.12.5", gateway: "189.240.12.1",
      isp: "Telmex Red de Acceso",
      org: "Uninet S.A. de C.V.", region: "CDMX", as: "AS8151 Uninet",
      aliases: ["mexico", "mx", "mexico city"]
    },
    "turkey": {
      country: "Turkey", flag: "🇹🇷", city: "Istanbul",
      ip: "185.184.24.5", gateway: "185.184.24.1",
      isp: "Turk Telekomunikasyon Istanbul",
      org: "Turk Telekom", region: "Istanbul", as: "AS9121 Turk Telekom",
      aliases: ["turkey", "turkiye", "tr", "istanbul"]
    },
    "ukraine": {
      country: "Ukraine", flag: "🇺🇦", city: "Kyiv",
      ip: "185.156.172.4", gateway: "185.156.172.1",
      isp: "Kyivstar Telecommunications",
      org: "JSC Kyivstar", region: "Kyiv City", as: "AS15895 Kyivstar",
      aliases: ["ukraine", "ua", "kyiv", "kiev"]
    },
    "south africa": {
      country: "South Africa", flag: "🇿🇦", city: "Johannesburg",
      ip: "102.165.32.14", gateway: "102.165.32.1",
      isp: "Vodacom SA Internet Backbone",
      org: "Vodacom", region: "Gauteng", as: "AS36937 Vodacom",
      aliases: ["south africa", "za", "johannesburg"]
    }
  };

  // Helper: Resolves any user-entered country query (or creates realistic node dynamically)
  function resolveCountryNode(rawQuery) {
    if (!rawQuery || typeof rawQuery !== "string") {
      return COUNTRY_NODES["netherlands"];
    }
    const q = rawQuery.trim().toLowerCase().replace(/[^a-z0-9 ]/g, "");
    if (!q) return COUNTRY_NODES["netherlands"];

    // 1. Direct match on key or aliases
    for (const key in COUNTRY_NODES) {
      const node = COUNTRY_NODES[key];
      if (key === q || (node.aliases && node.aliases.includes(q))) {
        return node;
      }
    }

    // 2. Partial match
    for (const key in COUNTRY_NODES) {
      const node = COUNTRY_NODES[key];
      if (key.includes(q) || q.includes(key)) {
        return node;
      }
      if (node.aliases) {
        for (const alias of node.aliases) {
          if (alias.includes(q) || q.includes(alias)) {
            return node;
          }
        }
      }
    }

    // 3. Fallback: Generate deterministic realistic IP & node for ANY arbitrary country name
    const title = rawQuery.trim().split(/\s+/).map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join(" ");
    let hash = 0;
    for (let i = 0; i < title.length; i++) {
      hash = ((hash << 5) - hash) + title.charCodeAt(i);
      hash |= 0;
    }
    const octet2 = 100 + (Math.abs(hash) % 150);
    const octet3 = 10 + (Math.abs(hash >> 3) % 240);
    const octet4 = 2 + (Math.abs(hash >> 7) % 250);
    const fakeIp = `185.${octet2}.${octet3}.${octet4}`;
    const gateway = `185.${octet2}.${octet3}.1`;

    return {
      country: title,
      flag: "🌐",
      city: `${title} Central Gateway`,
      ip: fakeIp,
      gateway: gateway,
      isp: `${title} Offshore Secure VPN Tunnel / Anonymous Relay`,
      org: `${title} Autonomous Telemetry Network`,
      region: `${title} Federal Region`,
      as: `AS${40000 + (Math.abs(hash) % 20000)}`,
      aliases: [q]
    };
  }

  // State Management
  const state = {
    currentDir: "root",
    history: [],
    historyIndex: -1,
    isAuthenticated: false,
    isSuspicious: false,
    vpnConnected: false,
    vpnNode: "Disconnected",
    apparentIp: "127.0.0.1 (Direct)",
    attackerIp: "127.0.0.1",
    vpnCountry: null,
    vpnCity: null,
    vpnIsp: null,
    vpnFlag: "🌐",
    vpnGateway: "127.0.0.1",
    canaryArmed: true,
    honeypotActive: false,
    incidentId: "NONE",
    targetUser: window.TARGET_USERNAME || "admin",
    wordlist: window.WORDLIST || [
      "123456", "password", "admin123", "admin@123",
      "Welcome@123", "qwerty123", "Admin@2026!", "letmein123"
    ]
  };

  // DOM Elements
  const termOutput = document.getElementById("termOutput");
  const termInput = document.getElementById("termInput");
  const terminalBody = document.getElementById("terminalBody");
  const promptPath = document.getElementById("promptPath");

  // Topbar / Telemetry DOM elements
  const topVpnStatus = document.getElementById("topVpnStatus");
  const topSessionStatus = document.getElementById("topSessionStatus");
  const targetHostEl = document.getElementById("targetHostEl");
  const vpnStatusEl = document.getElementById("vpnStatusEl");
  const sessionStatusEl = document.getElementById("sessionStatusEl");
  const honeypotStatusEl = document.getElementById("honeypotStatusEl");
  const canaryStatusEl = document.getElementById("canaryStatusEl");
  const incidentIdEl = document.getElementById("incidentIdEl");

  // Step elements
  const stepVpn = document.getElementById("stepVpn");
  const stepScan = document.getElementById("stepScan");
  const stepAuth = document.getElementById("stepAuth");
  const stepHoneypot = document.getElementById("stepHoneypot");
  const stepExport = document.getElementById("stepExport");
  const stepCanary = document.getElementById("stepCanary");

  // Helper: Sleep
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  // Helper: Scroll terminal to bottom
  function scrollToBottom() {
    if (terminalBody) {
      terminalBody.scrollTop = terminalBody.scrollHeight;
    }
  }

  // Print Line to Terminal
  function printLine(text, styleClass = "info") {
    const line = document.createElement("div");
    line.className = "term-line " + styleClass;
    line.innerHTML = text;
    termOutput.appendChild(line);
    scrollToBottom();
    return line;
  }

  // Print Raw HTML / Box to Terminal
  function printRaw(html) {
    const wrapper = document.createElement("div");
    wrapper.innerHTML = html;
    termOutput.appendChild(wrapper);
    scrollToBottom();
  }

  // Initialize Welcome Banner
  function printWelcomeBanner() {
    printLine("┌────────────────────────────────────────────────────────────────────────┐", "cyan");
    printLine("│  OFFENSIVE SECURITY PENTEST WORKSTATION — KALI LINUX 2026.4 (PORT 9000)│", "error");
    printLine("│  Autonomous Exploit Lab, Vulnerability Assessment & Deception Research │", "dim");
    printLine("└────────────────────────────────────────────────────────────────────────┘", "cyan");
    printLine("Target Company Host: <b style='color:#00e5ff;'>" + API_BASE + "</b> (Admin Security Center)", "info");
    printLine("Admin Alert SMS Target: <b style='color:#10b981;'>+91 99016 25399</b> (Real-time Dispatches)", "info");
    printLine("Type <b style='color:#ff003b;'>help</b> for offensive commands, or click any file/tool in the sidebar.", "cyan");
    printLine("");
  }

  // Update Status in Right & Top UI
  function updateUIState() {
    if (topVpnStatus) {
      topVpnStatus.textContent = state.vpnConnected
        ? `VPN: ${state.vpnFlag || '🌐'} ${state.vpnCountry || state.vpnNode}`
        : "VPN: OFF";
      topVpnStatus.parentElement.className = state.vpnConnected ? "atk-meta-pill vpn-active" : "atk-meta-pill";
    }
    if (topSessionStatus) {
      topSessionStatus.textContent = state.isAuthenticated
        ? (state.isSuspicious ? "SESSION: SUSPICIOUS [ISOLATED]" : "SESSION: AUTHENTICATED")
        : "SESSION: ANONYMOUS";
      topSessionStatus.parentElement.className = state.isSuspicious ? "atk-meta-pill suspicious-active" : "atk-meta-pill";
    }
    if (vpnStatusEl) {
      vpnStatusEl.textContent = state.vpnConnected
        ? `${state.vpnFlag || '🌐'} ${state.vpnCountry || state.vpnNode} (${state.attackerIp || (state.apparentIp || '127.0.0.1').split(' ')[0]})`
        : "DISCONNECTED";
      vpnStatusEl.className = state.vpnConnected ? "spec-val-badge badge-success" : "spec-val-badge badge-standby";
    }
    if (sessionStatusEl) {
      sessionStatusEl.textContent = state.isAuthenticated ? (state.isSuspicious ? "SUSPICIOUS" : "NORMAL") : "ANONYMOUS";
      sessionStatusEl.className = state.isSuspicious ? "spec-val-badge badge-active" : (state.isAuthenticated ? "spec-val-badge badge-success" : "spec-val-badge badge-standby");
    }
    if (honeypotStatusEl) {
      honeypotStatusEl.textContent = state.honeypotActive ? "ACTIVE (DECOY)" : "ARMED";
      honeypotStatusEl.className = state.honeypotActive ? "spec-val-badge badge-active" : "spec-val-badge badge-armed";
    }
    if (canaryStatusEl) {
      canaryStatusEl.textContent = state.canaryArmed ? (state.honeypotActive ? "ARMED (BEACON READY)" : "ARMED") : "TRIGGERED";
      canaryStatusEl.className = state.canaryArmed ? "spec-val-badge badge-armed" : "spec-val-badge badge-active";
    }
    if (incidentIdEl) {
      incidentIdEl.textContent = state.incidentId;
      incidentIdEl.style.color = state.incidentId !== "NONE" ? "#ef4444" : "#94a3b8";
    }
    if (promptPath) {
      promptPath.textContent = state.currentDir === "root" ? "~/workspace" : `~/workspace/${state.currentDir}`;
    }
  }

  // --- Commands Implementation ---

  const COMMANDS = {
    help: async () => {
      if (typeof window.playBeepSound === "function") window.playBeepSound();
      printLine("<b style='color:#00e5ff;'>OFFSEC PENTEST COMMAND DIRECTORY — KALI LINUX</b>", "cyan");
      printLine("─────────────────────────────────────────────────────────────────", "dim");
      
      printLine("<b style='color:#c084fc;'>[RECON, ANONYMITY & NETWORK]</b>", "purple");
      printLine("  <b>ipconfig</b> / <b>ifconfig</b>        Display active attacker IP, adapter settings & VPN routing", "info");
      printLine("  <b>vpn connect &lt;country&gt;</b>     Switch attacker IP to target country (e.g. India, USA, Germany)", "info");
      printLine("  <b>vpn &lt;country&gt;</b>             Direct shortcut to switch country IP (e.g. vpn India)", "info");
      printLine("  <b>vpn list</b>                List all available country exit nodes & public IPs", "info");
      printLine("  <b>vpn status</b>              Show active VPN node, apparent IP & geolocation", "info");
      printLine("  <b>vpn disconnect</b>          Reset VPN connection back to local direct link", "info");
      printLine("  <b>scan target</b>             Probe ports & endpoints on " + API_BASE, "info");
      printLine("");

      printLine("<b style='color:#ff003b;'>[ATTACK SIMULATIONS]</b>", "error");
      printLine("  <b>bruteforce</b>              Execute password dictionary crack against /api/login", "info");
      printLine("  <b>sqli [payload]</b>          Execute SQL Injection against /api/search-customer", "info");
      printLine("  <b>idor [id]</b>               Exploit Broken Object Level Authorization on /api/customer/{id}", "info");
      printLine("  <b>lfi [filepath]</b>          Exploit Local File Inclusion / Path Traversal on /api/download", "info");
      printLine("  <b>ssrf [target_url]</b>       Exploit Server-Side Request Forgery against cloud metadata", "info");
      printLine("  <b>rce [command]</b>           Execute Remote Command Injection against /api/diagnostics/ping", "info");
      printLine("  <b>honeytoken</b>              Test exfiltrated Canary API Key against /api/v1/internal/admin-dump", "info");
      printLine("  <b>xss [payload]</b>           Reflected Cross-Site Scripting probe", "info");
      printLine("  <b>hashlookup</b> / <b>rainbow</b>     Execute precomputed SHA-256 rainbow table matching", "info");
      printLine("");

      printLine("<b style='color:#10b981;'>[FILESYSTEM & EXFILTRATION]</b>", "success");
      printLine("  <b>ls</b> / <b>show files</b>          List files in current virtual filesystem", "info");
      printLine("  <b>cd &lt;dir&gt;</b>                 Change simulated directory (e.g. cd shadow_vault)", "info");
      printLine("  <b>cat &lt;file&gt;</b>               Inspect synthetic file / encrypted database payload", "info");
      printLine("  <b>show records</b>             Display preview of customer order records", "info");
      printLine("  <b>export data</b> / <b>fetch</b>      Exfiltrate database package (triggers honeypot & canary)", "info");
      printLine("");

      printLine("<b style='color:#f59e0b;'>[SYSTEM & AUDIT]</b>", "warning");
      printLine("  <b>status</b>                  Display full diagnostic state, incident ID & telemetry", "info");
      printLine("  <b>whoami</b>                  Display active Kali terminal identity & permissions", "info");
      printLine("  <b>clear</b> / <b>cls</b>             Clear terminal output console", "info");
      printLine("  <b>reset</b>                   Reset all backend alerts, incidents & honeypot state", "info");
      printLine("─────────────────────────────────────────────────────────────────", "dim");
    },

    clear: async () => {
      termOutput.innerHTML = "";
    },

    cls: async () => {
      termOutput.innerHTML = "";
    },

    status: async () => {
      printLine("<b style='color:#00e5ff;'>KALI PENTEST CONSOLE STATUS & TELEMETRY</b>", "cyan");
      printLine("┌─────────────────────────────────────────────────────────────┐", "dim");
      printLine(`│ Target Host:        ${(API_BASE + " (TrapWire Admin)").padEnd(40)}│`, "info");
      printLine(`│ Admin Alert Target: +91 99016 25399 (Live Dispatches)         │`, "success");
      const vpnDesc = state.vpnConnected ? `${state.vpnFlag || '🌐'} ${state.vpnCountry || state.vpnNode} [SPOOFED]` : "DISCONNECTED (Direct)";
      printLine(`│ VPN Circuit:        ${vpnDesc.padEnd(40)}│`, state.vpnConnected ? "cyan" : "dim");
      const activeIp = state.attackerIp || (state.apparentIp || '127.0.0.1').split(' ')[0];
      printLine(`│ Attacker IP:        ${activeIp.padEnd(40)}│`, state.vpnConnected ? "success" : "info");
      printLine(`│ Apparent Route:     ${state.apparentIp.padEnd(40)}│`, "info");
      if (state.vpnConnected) {
        printLine(`│ Geolocation:        ${((state.vpnCity || 'Gateway') + ', ' + (state.vpnCountry || 'Global')).padEnd(40)}│`, "cyan");
        printLine(`│ Gateway ISP:        ${(state.vpnIsp || 'Autonomous Relay').slice(0, 39).padEnd(40)}│`, "dim");
      }
      printLine(`│ Authenticated:      ${(state.isAuthenticated ? "YES (admin)" : "NO (Anonymous)").padEnd(40)}│`, state.isAuthenticated ? "success" : "dim");
      printLine(`│ Session Security:   ${(state.isSuspicious ? "SUSPICIOUS [FLAGGED & ISOLATED]" : "STANDARD").padEnd(40)}│`, state.isSuspicious ? "error" : "info");
      printLine(`│ Honeypot Defense:   ${(state.honeypotActive ? "ACTIVE — DECOY DATASET SERVED" : "ARMED").padEnd(40)}│`, state.honeypotActive ? "error" : "warning");
      printLine(`│ Canary Tracking:    ${(state.canaryArmed ? "ARMED — BEACON READY" : "TRIGGERED / ATTRIBUTED").padEnd(40)}│`, state.canaryArmed ? "warning" : "error");
      printLine(`│ Active Incident ID: ${state.incidentId.padEnd(40)}│`, state.incidentId !== "NONE" ? "error" : "dim");
      printLine("└─────────────────────────────────────────────────────────────┘", "dim");
    },

    whoami: async () => {
      const user = sessionStorage.getItem("kali_user") || "root";
      printLine(`${user}@kali (uid=1000 gid=1000 groups=1000(kali),27(sudo))`, "info");
      printLine("Workstation: KALI-OFFSEC-WORKSTATION-01 [Simulation Sandbox]", "dim");
    },

    pwd: async () => {
      printLine(state.currentDir === "root" ? "/home/kali/workspace" : `/home/kali/workspace/${state.currentDir}`, "info");
    },

    ls: async () => {
      printLine("<b style='color:#00e5ff;'>total 48K</b>", "dim");
      if (state.currentDir === "root") {
        printLine("drwx------ 4 kali kali 4.0K Oct 02 21:00 <b style='color:#38bdf8;'>shadow_vault/</b>", "blue");
        printLine("drwx------ 2 kali kali 4.0K Oct 02 21:00 <b style='color:#38bdf8;'>onion_links/</b>", "blue");
        printLine("drwx------ 3 kali kali 4.0K Oct 02 21:00 <b style='color:#38bdf8;'>malware_kits/</b>", "blue");
        printLine("drwx------ 2 kali kali 4.0K Oct 02 21:00 <b style='color:#38bdf8;'>stolen_creds/</b>", "blue");
        printLine("drwx------ 2 kali kali 4.0K Oct 02 21:00 <b style='color:#38bdf8;'>zero_logs/</b>", "blue");
        printLine("-rw-r--r-- 1 kali kali 12.4M Oct 02 21:10 <b style='color:#ef4444;'>leak_database.enc</b>", "error");
        printLine("-rw-r--r-- 1 kali kali 5.1K  Oct 02 21:12 <b style='color:#e2e8f0;'>session_logs.log</b>", "info");
        printLine("-rw-r--r-- 1 kali kali 2.4K  Oct 02 21:05 <b style='color:#f59e0b;'>vpn_configs.zip</b>", "warning");
      } else {
        const files = VIRTUAL_FS[state.currentDir];
        if (files) {
          printLine("drwx------ 2 kali kali 4.0K Oct 02 21:00 <b style='color:#38bdf8;'>.</b>", "blue");
          printLine("drwx------ 4 kali kali 4.0K Oct 02 21:00 <b style='color:#38bdf8;'>..</b>", "blue");
          for (const [fname, meta] of Object.entries(files)) {
            const color = fname.endsWith(".enc") ? "#ef4444" : (fname.endsWith(".sh") ? "#10b981" : "#e2e8f0");
            printLine(`-rw-r--r-- 1 kali kali ${meta.size.padEnd(6)} Oct 02 21:00 <b style='color:${color};'>${fname}</b>`);
          }
        }
      }
    },

    "show files": async () => {
      await COMMANDS.ls();
    },

    cd: async (args) => {
      const target = args[0] ? args[0].trim().replace(/\/$/, "") : "";
      if (!target || target === "~" || target === "/") {
        state.currentDir = "root";
      } else if (target === "..") {
        state.currentDir = "root";
      } else if (VIRTUAL_FS[target]) {
        state.currentDir = target;
      } else {
        printLine(`bash: cd: ${target}: No such file or directory`, "error");
        return;
      }
      updateUIState();
    },

    cat: async (args) => {
      if (!args[0]) {
        printLine("usage: cat <filename>", "warning");
        return;
      }
      const filename = args[0].trim().replace(/^.*\//, "");
      
      let fileObj = null;
      if (state.currentDir !== "root" && VIRTUAL_FS[state.currentDir] && VIRTUAL_FS[state.currentDir][filename]) {
        fileObj = VIRTUAL_FS[state.currentDir][filename];
      } else {
        for (const dir in VIRTUAL_FS) {
          if (VIRTUAL_FS[dir][filename]) {
            fileObj = VIRTUAL_FS[dir][filename];
            break;
          }
        }
      }

      if (fileObj) {
        printLine(fileObj.content, fileObj.type === "encrypted" ? "error" : "info");
      } else {
        printLine(`cat: ${filename}: No such file or directory`, "error");
      }
    },

    scan: async () => {
      if (typeof window.playBeepSound === "function") window.playBeepSound();
      printLine("<span class='term-tag tag-scan'>[SCAN]</span> Initializing target reconnaissance on " + API_BASE + "...", "purple");
      
      // Send telemetry to company server
      if (typeof window.notifyCompanyServer === "function") {
        window.notifyCompanyServer("port_scan");
      }

      await sleep(300);
      printLine("<span class='term-tag tag-scan'>[SCAN]</span> Sending SYN probes to top service ports...", "dim");
      await sleep(350);

      printLine("PORT     STATE SERVICE      REASON", "cyan");
      printLine("80/tcp   open  http         uvicorn / FastAPI (Company Server)", "success");
      printLine("8000/tcp open  http-alt     TRAPWIRE Application Server", "success");
      printLine("9000/tcp open  http-alt     Kali Linux Pentest Console", "error");
      printLine("443/tcp  filt  https        simulated-waf", "dim");
      printLine("");

      printLine("<span class='term-tag tag-scan'>[SCAN]</span> Target surface discovery:", "info");
      printLine("  ├── <b>POST /api/login</b>       - Authentication Gateway (Form-based)", "cyan");
      printLine("  ├── <b>GET  /company/dashboard</b> - Secured Administration Console", "cyan");
      printLine("  ├── <b>GET  /api/export</b>        - Customer Order Data Exfiltration Endpoint", "cyan");
      printLine("  └── <b>GET  /canary/{token}</b>   - Dynamic Tracking Beacon Endpoint", "warning");
      printLine("<span class='term-tag tag-success'>[+]</span> Reconnaissance complete. Target is reachable and online.", "success");

      if (stepScan) {
        stepScan.className = "step-item completed";
        stepScan.querySelector(".step-circle").textContent = "✓";
      }
    },

    "scan target": async () => {
      await COMMANDS.scan();
    },

    vpn: async (args) => {
      if (!args || args.length === 0) {
        await COMMANDS["vpn status"]();
        return;
      }
      const first = args[0].toLowerCase();
      if (first === "status") {
        await COMMANDS["vpn status"]();
      } else if (first === "disconnect" || first === "stop" || first === "down") {
        await COMMANDS["vpn disconnect"]();
      } else if (first === "list" || first === "nodes" || first === "countries" || first === "ls") {
        await COMMANDS["vpn list"]();
      } else if (first === "connect") {
        const countryQuery = args.slice(1).join(" ").trim() || "Netherlands";
        await COMMANDS["vpn connect"]([countryQuery]);
      } else {
        // Direct country argument: e.g. "vpn India", "vpn USA", "vpn Germany"
        const countryQuery = args.join(" ").trim();
        await COMMANDS["vpn connect"]([countryQuery]);
      }
    },

    "vpn connect": async (args) => {
      const countryQuery = (args && args.length > 0) ? (Array.isArray(args) ? args.join(" ") : String(args)) : "Netherlands";
      if (typeof window.playBeepSound === "function") window.playBeepSound();
      const nodeObj = resolveCountryNode(countryQuery);

      printLine("<span class='term-tag tag-vpn'>[VPN]</span> Initializing encrypted multi-hop tunnel...", "cyan");
      printLine(`[*] Target Exit Node: <b style="color:#00e5ff;">${nodeObj.flag} ${nodeObj.country}</b> (${nodeObj.city})`, "cyan");
      printLine(`[*] Target Country IPv4: <b style="color:#10b981;">${nodeObj.ip}</b>`, "success");
      await sleep(150);

      const hops = [
        { name: "Frankfurt Entry Relay", ip: "45.155.204.12", flag: "🇩🇪" },
        { name: "Zurich Swiss Guard Relay", ip: "185.107.56.23", flag: "🇨🇭" },
        { name: "Offshore Onion Transit", ip: "103.4.17.88", flag: "🧅" },
        { name: `${nodeObj.country} - ${nodeObj.city} Exit Gateway`, ip: nodeObj.ip, flag: nodeObj.flag }
      ];

      for (let i = 0; i < hops.length; i++) {
        const hop = hops[i];
        printLine(`  [${i + 1}/4] Relaying circuit via ${hop.flag} <b>${hop.name}</b> [${hop.ip}]...`, "dim");
        if (typeof window.playKeyClickSound === "function") window.playKeyClickSound();
        await sleep(150);
      }

      state.vpnConnected = true;
      state.vpnCountry = nodeObj.country;
      state.vpnCity = nodeObj.city;
      state.vpnIsp = nodeObj.isp;
      state.vpnFlag = nodeObj.flag;
      state.vpnGateway = nodeObj.gateway || `${nodeObj.ip.split('.').slice(0, 3).join('.')}.1`;
      state.attackerIp = nodeObj.ip;
      state.apparentIp = `${nodeObj.ip} (${nodeObj.country})`;
      state.vpnNode = `${nodeObj.country} (${nodeObj.city})`;

      window.AttackerState = {
        apparentIp: nodeObj.ip,
        attackerIp: nodeObj.ip,
        country: nodeObj.country,
        city: nodeObj.city,
        isp: nodeObj.isp,
        node: state.vpnNode
      };

      if (typeof window.notifyCompanyServer === "function") {
        window.notifyCompanyServer("vpn_hop", {
          node: state.vpnNode,
          ip: nodeObj.ip,
          country: nodeObj.country,
          city: nodeObj.city,
          isp: nodeObj.isp
        });
      }

      if (typeof window.playSuccessSound === "function") window.playSuccessSound();

      printLine(`<span class='term-tag tag-success'>[+]</span> <b>VPN CIRCUIT ESTABLISHED!</b>`, "success");
      printLine(`  ├── Country: <b style="color:#ffffff;">${nodeObj.flag} ${nodeObj.country}</b> (${nodeObj.city})`, "cyan");
      printLine(`  ├── Switched Attacker IP: <b style="color:#00e5ff;font-size:1.15em;">${nodeObj.ip}</b>`, "success");
      printLine(`  ├── Telecom Carrier: <b style="color:#94a3b8;">${nodeObj.isp}</b>`, "dim");
      printLine(`  ├── Subnet Gateway: <code>${state.vpnGateway}</code> [tun0]`, "dim");
      printLine(`  └── Security: <b>WireGuard ChaCha20 / DNS Leak Prevention Active</b>`, "dim");
      printLine("<span class='term-tag tag-warn'>[!]</span> Encrypted tunnel routed. Attacker IP broadcast to Defender SOC & OLED hardware.", "warning");
      printLine("<span class='term-tag tag-info'>[i]</span> Type <b style='color:#00e5ff;'>ipconfig</b> at any time to verify your switched country IP address.", "info");

      if (stepVpn) {
        stepVpn.className = "step-item completed";
        stepVpn.querySelector(".step-circle").textContent = "✓";
      }
      updateUIState();
    },

    "vpn status": async () => {
      const currentIp = state.attackerIp || (state.apparentIp ? state.apparentIp.split(" ")[0].trim() : "127.0.0.1");
      printLine(`<span class='term-tag tag-vpn'>[VPN]</span> Status: <b>${state.vpnConnected ? "CONNECTED [SPOOFED]" : "DISCONNECTED (Direct)"}</b>`, state.vpnConnected ? "success" : "info");
      if (state.vpnConnected) {
        printLine(`  ├── Country Origin:   ${state.vpnFlag || '🌐'} <b style="color:#ffffff;">${state.vpnCountry}</b> (${state.vpnCity})`, "cyan");
        printLine(`  ├── Switched IP:      <b style="color:#00e5ff;font-size:1.1em;">${currentIp}</b>`, "success");
        printLine(`  ├── Default Gateway:  <code>${state.vpnGateway}</code>`, "dim");
        printLine(`  ├── Relay Provider:   ${state.vpnIsp}`, "dim");
        printLine(`  └── Adapter Tunnel:   <b>tun0 (WireGuard / ChaCha20)</b>`, "dim");
        printLine("Type <b style='color:#00e5ff;'>ipconfig</b> to view full network adapter configuration.", "info");
      } else {
        printLine(`  ├── Current IP:       <b style="color:#f59e0b;">${currentIp} (Direct / Exposed)</b>`, "warning");
        printLine("  └── Recommendation:   Type <b style='color:#00e5ff;'>vpn connect India</b> or <b style='color:#00e5ff;'>vpn list</b> to switch IP.", "dim");
      }
    },

    "vpn disconnect": async () => {
      if (typeof window.playBeepSound === "function") window.playBeepSound();
      state.vpnConnected = false;
      state.vpnCountry = null;
      state.vpnCity = null;
      state.vpnIsp = null;
      state.vpnFlag = "🌐";
      state.vpnGateway = "127.0.0.1";
      state.vpnNode = "Disconnected";
      state.attackerIp = "127.0.0.1";
      state.apparentIp = "127.0.0.1 (Direct)";

      window.AttackerState = {
        apparentIp: "127.0.0.1",
        attackerIp: "127.0.0.1",
        country: "Local Direct",
        city: "Localhost",
        isp: "Direct Link",
        node: "Disconnected"
      };

      if (typeof window.notifyCompanyServer === "function") {
        window.notifyCompanyServer("vpn_hop", {
          node: "DIRECT",
          ip: "127.0.0.1",
          country: "Local Direct",
          city: "Localhost",
          isp: "Direct Loopback"
        });
      }

      printLine("<span class='term-tag tag-vpn'>[VPN]</span> Circuit dismantled. Connection reverted to direct local link.", "info");
      printLine("  ├── Attacker IP: <b style='color:#f59e0b;'>127.0.0.1 (Direct Localhost)</b>", "warning");
      printLine("  └── Tunnel Status: <b>INACTIVE</b> — Type <b style='color:#00e5ff;'>ipconfig</b> to inspect adapter.", "dim");
      updateUIState();
    },

    "vpn list": async () => {
      if (typeof window.playBeepSound === "function") window.playBeepSound();
      printLine("<b style='color:#00e5ff;'>AVAILABLE OFFSEC VPN COUNTRY NODES & PUBLIC IPS</b>", "cyan");
      printLine("─────────────────────────────────────────────────────────────────────────────", "dim");
      printLine("Country                     Flag  Gateway City       Assigned Attacker IP   ISP / Network", "cyan");
      printLine("─────────────────────────────────────────────────────────────────────────────", "dim");

      const popular = [
        "india", "united states", "germany", "netherlands", "singapore", "japan",
        "united kingdom", "canada", "france", "australia", "russia", "china",
        "switzerland", "sweden", "brazil", "united arab emirates", "south korea",
        "italy", "spain", "norway", "ireland", "israel", "hong kong", "turkey"
      ];

      for (const k of popular) {
        const node = COUNTRY_NODES[k];
        if (node) {
          const cName = node.country.padEnd(26);
          const city = node.city.padEnd(17);
          const ip = node.ip.padEnd(21);
          const isp = (node.isp || "").slice(0, 22);
          printLine(`${cName}  ${node.flag}   ${city}  <b style="color:#00e5ff;">${ip}</b>  ${isp}`, "info");
        }
      }
      printLine("─────────────────────────────────────────────────────────────────────────────", "dim");
      printLine("Usage: <b>vpn connect &lt;country&gt;</b> (e.g. <code>vpn connect India</code> or <code>vpn USA</code>)", "warning");
      printLine("Note: Any international country name can be specified and will dynamically route.", "dim");
    },

    "vpn countries": async () => {
      await COMMANDS["vpn list"]();
    },

    "vpn nodes": async () => {
      await COMMANDS["vpn list"]();
    },

    connect: async (args) => {
      await COMMANDS["vpn connect"](args);
    },

    ipconfig: async (args) => {
      if (typeof window.playBeepSound === "function") window.playBeepSound();
      const isAll = (args && args[0] && (args[0].toLowerCase() === "/all" || args[0].toLowerCase() === "-all" || args[0].toLowerCase() === "all"));
      const currentIp = state.attackerIp || (state.apparentIp ? state.apparentIp.split(" ")[0].trim() : "127.0.0.1");

      printLine("");
      printLine("<b style='color:#38bdf8;'>Windows IP Configuration</b>", "cyan");
      if (isAll) {
        printLine("   Host Name . . . . . . . . . . . . : KALI-OFFSEC-WORKSTATION", "dim");
        printLine("   Primary Dns Suffix. . . . . . . . : offsec.internal", "dim");
        printLine("   Node Type . . . . . . . . . . . . : Hybrid", "dim");
        printLine("   IP Routing Enabled. . . . . . . . : Yes", "dim");
        printLine("   WINS Proxy Enabled. . . . . . . . : No", "dim");
        printLine("   DNS Suffix Search List. . . . . . : offsec.internal, trapwire.lan", "dim");
        printLine("");
      }

      printLine("Ethernet adapter Local Area Connection (Physical Host Interface):", "info");
      printLine("   Connection-specific DNS Suffix  . : localdomain", "dim");
      printLine("   Link-local IPv6 Address . . . . . : fe80::4921:1a20:5b72:d489%12", "dim");
      printLine("   IPv4 Address. . . . . . . . . . . : 192.168.1.105", "dim");
      printLine("   Subnet Mask . . . . . . . . . . . : 255.255.255.0", "dim");
      printLine("   Default Gateway . . . . . . . . . : 192.168.1.1", "dim");
      printLine("");

      if (state.vpnConnected) {
        const countryName = state.vpnCountry || state.vpnNode;
        const flag = state.vpnFlag || "🌐";
        const city = state.vpnCity || "Gateway";
        const gateway = state.vpnGateway || `${currentIp.split(".").slice(0, 3).join(".")}.1`;
        const dnsSuffix = `${countryName.toLowerCase().replace(/[^a-z0-9]/g, "")}.vpn.offsec.net`;

        printLine(`PPP adapter tun0 (OffSec Anonymity Tunnel - <b style="color:#00e5ff;">${flag} ${countryName}</b>):`, "cyan");
        printLine(`   Connection-specific DNS Suffix  . : ${dnsSuffix}`, "dim");
        printLine("   Description . . . . . . . . . . . : WireGuard/OpenVPN Multi-Hop TAP-Windows Adapter V9", "dim");
        printLine("   Physical Address. . . . . . . . . : 00-FF-A4-89-21-4E", "dim");
        printLine("   DHCP Enabled. . . . . . . . . . . : Yes", "dim");
        printLine("   Autoconfiguration Enabled . . . . : Yes", "dim");
        printLine(`   <b style="color:#10b981;">IPv4 Address (ATTACKER IP) . . . . :</b> <b style="color:#00e5ff;font-size:1.15em;text-decoration:underline;">${currentIp}</b>  <span style="color:#10b981;font-weight:700;">[ASSIGNED COUNTRY IP]</span>`, "success");
        printLine("   Subnet Mask . . . . . . . . . . . : 255.255.255.0", "dim");
        printLine(`   Default Gateway . . . . . . . . . : ${gateway}`, "dim");
        printLine("   DHCP Server . . . . . . . . . . . : 10.8.0.1", "dim");
        printLine("   DNS Servers . . . . . . . . . . . : 1.1.1.1", "dim");
        printLine("                                       8.8.8.8", "dim");
        printLine(`   Country Geolocation . . . . . . . : ${flag} ${countryName} (${city})`, "cyan");
        printLine(`   Carrier / ISP Relay . . . . . . . : ${state.vpnIsp || "Autonomous System"}`, "dim");
        printLine(`   Tunnel Routing Status . . . . . . : <b style="color:#10b981;">ACTIVE (All outbound attacks routed through ${currentIp})</b>`, "success");
      } else {
        printLine("PPP adapter tun0 (OffSec Multi-Hop Tunnel Interface):", "warning");
        printLine("   Media State . . . . . . . . . . . : Media disconnected", "dim");
        printLine("   Connection-specific DNS Suffix  . :", "dim");
        printLine(`   <b style="color:#f59e0b;">IPv4 Address (ATTACKER IP) . . . . :</b> <b style="color:#f59e0b;font-size:1.1em;">${currentIp}</b>  <span style="color:#ef4444;">[DIRECT LOCALHOST / EXPOSED]</span>`, "warning");
        printLine("   Tunnel Routing Status . . . . . . : <b style="color:#ef4444;">DISCONNECTED (Direct link — type 'vpn connect &lt;country&gt;' to spoof IP)</b>", "error");
      }
      printLine("");
      printLine(`[+] Active Attacker Public IP: <b style="color:#00e5ff;">${currentIp}</b> ${state.vpnConnected ? ("(" + (state.vpnFlag || '🌐') + " " + state.vpnCountry + ")") : "[Exposed Local Link]"}`, "cyan");
    },

    "ipconfig /all": async () => {
      await COMMANDS.ipconfig(["/all"]);
    },

    ifconfig: async () => {
      if (typeof window.playBeepSound === "function") window.playBeepSound();
      const currentIp = state.attackerIp || (state.apparentIp ? state.apparentIp.split(" ")[0].trim() : "127.0.0.1");

      printLine("eth0: flags=4163&lt;UP,BROADCAST,RUNNING,MULTICAST&gt;  mtu 1500", "dim");
      printLine("        inet 192.168.1.105  netmask 255.255.255.0  broadcast 192.168.1.255", "dim");
      printLine("        inet6 fe80::4921:1a20:5b72:d489  prefixlen 64  scopeid 0x20&lt;link&gt;", "dim");
      printLine("        ether 08:00:27:d4:89:21  txqueuelen 1000  (Ethernet)", "dim");
      printLine("        RX packets 284192  bytes 194820124 (185.7 MB)", "dim");
      printLine("        TX packets 192841  bytes 84920194 (80.9 MB)", "dim");
      printLine("");

      if (state.vpnConnected) {
        const country = state.vpnCountry || state.vpnNode;
        const flag = state.vpnFlag || "🌐";
        printLine(`tun0: flags=4305&lt;UP,POINTOPOINT,RUNNING,NOARP,MULTICAST&gt;  mtu 1420 (${flag} ${country})`, "cyan");
        printLine(`        <b style="color:#10b981;">inet ${currentIp}</b>  netmask 255.255.255.0  destination ${state.vpnGateway || '10.8.0.1'}`, "success");
        printLine("        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)", "dim");
        printLine("        RX packets 8492  bytes 4829104 (4.6 MB)", "dim");
        printLine("        TX packets 8120  bytes 3910294 (3.7 MB)", "dim");
      } else {
        printLine("lo: flags=73&lt;UP,LOOPBACK,RUNNING&gt;  mtu 65536", "dim");
        printLine(`        <b style="color:#f59e0b;">inet 127.0.0.1</b>  netmask 255.0.0.0`, "warning");
        printLine("        inet6 ::1  prefixlen 128  scopeid 0x10&lt;host&gt;", "dim");
      }
      printLine("");
      printLine(`[+] Active Attacker Public IP: <b style="color:#00e5ff;">${currentIp}</b>`, "cyan");
    },

    ip: async (args) => {
      const sub = (args && args[0]) ? args[0].toLowerCase() : "";
      if (sub === "a" || sub === "addr" || sub === "address") {
        await COMMANDS.ifconfig();
      } else {
        await COMMANDS.ipconfig(args);
      }
    },

    "ip a": async () => {
      await COMMANDS.ifconfig();
    },

    "ip addr": async () => {
      await COMMANDS.ifconfig();
    },

    curl: async (args) => {
      const target = (args && args[0]) ? args[0].toLowerCase() : "";
      const currentIp = state.attackerIp || (state.apparentIp ? state.apparentIp.split(" ")[0].trim() : "127.0.0.1");
      if (target.includes("ifconfig") || target.includes("icanhazip") || target.includes("ipinfo") || target.includes("ipecho")) {
        printLine(currentIp, "success");
      } else {
        printLine(`curl: fetching ${args ? args.join(' ') : 'target'}...`, "dim");
        printLine(`Source IP routed as: ${currentIp}`, "cyan");
      }
    },

    "curl ifconfig.me": async () => {
      const currentIp = state.attackerIp || (state.apparentIp ? state.apparentIp.split(" ")[0].trim() : "127.0.0.1");
      printLine(currentIp, "success");
    },

    "curl icanhazip.com": async () => {
      const currentIp = state.attackerIp || (state.apparentIp ? state.apparentIp.split(" ")[0].trim() : "127.0.0.1");
      printLine(currentIp, "success");
    },

    auth: async () => {
      printLine("<span class='term-tag tag-info'>[AUTH]</span> Testing endpoint reachability: <code>POST " + API_BASE + "/api/login</code>", "info");
      await sleep(200);
      try {
        const res = await fetch(`${API_BASE}/api/login`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ username: "probe", password: "invalid_probe" }),
          credentials: "include"
        });
        printLine(`[AUTH] Gateway response: HTTP ${res.status} Unauthorized`, "warning");
        printLine("[AUTH] Form parameters confirmed: 'username', 'password'", "success");
        printLine("[AUTH] Target authentication portal is ACTIVE and ready for brute-force attack.", "cyan");
      } catch (err) {
        printLine(`[AUTH] Error reaching gateway: ${err.message}`, "error");
      }
    },

    "auth test": async () => {
      await COMMANDS.auth();
    },

    bruteforce: async () => {
      const username = state.targetUser;
      if (typeof window.playAlarmSound === "function") window.playAlarmSound();

      printLine("<span class='term-tag tag-error'>[BRUTEFORCE]</span> Initializing automated credential attack module...", "error");
      printLine(`[+] Target: TRAPWIRE Admin Portal (${API_BASE})`, "cyan");
      printLine(`[+] Target Username: <b>${username}</b>`, "cyan");
      printLine(`[+] Admin Phone Notification Target: <b style="color:#10b981;">+91 99016 25399</b>`, "success");
      printLine(`[*] Loading attack candidate wordlist (${state.wordlist.length} entries)...`, "info");
      printLine("");

      // Notify company server & trigger real SMS to 9901625399
      if (typeof window.notifyCompanyServer === "function") {
        window.notifyCompanyServer("bruteforce_start");
      }

      const decoyPool = ["dragon123", "shadow2024", "monkey99", "qwerty88", "football7", "batman123"];
      const decoys = decoyPool.slice(0, 3 + Math.floor(Math.random() * 2));

      // 1. Rapid decoy attempts
      for (let i = 0; i < decoys.length; i++) {
        const pw = decoys[i];
        printLine(`  [${String(i + 1).padStart(2, '0')}] Trying: "${pw}" .................... <span style="color:#ef4444;">FAILED</span>`, "dim");
        if (typeof window.playKeyClickSound === "function") window.playKeyClickSound();
        await sleep(90);
      }

      // 2. Real attempts against /api/login on Company Server
      let cracked = false;
      let attemptNum = decoys.length;

      for (const pw of state.wordlist) {
        attemptNum++;
        printLine(`  [${String(attemptNum).padStart(2, '0')}] Testing candidate: "${pw}" ...`, "info");
        if (typeof window.playKeyClickSound === "function") window.playKeyClickSound();
        await sleep(220);

        try {
          const currentIp = state.attackerIp || (state.apparentIp ? state.apparentIp.split(" ")[0].trim() : "127.0.0.1");
          const body = new URLSearchParams({ username: username, password: pw });
          const res = await fetch(`${API_BASE}/api/login`, {
            method: "POST",
            body: body,
            headers: {
              "X-Attacker-IP": currentIp,
              "X-VPN-IP": currentIp,
              "X-Attacker-Country": state.vpnCountry || "Unknown"
            },
            credentials: "include"
          });
          const data = await res.json().catch(() => ({}));

          if (res.ok && data.ok) {
            cracked = true;
            state.isAuthenticated = true;
            state.isSuspicious = !!data.suspicious;
            state.honeypotActive = state.isSuspicious;
            state.canaryArmed = true;
            state.incidentId = data.incident_id || ("INC-" + Math.random().toString(16).substring(2, 10).toUpperCase());

            if (typeof window.playSuccessSound === "function") window.playSuccessSound();

            printLine("");
            printLine("╔═══════════════════════════════════════════════════════════════╗", "success");
            printLine("║                CRITICAL CREDENTIAL MATCH FOUND                ║", "success");
            printLine("╠═══════════════════════════════════════════════════════════════╣", "success");
            printLine(`║  USERNAME: ${username.padEnd(49)}║`, "success");
            printLine(`║  PASSWORD: ${pw.padEnd(49)}║`, "success");
            printLine(`║  STATUS:   AUTHENTICATION GRANTED                            ║`, "success");
            printLine("╚═══════════════════════════════════════════════════════════════╝", "success");
            printLine("");

            if (state.isSuspicious) {
              printLine("<span class='term-tag tag-warn'>[!]</span> <b>INTRUSION DETECTION ALERT TRIGGERED:</b>", "warning");
              printLine("  [!] Failed login threshold exceeded (>3 failed attempts).", "warning");
              printLine("  [!] Session classified as: <b style='color:#ef4444;'>SUSPICIOUS (ISOLATED)</b>", "error");
              printLine("  [+] Honeypot Deception Engine activated: Decoy customer dataset deployed.", "cyan");
              printLine("  [+] Embedded Canary Tracking Tokens ARMED.", "cyan");
              printLine(`  [!] Emergency SMS dispatched to Admin: <b>+91 99016 25399</b>`, "success");
              printLine(`  [!] Incident recorded on company defender console: <b>${state.incidentId}</b>`, "error");
            }

            if (stepAuth) {
              stepAuth.className = "step-item completed";
              stepAuth.querySelector(".step-circle").textContent = "✓";
            }
            if (stepHoneypot) {
              stepHoneypot.className = "step-item completed";
              stepHoneypot.querySelector(".step-circle").textContent = "✓";
            }
            updateUIState();
            break;
          } else {
            printLine(`  └─> Result: <span style="color:#ef4444;">AUTHENTICATION FAILED</span> (HTTP 401)`, "error");
          }
        } catch (err) {
          printLine(`  └─> Network Error: ${err.message}`, "error");
        }
      }

      if (!cracked) {
        printLine("[!] Wordlist exhausted without matching credentials.", "warning");
      }
    },

    sqli: async (args) => {
      const payload = args.length ? args.join(" ") : "' UNION SELECT username, password_hash FROM users --";
      if (typeof window.playAlarmSound === "function") window.playAlarmSound();

      const currentIp = state.attackerIp || (state.apparentIp ? state.apparentIp.split(" ")[0].trim() : "127.0.0.1");
      printLine("<span class='term-tag tag-error'>[SQLi]</span> Launching In-Band SQL Injection Exploit...", "error");
      printLine(`[+] Target Endpoint: <code>GET ${API_BASE}/api/search-customer?q=...</code>`, "cyan");
      printLine(`[+] Injected String: <b style="color:#f87171;">${payload}</b>`, "error");
      printLine(`[+] Route IP: <b style="color:#38bdf8;">${currentIp}</b>`, "dim");
      await sleep(250);

      try {
        const res = await fetch(`${API_BASE}/api/search-customer?q=${encodeURIComponent(payload)}`, {
          headers: {
            "X-Attacker-IP": currentIp,
            "X-VPN-IP": currentIp,
            "X-Attacker-Country": state.vpnCountry || "Unknown"
          }
        });
        const json = await res.json();
        
        printLine("[*] HTTP Response 200 OK — Database syntax evaluated.", "dim");
        await sleep(200);
        printLine("╔═══════════════════════════════════════════════════════════════╗", "success");
        printLine("║                SQL INJECTION EXPLOIT SUCCESSFUL               ║", "success");
        printLine("╠═══════════════════════════════════════════════════════════════╣", "success");
        printLine("║  VULNERABILITY: In-Band SQL Injection (CWE-89)                ║", "success");
        printLine("║  DATABASE:      MySQL 8.0.36 (InnoDB Honeypot Isolation)      ║", "success");
        printLine("║  EXPOSED ROWS:  2 Decoy Admin Credentials Extracted           ║", "success");
        printLine("║  TRIPWIRE:      Quarantined to Synthetic Honeypot Records     ║", "warning");
        printLine("║  DPB REPORT:    Preliminary DPDP Statutory Report Auto-Filed  ║", "error");
        printLine("╚═══════════════════════════════════════════════════════════════╝", "success");
        printLine("");
        printLine("Extracted Raw Rows (Decoy Synthetic Hashes):", "cyan");
        if (json.results) {
          json.results.forEach(r => {
            printLine(`  [ROW] USER: <b style="color:#38bdf8;">${r.username}</b> | HASH: <b style="color:#ef4444;">${r.password_hash}</b> | ROLE: ${r.role}`);
          });
        }
      } catch (err) {
        printLine(`[!] Error: ${err.message}`, "error");
      }
    },

    "sql injection": async (args) => {
      await COMMANDS.sqli(args);
    },

    exploit: async (args) => {
      await COMMANDS.sqli(args);
    },

    idor: async (args) => {
      const custId = args[0] || "9901";
      if (typeof window.playAlarmSound === "function") window.playAlarmSound();

      const currentIp = state.attackerIp || (state.apparentIp ? state.apparentIp.split(" ")[0].trim() : "127.0.0.1");
      printLine("<span class='term-tag tag-error'>[IDOR]</span> Launching Broken Object Level Authorization (IDOR) exploit...", "error");
      printLine(`[+] Target Endpoint: <code>GET ${API_BASE}/api/customer/${custId}</code>`, "cyan");
      printLine(`[+] Probing Arbitrary Principal Record: <b style="color:#f59e0b;">CUSTOMER_ID=${custId}</b>`, "warning");
      await sleep(250);

      try {
        const res = await fetch(`${API_BASE}/api/customer/${custId}`, {
          headers: {
            "X-Attacker-IP": currentIp,
            "X-VPN-IP": currentIp,
            "X-Attacker-Country": state.vpnCountry || "Unknown"
          }
        });
        const data = await res.json();
        
        printLine("╔═══════════════════════════════════════════════════════════════╗", "success");
        printLine("║                IDOR / BOLA EXPLOIT SUCCESSFUL                 ║", "success");
        printLine("╠═══════════════════════════════════════════════════════════════╣", "success");
        printLine("║  VULNERABILITY: Broken Object Level Authorization (CWE-639)   ║", "success");
        printLine(`║  EXTRACTED ID:  ${custId.padEnd(46)}║`, "success");
        printLine(`║  NAME:          ${(data.name || "Decoy Principal").padEnd(46)}║`, "success");
        printLine(`║  CITY:          ${(data.city || "Mumbai").padEnd(46)}║`, "success");
        printLine("║  DECEPTION:     Synthetic Profile Served with Canary Token    ║", "warning");
        printLine("║  DPB REPORT:    Preliminary DPDP Incident Report Auto-Filed   ║", "error");
        printLine("╚═══════════════════════════════════════════════════════════════╝", "success");
        printLine("<span class='term-tag tag-warn'>[!]</span> IDOR access quarantined to isolated honeypot customer database.", "warning");
      } catch (err) {
        printLine(`[!] Error: ${err.message}`, "error");
      }
    },

    bola: async (args) => {
      await COMMANDS.idor(args);
    },

    lfi: async (args) => {
      const filePath = args[0] || "../../.env";
      if (typeof window.playAlarmSound === "function") window.playAlarmSound();

      const currentIp = state.attackerIp || (state.apparentIp ? state.apparentIp.split(" ")[0].trim() : "127.0.0.1");
      printLine("<span class='term-tag tag-error'>[LFI]</span> Launching Local File Inclusion / Directory Traversal...", "error");
      printLine(`[+] Target Endpoint: <code>GET ${API_BASE}/api/download?file=${filePath}</code>`, "cyan");
      await sleep(250);

      try {
        const res = await fetch(`${API_BASE}/api/download?file=${encodeURIComponent(filePath)}`, {
          headers: {
            "X-Attacker-IP": currentIp,
            "X-VPN-IP": currentIp,
            "X-Attacker-Country": state.vpnCountry || "Unknown"
          }
        });
        const text = await res.text();
        
        printLine("╔═══════════════════════════════════════════════════════════════╗", "success");
        printLine("║             DIRECTORY TRAVERSAL / LFI SUCCESSFUL              ║", "success");
        printLine("╠═══════════════════════════════════════════════════════════════╣", "success");
        printLine("║  VULNERABILITY: Path Traversal (CWE-22 / CWE-98)              ║", "success");
        printLine(`║  ACCESSED FILE: ${filePath.padEnd(46)}║`, "success");
        printLine("║  TRIPWIRE:      Planted Honeypot Configuration File Returned  ║", "warning");
        printLine("║  HONEYTOKENS:   Planted AWS Canary Keys & DB Credentials      ║", "error");
        printLine("╚═══════════════════════════════════════════════════════════════╝", "success");
        printLine("");
        printLine("Exfiltrated File Content (Planted Honeytokens):", "cyan");
        printLine(`<pre style="color:#a7f3d0;font-size:11px;background:#064e3b;padding:6px;border-radius:4px;">${text}</pre>`);
      } catch (err) {
        printLine(`[!] Error: ${err.message}`, "error");
      }
    },

    traversal: async (args) => {
      await COMMANDS.lfi(args);
    },

    ssrf: async (args) => {
      const targetUrl = args[0] || "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
      if (typeof window.playAlarmSound === "function") window.playAlarmSound();

      const currentIp = state.attackerIp || (state.apparentIp ? state.apparentIp.split(" ")[0].trim() : "127.0.0.1");
      printLine("<span class='term-tag tag-error'>[SSRF]</span> Launching Server-Side Request Forgery Exploit...", "error");
      printLine(`[+] Target Endpoint: <code>GET ${API_BASE}/api/preview-url?url=${targetUrl}</code>`, "cyan");
      printLine(`[+] Probing Internal Resource: <b style="color:#f87171;">${targetUrl}</b>`, "error");
      await sleep(300);

      try {
        const res = await fetch(`${API_BASE}/api/preview-url?url=${encodeURIComponent(targetUrl)}`, {
          headers: {
            "X-Attacker-IP": currentIp,
            "X-VPN-IP": currentIp,
            "X-Attacker-Country": state.vpnCountry || "Unknown"
          }
        });
        const data = await res.json();
        
        printLine("╔═══════════════════════════════════════════════════════════════╗", "success");
        printLine("║             SSRF CLOUD METADATA EXPLOIT SUCCESSFUL            ║", "success");
        printLine("╠═══════════════════════════════════════════════════════════════╣", "success");
        printLine("║  VULNERABILITY: Server-Side Request Forgery (CWE-918)         ║", "success");
        printLine("║  TARGET:        AWS IMDSv2 Cloud Metadata Endpoint            ║", "success");
        printLine(`║  IAM ROLE:      ${(data.RoleName || "TRAPWIRE-DECOY-IAM").padEnd(46)}║`, "success");
        printLine(`║  CANARY KEY:    ${(data.AccessKeyId || "AKIA_TRAPWIRE_CANARY").padEnd(46)}║`, "error");
        printLine("║  DPB REPORT:    Preliminary DPDP Statutory Report Auto-Filed  ║", "error");
        printLine("╚═══════════════════════════════════════════════════════════════╝", "success");
        printLine("");
        printLine("<span class='term-tag tag-warn'>[!]</span> Decoy Cloud IAM Credentials served. Usage triggers instant forensic attribution.", "warning");
      } catch (err) {
        printLine(`[!] Error: ${err.message}`, "error");
      }
    },

    honeytoken: async () => {
      const canaryKey = "AKIA_TRAPWIRE_CANARY_TOKEN_9901";
      if (typeof window.playAlarmSound === "function") window.playAlarmSound();

      const currentIp = state.attackerIp || (state.apparentIp ? state.apparentIp.split(" ")[0].trim() : "127.0.0.1");
      printLine("<span class='term-tag tag-error'>[HONEYTOKEN]</span> Testing exfiltrated Canary API Key against Internal Admin API...", "error");
      printLine(`[+] Target Endpoint: <code>GET ${API_BASE}/api/v1/internal/admin-dump</code>`, "cyan");
      printLine(`[+] Authorization Header: <code>Bearer ${canaryKey}</code>`, "info");
      printLine(`[+] Route IP: <b style="color:#38bdf8;">${currentIp}</b>`, "dim");
      await sleep(300);

      try {
        const res = await fetch(`${API_BASE}/api/v1/internal/admin-dump`, {
          headers: { 
            "Authorization": `Bearer ${canaryKey}`,
            "X-Attacker-IP": currentIp,
            "X-VPN-IP": currentIp,
            "X-Attacker-Country": state.vpnCountry || "Unknown"
          }
        });
        const data = await res.json();
        
        printLine("╔═══════════════════════════════════════════════════════════════╗", "error");
        printLine("║          CANARY HONEYTOKEN DETONATED / ATTRIBUTION FIRED      ║", "error");
        printLine("╠═══════════════════════════════════════════════════════════════╣", "error");
        printLine("║  STATUS:        Canary Token De-Anonymization Activated      ║", "error");
        printLine(`║  INCIDENT ID:   ${(data.forensic_case || "INC-2026-DPB").padEnd(46)}║`, "error");
        printLine(`║  DPB ACK:       ${(data.dpb_ack || "ACK-DPB-2026").padEnd(46)}║`, "success");
        printLine("║  FORENSICS:     Full Attacker IP, ISP & Fingerprint Submitted ║", "success");
        printLine("╚═══════════════════════════════════════════════════════════════╝", "error");
        printLine("<span class='term-tag tag-success'>[+]</span> Statutory Final Breach Report submitted directly to DPB Registry.", "success");
      } catch (err) {
        printLine(`[!] Error: ${err.message}`, "error");
      }
    },

    rce: async (args) => {
      const cmdPayload = args.length ? args.join(" ") : "127.0.0.1; whoami; id";
      if (typeof window.playAlarmSound === "function") window.playAlarmSound();

      const currentIp = state.attackerIp || (state.apparentIp ? state.apparentIp.split(" ")[0].trim() : "127.0.0.1");
      printLine("<span class='term-tag tag-error'>[RCE]</span> Launching Command Injection Exploit against Diagnostics Engine...", "error");
      printLine(`[+] Target Endpoint: <code>GET ${API_BASE}/api/diagnostics/ping?host=...</code>`, "cyan");
      printLine(`[+] Command Payload: <b style="color:#f87171;">${cmdPayload}</b>`, "error");
      printLine(`[+] Route IP: <b style="color:#38bdf8;">${currentIp}</b>`, "dim");
      await sleep(300);

      try {
        const res = await fetch(`${API_BASE}/api/diagnostics/ping?host=${encodeURIComponent(cmdPayload)}`, {
          headers: {
            "X-Attacker-IP": currentIp,
            "X-VPN-IP": currentIp,
            "X-Attacker-Country": state.vpnCountry || "Unknown"
          }
        });
        const data = await res.json();
        
        printLine("╔═══════════════════════════════════════════════════════════════╗", "success");
        printLine("║             COMMAND INJECTION / RCE SUCCESSFUL                ║", "success");
        printLine("╠═══════════════════════════════════════════════════════════════╣", "success");
        printLine("║  VULNERABILITY: OS Command Injection (CWE-78)                 ║", "success");
        printLine("║  SANDBOX:       Trapped in Deception DMZ Container            ║", "warning");
        printLine("║  OUTPUT:        " + (data.output || "uid=0(root)").padEnd(46) + "║", "info");
        printLine("║  DPB REPORT:    Preliminary Statutory Report Auto-Filed       ║", "error");
        printLine("╚═══════════════════════════════════════════════════════════════╝", "success");
        printLine("<span class='term-tag tag-warn'>[!]</span> Command executed inside quarantined deception sandbox container.", "warning");
      } catch (err) {
        printLine(`[!] Error: ${err.message}`, "error");
      }
    },

    cmdi: async (args) => {
      await COMMANDS.rce(args);
    },

    nmap: async () => {
      await COMMANDS.scan();
    },

    dictionary: async () => {
      printLine("<span class='term-tag tag-purple'>[DICTIONARY]</span> Launching dictionary attack simulation...", "purple");
      printLine("[*] Source: rockyou-sample.txt (Top Common Passwords)", "dim");
      await sleep(200);

      const dictWords = ["letmein", "welcome1", "qwertyuiop", "admin2023", "password1", "changeme", "guest123", "root1234"];
      for (let i = 0; i < dictWords.length; i++) {
        printLine(`  [${i + 1}/${dictWords.length}] Dictionary word "${dictWords[i]}" ... <span style="color:#ef4444;">failed (no match)</span>`, "dim");
        await sleep(120);
      }
      printLine("[*] Dictionary space scanned. Real-world systems enforce rate-limiting against dictionary attacks.", "warning");
    },

    hashlookup: async () => {
      printLine("<span class='term-tag tag-warn'>[RAINBOW]</span> Initializing precomputed SHA-256 rainbow table matching...", "warning");
      await sleep(200);

      const hashes = [
        { plain: "123456", hash: "8d969eef6ecad3c29a3a..." },
        { plain: "password", hash: "5e884898da28047151d0..." },
        { plain: "qwerty123", hash: "65e84be33532fb784c48..." },
        { plain: "letmein123", hash: "a94a8fe5ccb19ba61c4c..." },
        { plain: "Admin@2026!", hash: "c897bf1277a06f34e6e6..." }
      ];

      for (const h of hashes) {
        printLine(`  [LOOKUP] ${h.hash}  ==>  <span style="color:#10b981;font-weight:700;">MATCH: "${h.plain}"</span>`, "success");
        await sleep(150);
      }
      printLine("<span class='term-tag tag-success'>[+]</span> Rainbow table reverse resolution complete.", "success");
    },

    rainbow: async () => {
      await COMMANDS.hashlookup();
    },

    "show records": async () => {
      printLine("<b style='color:#00e5ff;'>CURRENTLY AVAILABLE CUSTOMER RECORDS (HONEYPOT VAULT)</b>", "cyan");
      printLine("─────────────────────────────────────────────────────────────────────────────", "dim");
      printLine("Order ID    Customer Name       City        Status       Phone", "cyan");
      printLine("─────────────────────────────────────────────────────────────────────────────", "dim");
      printLine("ORD-749201  Aarav Sharma        Bengaluru   Delivered    +91 90000-00001", "info");
      printLine("ORD-839104  Ananya Reddy        Mumbai      Shipped      +91 90000-00002", "info");
      printLine("ORD-194820  Kabir Verma         Delhi       Processing   +91 90000-00003", "info");
      printLine("ORD-402918  Meera Iyer          Hyderabad   Delivered    +91 90000-00004", "info");
      printLine("ORD-592817  Vivaan Nair         Pune        Delivered    +91 90000-00005", "info");
      printLine("─────────────────────────────────────────────────────────────────────────────", "dim");
      printLine("Use <b>export data</b> to dump full cryptographic export package.", "warning");
    },

    records: async () => {
      await COMMANDS["show records"]();
    },

    export: async () => {
      if (!state.isAuthenticated) {
        printLine("<span class='term-tag tag-error'>[ERROR]</span> Authentication required.", "error");
        printLine("[!] You must authenticate before attempting data export.", "warning");
        printLine("[*] Tip: Run <b>bruteforce --user admin</b> first to crack target credentials.", "cyan");
        return;
      }

      printLine("<span class='term-tag tag-info'>[+]</span> Preparing data export from " + API_BASE + "...", "cyan");
      await sleep(250);
      printLine("<span class='term-tag tag-info'>[+]</span> Enumerating records...", "cyan");
      await sleep(250);
      printLine("<span class='term-tag tag-info'>[+]</span> Encrypting transfer channel...", "cyan");
      await sleep(350);

      // Progressive progress bar animation
      const progressSteps = [
        "▌▌▌▌................",
        "▌▌▌▌▌▌▌▌............",
        "▌▌▌▌▌▌▌▌▌▌▌▌........",
        "▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌....",
        "▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌"
      ];

      const progBox = document.createElement("div");
      progBox.className = "term-progress-box";
      progBox.innerHTML = `<div class="term-progress-bar">${progressSteps[0]}</div><div class="term-progress-status">→ EXFILTRATING DATA (0%)</div>`;
      termOutput.appendChild(progBox);
      scrollToBottom();

      for (let i = 0; i < progressSteps.length; i++) {
        await sleep(250);
        const pct = ((i + 1) / progressSteps.length * 100).toFixed(0);
        progBox.innerHTML = `<div class="term-progress-bar">${progressSteps[i]}</div><div class="term-progress-status">→ EXFILTRATING DATA (${pct}%)</div>`;
        scrollToBottom();
      }

      await sleep(300);
      printLine("<span class='term-tag tag-success'>[+]</span> Records discovered: 14", "success");
      await sleep(200);
      printLine("<span class='term-tag tag-success'>[+]</span> Export package generated: <code>customer_export.json</code>", "success");
      await sleep(200);

      // Fetch actual backend export
      let payload = null;
      try {
        const currentIp = state.attackerIp || (state.apparentIp ? state.apparentIp.split(" ")[0].trim() : "127.0.0.1");
        const res = await fetch(`${API_BASE}/api/export`, {
          credentials: "include",
          headers: {
            "X-Attacker-IP": currentIp,
            "X-VPN-IP": currentIp,
            "X-Attacker-Country": state.vpnCountry || "Unknown"
          }
        });
        payload = await res.json();

        // Download JSON file locally
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "customer_export.json";
        a.click();
      } catch (err) {
        console.error("Export fetch error:", err);
      }

      // ASCII SUCCESS BANNER
      const asciiBanner = `
<div class="term-success-banner">
<pre>
███████╗██╗   ██╗ ██████╗ ██████╗███████╗███████╗███████╗
██╔════╝██║   ██║██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝
███████╗██║   ██║██║     ██║     █████╗  █████╗  ███████╗
╚════██║██║   ██║██║     ██║     ██╔══╝  ██╔══╝  ╚════██║
███████║╚██████╔╝╚██████╗╚██████╗███████╗███████╗███████║
╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝╚══════╝╚══════╝╚══════╝

                DATA EXPORT SUCCESSFUL
</pre>
</div>`;
      printRaw(asciiBanner);

      printLine("<span class='term-tag tag-success'>[+]</span> <b>SIMULATED DATA ACQUIRED</b>", "success");
      printLine("<span class='term-tag tag-info'>[+]</span> RECORDS: 14", "info");
      printLine("<span class='term-tag tag-honey'>[+]</span> <b>HONEYPOT TRIGGER: ACTIVE</b> (All personal data SHA-256 hashed & synthetic)", "error");
      printLine(`<span class='term-tag tag-warn'>[+]</span> INCIDENT ID: <b>${state.incidentId}</b>`, "warning");
      printLine("<span class='term-tag tag-error'>[!]</span> <b>DEFENDER ALERT: GENERATED</b> (Logged to Company Security Center & DPB Registry)", "error");
      printLine("<span class='term-tag tag-success'>[!]</span> <b>SMS NOTIFICATION DISPATCHED</b> to Admin (+91 99016 25399)", "success");
      printLine("");

      if (stepExport) {
        stepExport.className = "step-item completed";
        stepExport.querySelector(".step-circle").textContent = "✓";
      }

      // Trigger Canary Token phone-home beacon
      if (payload && Array.isArray(payload) && payload[0] && payload[0]._tracking_invoice_url) {
        const trackingUrl = payload[0]._tracking_invoice_url;
        printLine("<span class='term-tag tag-warn'>[*]</span> Opening simulated invoice preview...", "dim");
        
        setTimeout(() => {
          const iframe = document.createElement("iframe");
          iframe.style.display = "none";
          iframe.src = trackingUrl;
          document.body.appendChild(iframe);
          
          state.canaryArmed = false;
          if (stepCanary) {
            stepCanary.className = "step-item completed";
            stepCanary.querySelector(".step-circle").textContent = "✓";
          }
          updateUIState();
          printLine("<span class='term-tag tag-error'>[CANARY BEACON]</span> <b>Canary tracking token triggered!</b>", "error");
          printLine("  [!] Attacker de-anonymized via honeypot invoice tracking link.", "warning");
          printLine("  [!] Device fingerprint captured -> Submitted to simulated Data Protection Board.", "info");
          printLine("  [!] Emergency SMS update dispatched to +91 99016 25399.", "success");
        }, 1000);
      }
    },

    "export data": async () => {
      await COMMANDS.export();
    },

    "fetch records": async () => {
      await COMMANDS.export();
    },

    exfiltrate: async () => {
      await COMMANDS.export();
    }
  };

  // --- Input Command Handling ---

  async function handleCommand(cmdRaw) {
    const cmd = cmdRaw.trim();
    if (!cmd) return;

    // Echo input prompt
    const promptUser = sessionStorage.getItem("kali_user") || "root";
    const promptPathStr = state.currentDir === "root" ? "~/workspace" : `~/workspace/${state.currentDir}`;
    printLine(`<span style="color:#10b981;">${promptUser}</span><span style="color:#94a3b8;">@</span><span style="color:#ef4444;">kali</span>:<span style="color:#818cf8;">${promptPathStr}</span><span style="color:#ff003b;">#</span> ${cmd}`);

    // Add to history
    state.history.push(cmd);
    state.historyIndex = state.history.length;

    const parts = cmd.split(/\s+/);
    const primary = parts[0].toLowerCase();
    const args = parts.slice(1);

    // Multi-word matches
    const twoWord = (parts[0] + " " + (parts[1] || "")).toLowerCase();

    if (COMMANDS[cmd.toLowerCase()]) {
      await COMMANDS[cmd.toLowerCase()](args);
    } else if (COMMANDS[twoWord]) {
      await COMMANDS[twoWord](parts.slice(2));
    } else if (COMMANDS[primary]) {
      await COMMANDS[primary](args);
    } else {
      printLine(`bash: command not found: ${primary}. Type <b style="color:#00e5ff;">help</b> for available commands.`, "error");
    }
  }

  // --- Event Listeners ---

  if (termInput) {
    termInput.addEventListener("keydown", async (e) => {
      if (e.key === "Enter") {
        const val = termInput.value;
        termInput.value = "";
        await handleCommand(val);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        if (state.historyIndex > 0) {
          state.historyIndex--;
          termInput.value = state.history[state.historyIndex];
        }
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        if (state.historyIndex < state.history.length - 1) {
          state.historyIndex++;
          termInput.value = state.history[state.historyIndex];
        } else {
          state.historyIndex = state.history.length;
          termInput.value = "";
        }
      } else if (e.key === "l" && e.ctrlKey) {
        e.preventDefault();
        await COMMANDS.clear();
      }
    });
  }

  // Terminal tool buttons
  document.getElementById("termClearBtn")?.addEventListener("click", () => COMMANDS.clear());
  document.getElementById("termHelpBtn")?.addEventListener("click", () => COMMANDS.help());

  // Quick suggestion chips
  document.querySelectorAll(".sugg-chip, .atk-quick-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const cmd = btn.dataset.cmd;
      if (cmd) {
        handleCommand(cmd);
      }
    });
  });

  // Filesystem click-to-view
  document.querySelectorAll(".fs-file-item").forEach((item) => {
    item.addEventListener("click", () => {
      const fname = item.dataset.file;
      if (fname) {
        handleCommand(`cat ${fname}`);
      }
    });
  });

  document.querySelectorAll(".fs-dir-title").forEach((dir) => {
    dir.addEventListener("click", () => {
      const dname = dir.dataset.dir;
      if (dname) {
        handleCommand(`cd ${dname}`);
      }
    });
  });

  // Auto-focus input on click anywhere in terminal
  terminalBody?.addEventListener("click", () => {
    termInput?.focus();
  });

  // Init
  printWelcomeBanner();
  updateUIState();

})();
