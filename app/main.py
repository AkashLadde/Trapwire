"""
TRAPWIRE — Main Enterprise Defender Server & DPDP Compliance Engine (Server 1)
Runs on http://127.0.0.1:8000
Manages Admin SOC Dashboard, Honeypot Deception Engine, Canary Token Tracking,
DPB Statutory Compliance Reporting, Real-Time WebSocket Alerts, MySQL Storage,
and Out-of-Band Admin SMS Alerts to 9901625399 (+91 99016 25399).
"""

import time
import uuid
import random
import os
import requests
from typing import Optional

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import (HTMLResponse, JSONResponse, RedirectResponse,
                                Response, StreamingResponse)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app import state, data, reports, dpb, database
from app.services import sms_service, hardware_service
from app.core.network import COUNTRY_VPN_REGISTRY, KNOWN_COUNTRY_IPS

# Initialize Database (MySQL with SQLite automatic fallback)
database.init_db()

app = FastAPI(title="TRAPWIRE Defender & DPDP Compliance Engine")

# Enable CORS so the independent Attacker Portal (Port 9000) can interact with API endpoints
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(SessionMiddleware, secret_key="trapwire-capstone-demo-secret-change-me")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
app.include_router(dpb.router)

REAL_CUSTOMERS = data.generate_customers(14)

VPN_NODES = [
    {"label": "India - Mumbai", "country": "India", "fake_ip": "103.152.112.45"},
    {"label": "USA - New York", "country": "United States", "fake_ip": "198.51.100.77"},
    {"label": "Netherlands - Amsterdam", "country": "Netherlands", "fake_ip": "185.220.101.45"},
    {"label": "Germany - Frankfurt", "country": "Germany", "fake_ip": "45.155.204.12"},
    {"label": "Singapore", "country": "Singapore", "fake_ip": "103.253.24.19"},
    {"label": "Japan - Tokyo", "country": "Japan", "fake_ip": "103.4.17.88"},
    {"label": "United Kingdom - London", "country": "United Kingdom", "fake_ip": "185.220.101.5"},
    {"label": "Canada - Montreal", "country": "Canada", "fake_ip": "198.50.200.41"},
    {"label": "France - Paris", "country": "France", "fake_ip": "51.255.45.10"},
    {"label": "Australia - Sydney", "country": "Australia", "fake_ip": "139.99.130.20"},
    {"label": "Russia - Moscow", "country": "Russia", "fake_ip": "95.173.136.25"},
    {"label": "Switzerland - Zurich", "country": "Switzerland", "fake_ip": "185.107.56.23"},
]


# Global cache for host machine public network intelligence
REAL_PUBLIC_IP_CACHE: Optional[str] = None
REAL_PUBLIC_GEO_CACHE: Optional[dict] = None


def get_real_network_intel() -> tuple[str, dict]:
    """Resolves real public IP and ISP of the running host with robust caching."""
    global REAL_PUBLIC_IP_CACHE, REAL_PUBLIC_GEO_CACHE
    if REAL_PUBLIC_IP_CACHE and REAL_PUBLIC_GEO_CACHE:
        return REAL_PUBLIC_IP_CACHE, REAL_PUBLIC_GEO_CACHE
    try:
        resp = requests.get("http://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query", timeout=2.0)
        if resp.ok:
            data = resp.json()
            if data.get("status") == "success":
                REAL_PUBLIC_IP_CACHE = data.get("query", "127.0.0.1")
                REAL_PUBLIC_GEO_CACHE = {
                    "isp": data.get("isp", "Local Telecom Provider"),
                    "city": data.get("city", "Mumbai"),
                    "country": data.get("country", "India"),
                    "region": data.get("regionName", "Maharashtra"),
                    "org": data.get("org", data.get("isp", "Internet Service Provider")),
                    "as": data.get("as", "AS55836"),
                    "timezone": data.get("timezone", "Asia/Kolkata")
                }
                return REAL_PUBLIC_IP_CACHE, REAL_PUBLIC_GEO_CACHE
    except Exception:
        pass
    
    # Fallback to high-fidelity simulated enterprise IP & ISP if offline
    REAL_PUBLIC_IP_CACHE = "152.58.21.144"
    REAL_PUBLIC_GEO_CACHE = {
        "isp": "Reliance Jio Infocomm Ltd (Fiber Broadband)",
        "city": "Mumbai",
        "country": "India",
        "region": "Maharashtra",
        "org": "Reliance Jio Infocomm",
        "as": "AS55836 Jio Broadband",
        "timezone": "Asia/Kolkata"
    }
    return REAL_PUBLIC_IP_CACHE, REAL_PUBLIC_GEO_CACHE


def client_ip(request: Request) -> str:
    # 1. Check direct simulated VPN headers
    vpn_ip = request.headers.get("x-attacker-ip") or request.headers.get("x-vpn-ip")
    if vpn_ip:
        return vpn_ip.split(" ")[0].strip()
    # 2. Check X-Forwarded-For
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    # 3. If request originates from Kali Pentest Console (port 9000), use active attacker VPN IP
    host = request.client.host if request.client else "127.0.0.1"
    if host in ("127.0.0.1", "localhost", "::1", "unknown"):
        origin = request.headers.get("origin", "")
        referer = request.headers.get("referer", "")
        if (":9000" in origin or ":9000" in referer) and state.BREACH.get("attacker_ip"):
            return state.BREACH.get("attacker_ip")
        pub_ip, _ = get_real_network_intel()
        return pub_ip
    return host


def mock_geolocate(ip: str, hint_country: Optional[str] = None, hint_city: Optional[str] = None, hint_isp: Optional[str] = None) -> dict:
    """Best-effort real ISP & Geo lookup with instant country registry matching."""
    pub_ip, pub_geo = get_real_network_intel()
    if ip in ("127.0.0.1", "localhost", "::1", "unknown", pub_ip):
        return pub_geo

    # 1. Match against known VPN Country IP registry
    if ip in KNOWN_COUNTRY_IPS:
        entry = KNOWN_COUNTRY_IPS[ip]
        return {
            "isp": entry["isp"],
            "city": entry["city"],
            "country": entry["country"],
            "org": entry["org"],
            "region": entry["region"],
            "as": entry["as"],
        }

    # 2. Check if a direct country hint was provided in the telemetry packet
    if hint_country:
        q = hint_country.strip().lower()
        for k, v in COUNTRY_VPN_REGISTRY.items():
            if q == k or q in v["aliases"]:
                return {
                    "isp": hint_isp or v["isp"],
                    "city": hint_city or v["city"],
                    "country": v["country"],
                    "org": v["org"],
                    "region": v["region"],
                    "as": v["as"],
                }
        return {
            "isp": hint_isp or f"{hint_country.title()} Offshore VPN Relay",
            "city": hint_city or f"{hint_country.title()} Gateway",
            "country": hint_country.title(),
            "org": f"{hint_country.title()} Autonomous Transit",
            "region": f"{hint_country.title()} Region",
            "as": "AS60068",
        }

    # 3. Live online IP intelligence lookup
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=1.8)
        if resp.ok:
            j = resp.json()
            if j.get("status") == "success":
                return {
                    "isp": j.get("isp", "Unknown ISP"),
                    "city": j.get("city", "Unknown City"),
                    "country": j.get("country", "Unknown Country"),
                    "org": j.get("org", j.get("isp", "Unknown Org")),
                    "region": j.get("regionName", ""),
                    "as": j.get("as", "")
                }
    except Exception:
        pass

    # 4. Fallback default
    return {
        "isp": "Tor Exit Relay / Offshore Proxy (OffSec Network)",
        "city": "Amsterdam",
        "country": "Netherlands",
        "org": "DataCamp Limited - Anonymous Relay",
        "region": "North Holland",
        "as": "AS60068"
    }


async def auto_submit_report(stage: str = "preliminary", reason: str = "Intrusion detected"):
    """
    Auto-generates statutory breach PDF report with full forensic metadata,
    submits it directly to the Data Protection Board (DPB) registry,
    and returns acknowledgement record to broadcast live.
    """
    if not state.BREACH.get("incident_id"):
        state.BREACH["incident_id"] = "INC-" + uuid.uuid4().hex[:8].upper()
    if not state.BREACH.get("detected_at"):
        state.BREACH["detected_at"] = time.time()
        
    pdf_bytes = reports.build_breach_report_pdf(state.BREACH, state.ALERTS, state.CANARY_HITS, stage=stage)
    filename = reports.save_submitted_report(pdf_bytes, state.BREACH["incident_id"], stage)

    ack = dpb.receive_submission(pdf_bytes, {
        "incident_id": state.BREACH["incident_id"],
        "stage": stage,
        "company_name": "TrapWire Pvt Ltd",
        "attacker_ip": state.BREACH.get("download_ip") or state.BREACH.get("attacker_ip"),
        "attacker_isp": state.BREACH.get("download_isp") or state.BREACH.get("attacker_isp"),
        "detected_at": state.BREACH.get("detected_at"),
        "reason": reason
    })

    record = {
        "incident_id": state.BREACH["incident_id"],
        "stage": stage,
        "filename": filename,
        "submitted_at": time.time(),
        "ack_number": ack["ack_number"],
        "ack_status": ack["status"],
        "download_url": f"/api/submitted-reports/{filename}",
        "dpb_url": f"/dpb/submission/{ack['ack_number']}",
        "attacker_ip": state.BREACH.get("attacker_ip"),
        "attacker_isp": state.BREACH.get("attacker_isp"),
    }
    state.SUBMITTED_REPORTS.append(record)
    label = "Preliminary" if stage == "preliminary" else "Final Statutory"
    
    alert = state.new_alert(
        f"📄 STATUTORY DPDP BREACH REPORT AUTO-SUBMITTED TO DATA PROTECTION BOARD ({label}). "
        f"Official Ack ID: {ack['ack_number']} — All evidence timestamped and sealed.",
        level="critical",
        meta=record,
    )
    await broadcast_alert(alert)
    return record


async def broadcast_alert(alert: dict):
    """Broadcasts alert to connected admin WebSockets, saves to database, and directly dispatches to physical ESP32 hardware."""
    # 1. Save to Database
    try:
        database.db_save_alert(alert)
    except Exception as e:
        print(f"[DB LOG ERROR] {e}")

    # 2. Push via WebSocket to active Admin consoles
    dead = []
    for ws in state.ADMIN_SOCKETS:
        try:
            await ws.send_json(alert)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in state.ADMIN_SOCKETS:
            state.ADMIN_SOCKETS.remove(ws)

    # 3. Direct Hardware Dispatch to ESP32 on COM7 (OLED HUD, Piezo Buzzer & Blue LED Strobe)
    try:
        hw = hardware_service.get_hardware_controller()
        hw.dispatch_alert(alert)
    except Exception as e:
        print(f"[HARDWARE DISPATCH ERROR] {e}")


# ---------------------------------------------------------------- landing --
@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "company_url": "http://127.0.0.1:8000/company/login",
        "attacker_url": "http://127.0.0.1:9000/"
    })


# --------------------------------------------------------------- company --
@app.get("/company/login", response_class=HTMLResponse)
def company_login_page(request: Request):
    return templates.TemplateResponse("company_login.html", {"request": request})


# -------------------------------------------------------------- attacker --
@app.get("/attacker/login", response_class=HTMLResponse)
def attacker_login_page(request: Request):
    return templates.TemplateResponse("attacker_login.html", {
        "request": request,
        "target_api_base": "http://127.0.0.1:8000",
        "target_username": "admin"
    })


@app.get("/attacker", response_class=HTMLResponse)
@app.get("/attacker/console", response_class=HTMLResponse)
def attacker_console_page(request: Request):
    return templates.TemplateResponse("attacker_portal.html", {
        "request": request,
        "target_username": "admin",
        "wordlist": ["123456", "password", "admin123", "admin@123", "Welcome@123", "qwerty123", "Admin@2026!", "letmein123"],
        "vpn_nodes": VPN_NODES,
        "show_login": False,
        "target_api_base": "http://127.0.0.1:8000"
    })


@app.post("/api/login")
async def api_login(request: Request):
    form = await request.form()
    username = (form.get("username") or "").strip()
    password = (form.get("password") or "").strip()
    ip = client_ip(request)

    if username == state.ADMIN_USERNAME and password == state.ADMIN_PASSWORD:
        failed = state.LOGIN_ATTEMPTS.get(ip, 0)
        suspicious = failed >= 3
        request.session["authenticated"] = True
        request.session["suspicious"] = suspicious
        request.session["username"] = username
        state.LOGIN_ATTEMPTS[ip] = 0

        if suspicious:
            token = str(uuid.uuid4())
            request.session["canary_token"] = token
            incident_id = "INC-" + uuid.uuid4().hex[:8].upper()
            state.BREACH.update({
                "incident_id": incident_id,
                "detected_at": time.time(),
                "attacker_ip": ip,
            })
            alert = state.new_alert(
                f"🚨 INTRUSION CONFIRMED: Suspicious login succeeded after {failed} failed attempts "
                f"(Source IP: {ip}, Target: '{username}'). Deception engaged: session quarantined to honeypot decoy dataset.",
                level="critical",
                meta={"ip": ip, "incident_id": incident_id, "attempt": failed, "type": "suspicious_login"},
            )
            await broadcast_alert(alert)
        else:
            alert = state.new_alert(f"Admin '{username}' logged in normally from {ip}.", level="info", meta={"suppress_sms": True})
            await broadcast_alert(alert)

        return JSONResponse({"ok": True, "suspicious": suspicious, "incident_id": state.BREACH.get("incident_id")})

    failed = state.LOGIN_ATTEMPTS.get(ip, 0) + 1
    state.LOGIN_ATTEMPTS[ip] = failed
    level = "critical" if failed >= 3 else "warning"
    
    alert_msg = f"⚠️ INTRUSION ATTEMPT: Failed authentication #{failed} on user '{username}' from IP {ip}. Honeypot deception monitoring active."
    alert = state.new_alert(
        alert_msg,
        level=level,
        meta={"ip": ip, "target_user": username, "attempt": failed, "type": "failed_login", "timestamp": time.time()},
    )
    await broadcast_alert(alert)
    return JSONResponse({"ok": False, "attempts": failed, "suspicious": failed >= 3}, status_code=401)


@app.get("/company/dashboard", response_class=HTMLResponse)
def company_dashboard(request: Request):
    if not request.session.get("authenticated"):
        return RedirectResponse("/company/login")

    suspicious = request.session.get("suspicious", False)

    if suspicious:
        records = data.generate_honeypot_view(n=14)
        for r in records:
            r["aadhaar_display"] = data.mask_aadhaar(r["aadhaar"])
            r["pan_display"] = data.mask_pan(r["pan"])
            r["card_display"] = data.mask_card(r["card_last4"])
            r["phone_display"] = r["phone"]
            r["email_display"] = r["email"]
    else:
        records = []
        for r in REAL_CUSTOMERS:
            rr = dict(r)
            rr["aadhaar_display"] = data.mask_aadhaar(r["aadhaar"])
            rr["pan_display"] = data.mask_pan(r["pan"])
            rr["card_display"] = data.mask_card(r["card_last4"])
            rr["phone_display"] = r["phone"]
            rr["email_display"] = r["email"]
            records.append(rr)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "records": records,
        "suspicious": suspicious,
        "username": request.session.get("username", "admin"),
        "admin_phone": sms_service.ADMIN_PHONE_FORMATTED,
        "raw_admin_phone": sms_service.ADMIN_PHONE_NUMBER
    })


@app.get("/api/alerts")
def api_alerts(request: Request):
    if not request.session.get("authenticated") or request.session.get("suspicious"):
        return JSONResponse(list(reversed(state.ALERTS[-50:])))
    return JSONResponse(list(reversed(state.ALERTS[-50:])))


@app.post("/api/attacker-session-event")
async def attacker_session_event(request: Request):
    """
    Recognizes all attacker activities performed from Port 9000:
    - Attacker attempting to login
    - Attacker successfully logging in
    - Type of attack performed (Brute Force, SQL Injection, Recon, VPN Hop)
    - Data extracted by attacker (Honeypot Decoy exfiltration, Canary token hits)
    Collects real-time IP, ISP, Geo-location, dispatches SMS to 9901625399,
    and automatically files statutory breach reports with the Data Protection Board.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
    
    event_type = body.get("event", "session_start")
    raw_ip = body.get("ip") or client_ip(request)
    # Clean simulated IP display strings if present
    clean_ip = raw_ip.split(" ")[0].strip()
    hint_c = body.get("country")
    hint_city = body.get("city")
    hint_isp = body.get("isp")
    geo = mock_geolocate(clean_ip, hint_country=hint_c, hint_city=hint_city, hint_isp=hint_isp)
    
    user = body.get("user", "kali")
    tool = body.get("tool", "Kali Pentest Console")
    payload = body.get("payload", "")
    target = body.get("target", "/api/orders")
    
    # Update global breach forensic tracker with maximum attacker telemetry
    state.BREACH.update({
        "attacker_ip": clean_ip,
        "attacker_isp": geo["isp"],
        "attacker_location": f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}",
        "user_agent": request.headers.get("user-agent", "Mozilla/5.0 (Kali Linux x86_64) OffSec/2026"),
        "last_activity": time.time(),
        "attack_type": event_type,
        "payload": payload,
        "target": target
    })
    
    ack_info = None

    if event_type in ("terminal_login_attempt", "login_attempt"):
        entered_pass = body.get("password_attempt", "******")
        msg = f"⚠️ ATTACKER LOGIN ATTEMPT: Operator '{user}' attempting authentication on Kali Console (Passkey: '{entered_pass}') from IP {clean_ip} [{geo['isp']}]."
        level = "warning"
        
    elif event_type in ("terminal_login_success", "terminal_login"):
        msg = f"🚨 HACKER WORKSTATION ACTIVE: Attacker '{user}' successfully logged in to OffSec Pentest Console from IP {clean_ip} [{geo['isp']}, {geo.get('city','')}] targeting TrapWire APIs."
        level = "critical"
        
    elif event_type in ("bruteforce_start", "brute_force"):
        msg = f"💥 BRUTE-FORCE INTRUSION DETECTED: Dictionary credential attack launched from {clean_ip} [{geo['isp']}] targeting Admin account."
        level = "critical"
        if not state.BREACH.get("incident_id"):
            state.BREACH["incident_id"] = "INC-" + uuid.uuid4().hex[:8].upper()
            state.BREACH["detected_at"] = time.time()
        ack_info = await auto_submit_report(stage="preliminary", reason=f"Brute-force credential attack from {clean_ip}")
        
    elif event_type in ("sqli_attack", "sql_injection"):
        payload_str = payload or "UNION SELECT username, password FROM users --"
        msg = f"💉 SQL INJECTION EXPLOIT DETECTED: Malicious payload `{payload_str}` executed against `{target}` from IP {clean_ip} [{geo['isp']}]. Deception quarantine engaged."
        level = "critical"
        if not state.BREACH.get("incident_id"):
            state.BREACH["incident_id"] = "INC-" + uuid.uuid4().hex[:8].upper()
            state.BREACH["detected_at"] = time.time()
        ack_info = await auto_submit_report(stage="preliminary", reason=f"SQL Injection payload '{payload_str}' from {clean_ip}")
        
    elif event_type in ("idor_attack", "bola_attack"):
        obj_target = target or "/api/customer/9901"
        msg = f"🔍 IDOR / BOLA EXPLOIT DETECTED: Sequential object parameter traversal `{obj_target}` intercepted from IP {clean_ip} [{geo['isp']}]. Decoy customer record served."
        level = "critical"
        if not state.BREACH.get("incident_id"):
            state.BREACH["incident_id"] = "INC-" + uuid.uuid4().hex[:8].upper()
            state.BREACH["detected_at"] = time.time()
        ack_info = await auto_submit_report(stage="preliminary", reason=f"IDOR object traversal on '{obj_target}' from {clean_ip}")

    elif event_type in ("ssrf_attack", "ssrf_exploit"):
        ssrf_target = payload or "http://169.254.169.254/latest/meta-data/"
        msg = f"🛰️ SERVER-SIDE REQUEST FORGERY (SSRF) BLOCKED: Cloud metadata probe `{ssrf_target}` neutralized from IP {clean_ip} [{geo['isp']}]. Decoy IAM token served."
        level = "critical"
        if not state.BREACH.get("incident_id"):
            state.BREACH["incident_id"] = "INC-" + uuid.uuid4().hex[:8].upper()
            state.BREACH["detected_at"] = time.time()
        ack_info = await auto_submit_report(stage="preliminary", reason=f"SSRF cloud metadata probe from {clean_ip}")

    elif event_type in ("rce_attack", "cmdi_attack", "command_injection"):
        cmd_str = payload or "whoami; cat /etc/passwd"
        msg = f"💣 COMMAND INJECTION (RCE) INTERCEPTED: Arbitrary command string `{cmd_str}` quarantined in sandbox from IP {clean_ip} [{geo['isp']}]."
        level = "critical"
        if not state.BREACH.get("incident_id"):
            state.BREACH["incident_id"] = "INC-" + uuid.uuid4().hex[:8].upper()
            state.BREACH["detected_at"] = time.time()
        ack_info = await auto_submit_report(stage="preliminary", reason=f"RCE command execution '{cmd_str}' from {clean_ip}")

    elif event_type in ("honeytoken_hit", "canary_key_used", "leaked_secret"):
        key_str = payload or "AKIA_TRAPWIRE_CANARY_TOKEN_9901"
        msg = f"🎯 CANARY SECRET / API KEY LEAK DETECTED: Decoy credential `{key_str}` utilized by unauthorized actor at IP {clean_ip} [{geo['isp']}]."
        level = "critical"
        if not state.BREACH.get("incident_id"):
            state.BREACH["incident_id"] = "INC-" + uuid.uuid4().hex[:8].upper()
            state.BREACH["detected_at"] = time.time()
        ack_info = await auto_submit_report(stage="final", reason=f"Leaked canary API key utilized by {clean_ip}")

    elif event_type in ("data_exfiltration", "export"):
        files = body.get("files", "customer_export.json (14 PII records)")
        msg = f"🚨 DATA EXFILTRATION DETECTED: Attacker at {clean_ip} [{geo['isp']}] extracted `{files}`. Decoy honeypot dataset served with active Canary tripwires."
        level = "critical"
        state.BREACH.update({
            "download_ip": clean_ip,
            "download_isp": geo["isp"],
            "download_time": time.time(),
        })
        ack_info = await auto_submit_report(stage="preliminary", reason=f"Decoy customer database exfiltration by {clean_ip}")
        
    elif event_type in ("xss_attack", "xss_exploit"):
        xss_payload = payload or "<script>alert(document.cookie)</script>"
        msg = f"⚡ CROSS-SITE SCRIPTING (XSS) INTERCEPTED: Malicious payload `{xss_payload}` blocked from IP {clean_ip} [{geo['isp']}]."
        level = "warning"

    elif event_type in ("traversal_attack", "path_traversal", "lfi_attack"):
        trav_path = payload or "/etc/shadow"
        msg = f"📂 PATH TRAVERSAL / LFI PROBE: Unauthorized directory enumeration `{trav_path}` intercepted from IP {clean_ip} [{geo['isp']}]."
        level = "warning"

    elif event_type in ("vpn_hop", "vpn_switch"):
        new_node = body.get("node") or (f"{geo['country']} - {geo['city']}" if geo.get("country") else "Netherlands - Amsterdam")
        msg = f"🌐 ATTACKER VPN SPOOFING: Adversary switched routing tunnel to `{new_node}` (Apparent IP: {clean_ip} [{geo['isp']}])."
        level = "warning"
        
    elif event_type in ("port_scan", "recon"):
        msg = f"🔍 PORT RECONNAISSANCE PROBE: Network port scan on ports 80/8000/443/2222 detected from IP {clean_ip} [{geo['isp']}]."
        level = "warning"
        
    elif event_type in ("malware_exec", "exploit_runner"):
        script = body.get("script", "payloads.sh")
        msg = f"🛡️ EXPLOIT EXECUTION ATTEMPT: Benign test script `{script}` neutralized by Honeypot Deception Sandbox from {clean_ip} [{geo['isp']}]."
        level = "warning"

    else:
        msg = f"🛡️ ATTACKER TELEMETRY EVENT: '{tool}' activity observed from {clean_ip} [{geo['isp']}]."
        level = "warning"
        
    alert_meta = {
        "ip": clean_ip,
        "attacker_ip": clean_ip,
        "isp": geo["isp"],
        "city": geo.get("city", ""),
        "country": geo.get("country", ""),
        "org": geo.get("org", geo["isp"]),
        "type": event_type,
        "user": user,
        "tool": tool,
        "payload": payload,
        "target": target,
        "timestamp": time.time()
    }
    if ack_info:
        alert_meta["ack_number"] = ack_info["ack_number"]
        alert_meta["download_url"] = ack_info["download_url"]
        alert_meta["dpb_url"] = ack_info["dpb_url"]

    alert = state.new_alert(msg, level=level, meta=alert_meta)
    await broadcast_alert(alert)
    return JSONResponse({
        "ok": True, 
        "alert_id": alert["id"], 
        "resolved_ip": clean_ip, 
        "resolved_isp": geo["isp"],
        "resolved_location": f"{geo.get('city', '')}, {geo.get('country', '')}",
        "dpb_ack": ack_info["ack_number"] if ack_info else None,
        "dpb_compliance": "AUTOMATED_REPORT_DISPATCHED" if ack_info else "STANDBY"
    })


# ------------------------------------------------------------- Interactive Honeypots --
@app.get("/api/search-customer")
@app.post("/api/search-customer")
async def api_search_customer(request: Request, q: str = ""):
    """SQL Injection Honeypot endpoint."""
    ip = client_ip(request)
    geo = mock_geolocate(ip)
    sqli_indicators = ["union", "select", "'", "--", "/*", "1=1", "drop", "sleep(", "schema"]
    q_lower = q.lower()
    
    is_sqli = any(ind in q_lower for ind in sqli_indicators)
    if is_sqli:
        msg = f"💉 SQL INJECTION DETECTED: Payload `{q}` submitted to `/api/search-customer` from IP {ip} [{geo['isp']}]. Deception quarantine engaged."
        if not state.BREACH.get("incident_id"):
            state.BREACH["incident_id"] = "INC-" + uuid.uuid4().hex[:8].upper()
            state.BREACH["detected_at"] = time.time()
        ack_info = await auto_submit_report(stage="preliminary", reason=f"SQLi on /api/search-customer with payload '{q}'")
        alert = state.new_alert(msg, level="critical", meta={
            "ip": ip, "attacker_ip": ip, "isp": geo["isp"], "type": "sqli_attack", "payload": q,
            "target": "/api/search-customer", "ack_number": ack_info.get("ack_number") if ack_info else None
        })
        await broadcast_alert(alert)
        # Return decoy honeypot results
        return JSONResponse({
            "status": "success",
            "query": q,
            "vulnerability_detected": True,
            "quarantine": "HONEYPOT_DECEPTION_ENGAGED",
            "results": [
                {"id": 1, "username": "admin", "password_hash": "c897bf1277a06f34e6e66cf533b769ea8d407670733d3d622f6d2f36b6d51012", "role": "DECOY_ADMIN"},
                {"id": 2, "username": "finance_mgr", "password_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "role": "DECOY_STAFF"}
            ]
        })
    # Normal search
    results = [c for c in REAL_CUSTOMERS if q.lower() in c.get("name", "").lower() or q.lower() in c.get("city", "").lower()]
    return JSONResponse({"status": "success", "query": q, "results": results})


@app.get("/api/customer/{customer_id}")
@app.get("/api/orders/{customer_id}")
async def api_customer_idor(customer_id: str, request: Request):
    """Broken Object Level Authorization (IDOR / BOLA) Honeypot."""
    ip = client_ip(request)
    geo = mock_geolocate(ip)
    
    # Any access to IDs >= 15 or containing ORD-99/ORD-74 triggers IDOR honeypot detection
    msg = f"🔍 IDOR / BOLA VIOLATION: Unauthorized access to customer ID `{customer_id}` from IP {ip} [{geo['isp']}]."
    if not state.BREACH.get("incident_id"):
        state.BREACH["incident_id"] = "INC-" + uuid.uuid4().hex[:8].upper()
        state.BREACH["detected_at"] = time.time()
    ack_info = await auto_submit_report(stage="preliminary", reason=f"IDOR access on customer ID '{customer_id}'")
    alert = state.new_alert(msg, level="critical", meta={
        "ip": ip, "attacker_ip": ip, "isp": geo["isp"], "type": "idor_attack", "target": f"/api/customer/{customer_id}",
        "ack_number": ack_info.get("ack_number") if ack_info else None
    })
    await broadcast_alert(alert)

    # Return decoy customer record
    token = str(uuid.uuid4())
    base = str(request.base_url).rstrip("/")
    decoy = data.generate_customers(1)[0]
    decoy["id"] = customer_id
    decoy["_security_status"] = "HONEYPOT_RECORD_SERVED"
    decoy["_tracking_invoice_url"] = f"{base}/canary/{token}"
    return JSONResponse(decoy)


@app.get("/api/download")
@app.get("/api/view-document")
async def api_download_honeypot(request: Request, file: str = "document.pdf"):
    """LFI / Path Traversal Honeypot endpoint."""
    ip = client_ip(request)
    geo = mock_geolocate(ip)
    file_lower = file.lower()
    
    if ".." in file or "/etc/" in file_lower or ".env" in file_lower or "passwd" in file_lower or "shadow" in file_lower:
        msg = f"📂 PATH TRAVERSAL / LFI EXPLOIT: Unauthorized traversal query `{file}` intercepted from IP {ip} [{geo['isp']}]."
        if not state.BREACH.get("incident_id"):
            state.BREACH["incident_id"] = "INC-" + uuid.uuid4().hex[:8].upper()
            state.BREACH["detected_at"] = time.time()
        ack_info = await auto_submit_report(stage="preliminary", reason=f"Path traversal query '{file}'")
        alert = state.new_alert(msg, level="critical", meta={
            "ip": ip, "attacker_ip": ip, "isp": geo["isp"], "type": "traversal_attack", "payload": file,
            "target": f"/api/download?file={file}", "ack_number": ack_info.get("ack_number") if ack_info else None
        })
        await broadcast_alert(alert)
        
        # Return decoy honeypot .env file with planted honeytokens
        decoy_env = """# TRAPWIRE PRODUCTION ENVIRONMENT CONFIG (DECOY HONEYPOT)
DATABASE_URL=mysql://admin:DecoyPass2026!@127.0.0.1:3306/production_db
SECRET_KEY=trapwire-canary-secret-deception-jwt-key
AWS_ACCESS_KEY_ID=AKIA_TRAPWIRE_CANARY_TOKEN_9901
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYCANARY9901KEY
DPDP_COMPLIANCE_MODE=ENFORCED
"""
        return Response(content=decoy_env, media_type="text/plain")
    return Response(content="[PDF DOCUMENT CONTENT - SAMPLE ONLY]", media_type="text/plain")


@app.get("/api/preview-url")
@app.get("/api/fetch-webhook")
async def api_ssrf_honeypot(request: Request, url: str = "http://example.com"):
    """Server-Side Request Forgery (SSRF) Honeypot endpoint."""
    ip = client_ip(request)
    geo = mock_geolocate(ip)
    url_lower = url.lower()
    
    if any(target in url_lower for target in ["169.254.169.254", "localhost", "127.0.0.1", "0.0.0.0", "metadata"]):
        msg = f"🛰️ SSRF ATTACK DETECTED: Probing internal/metadata URI `{url}` from IP {ip} [{geo['isp']}]."
        if not state.BREACH.get("incident_id"):
            state.BREACH["incident_id"] = "INC-" + uuid.uuid4().hex[:8].upper()
            state.BREACH["detected_at"] = time.time()
        ack_info = await auto_submit_report(stage="preliminary", reason=f"SSRF probe to '{url}'")
        alert = state.new_alert(msg, level="critical", meta={
            "ip": ip, "attacker_ip": ip, "isp": geo["isp"], "type": "ssrf_attack", "payload": url,
            "target": f"/api/preview-url?url={url}", "ack_number": ack_info.get("ack_number") if ack_info else None
        })
        await broadcast_alert(alert)
        
        # Return decoy cloud metadata with canary credentials
        return JSONResponse({
            "Code": "Success",
            "LastUpdated": "2026-10-03T12:00:00Z",
            "Type": "AWS-HMAC",
            "AccessKeyId": "AKIA_TRAPWIRE_CANARY_TOKEN_9901",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYCANARY9901KEY",
            "Token": "canary-session-token-trapwire-decoy",
            "RoleName": "TRAPWIRE-DECOY-IAM-ROLE",
            "_honeypot_note": "Canary token deployed. Any use of these credentials triggers immediate forensic attribution."
        })
    return JSONResponse({"status": "preview_generated", "target_url": url, "http_status": 200})


@app.get("/api/v1/internal/admin-dump")
async def api_canary_key_honeypot(request: Request):
    """Exposed Canary API Key / Honeytoken Verification endpoint."""
    ip = client_ip(request)
    geo = mock_geolocate(ip)
    auth_header = request.headers.get("authorization", "") or request.headers.get("x-api-key", "")
    
    msg = f"🎯 CANARY HONEYTOKEN UTILIZED: Leaked secret `{auth_header}` submitted from IP {ip} [{geo['isp']}]. High-confidence de-anonymization recorded."
    if not state.BREACH.get("incident_id"):
        state.BREACH["incident_id"] = "INC-" + uuid.uuid4().hex[:8].upper()
        state.BREACH["detected_at"] = time.time()
    ack_info = await auto_submit_report(stage="final", reason=f"Canary API key '{auth_header}' used by {ip}")
    alert = state.new_alert(msg, level="critical", meta={
        "ip": ip, "attacker_ip": ip, "isp": geo["isp"], "type": "honeytoken_hit", "payload": auth_header,
        "target": "/api/v1/internal/admin-dump", "ack_number": ack_info.get("ack_number") if ack_info else None
    })
    await broadcast_alert(alert)
    return JSONResponse({
        "status": "HONEYTOKEN_TRIGGERED",
        "deception_status": "ATTACKER_DE_ANONYMIZED",
        "forensic_case": state.BREACH.get("incident_id"),
        "dpb_ack": ack_info.get("ack_number") if ack_info else None
    })


@app.get("/api/diagnostics/ping")
async def api_rce_honeypot(request: Request, host: str = "127.0.0.1"):
    """Command Injection / RCE Honeypot endpoint."""
    ip = client_ip(request)
    geo = mock_geolocate(ip)
    
    if any(char in host for char in [";", "|", "&", "`", "$", "(", ")"]):
        msg = f"💣 COMMAND INJECTION (RCE) INTERCEPTED: Payload `{host}` quarantined from IP {ip} [{geo['isp']}]."
        if not state.BREACH.get("incident_id"):
            state.BREACH["incident_id"] = "INC-" + uuid.uuid4().hex[:8].upper()
            state.BREACH["detected_at"] = time.time()
        ack_info = await auto_submit_report(stage="preliminary", reason=f"Command injection payload '{host}'")
        alert = state.new_alert(msg, level="critical", meta={
            "ip": ip, "attacker_ip": ip, "isp": geo["isp"], "type": "rce_attack", "payload": host,
            "target": f"/api/diagnostics/ping?host={host}", "ack_number": ack_info.get("ack_number") if ack_info else None
        })
        await broadcast_alert(alert)
        return JSONResponse({
            "command": f"ping -c 1 {host}",
            "status": "quarantined_sandbox_output",
            "output": "root@trapwire-honeypot-dmz:~# id\nuid=0(root) gid=0(root) groups=0(root) [DECOY ENVIRONMENT]"
        })
    return JSONResponse({"command": f"ping -c 1 {host}", "output": f"64 bytes from {host}: icmp_seq=1 ttl=64 time=0.042 ms"})


@app.get("/api/export")
async def api_export(request: Request):
    if not request.session.get("authenticated"):
        # For testing / demo simplicity allow export if flagged as suspicious
        pass

    suspicious = request.session.get("suspicious", True)
    if suspicious:
        token = request.session.get("canary_token") or str(uuid.uuid4())
        base = str(request.base_url).rstrip("/")
        payload = data.generate_honeypot_export(base, token, n=14)

        ip = client_ip(request)
        geo = mock_geolocate(ip)
        state.BREACH.update({
            "download_ip": ip,
            "download_isp": geo["isp"],
            "download_user_agent": request.headers.get("user-agent", "unknown"),
            "download_time": time.time(),
        })

        alert = state.new_alert(
            f"🚨 EXFILTRATION ATTEMPT DETECTED: Flagged session from IP {ip} ({geo['isp']}) downloaded customer dataset. "
            f"Decoy honeypot dataset with active canary tracking token served instead of real data.",
            level="critical",
            meta={"ip": ip, "isp": geo["isp"], "token": token, "type": "data_exfiltration"}
        )
        await broadcast_alert(alert)

        # Automatically generate + submit the preliminary breach report
        await auto_submit_report(stage="preliminary")
    else:
        payload = REAL_CUSTOMERS

    filename = "customer_export.json"
    return JSONResponse(payload, headers={
        "Content-Disposition": f"attachment; filename={filename}"
    })


@app.get("/canary/{token}")
async def canary_hit(token: str, request: Request):
    """Canary tracking link phone-home beacon."""
    ip = client_ip(request)
    geo = mock_geolocate(ip)
    hit = {
        "token": token,
        "ip": ip,
        "isp": geo["isp"],
        "city": geo["city"],
        "country": geo["country"],
        "user_agent": request.headers.get("user-agent", "unknown"),
        "timestamp": time.time(),
        "screen": None, "timezone": None, "language": None,
        "platform": None, "cores": None,
    }
    state.CANARY_HITS.append(hit)
    
    # Save hit to MySQL
    try:
        conn = database.get_mysql_connection()
        if conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO canary_hits (token, ip, isp, user_agent, triggered_at) VALUES (%s, %s, %s, %s, %s)",
                    (token, ip, geo["isp"], hit["user_agent"], hit["timestamp"])
                )
            conn.commit()
            conn.close()
    except Exception:
        pass

    alert = state.new_alert(
        f"🎯 CANARY TOKEN TRIGGERED: Attacker de-anonymized! Source IP: {ip}, ISP: {geo['isp']}, Location: {geo['city']}, {geo['country']}. Gathering forensic device telemetry...",
        level="critical",
        meta=hit,
    )
    await broadcast_alert(alert)

    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Loading document…</title></head>
<body style="font-family:sans-serif;color:#94a3b8;background:#0f172a;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
<p>Preparing document preview…</p>
<script>
  const info = {{
    screen: screen.width + 'x' + screen.height,
    color_depth: screen.colorDepth,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    language: navigator.language,
    platform: navigator.platform || navigator.userAgentData?.platform || 'unknown',
    cores: navigator.hardwareConcurrency || 'unknown'
  }};
  fetch("/api/canary-details/{token}", {{
    method: "POST",
    headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify(info)
  }});
</script>
</body></html>"""
    return HTMLResponse(content=html)


@app.post("/api/canary-details/{token}")
async def canary_details(token: str, request: Request):
    body = await request.json()
    hit = next((h for h in reversed(state.CANARY_HITS) if h["token"] == token), None)
    if hit:
        hit.update({
            "screen": body.get("screen"),
            "color_depth": body.get("color_depth"),
            "timezone": body.get("timezone"),
            "language": body.get("language"),
            "platform": body.get("platform"),
            "cores": body.get("cores"),
        })
        alert = state.new_alert(
            f"📱 FORENSIC ATTRIBUTION COMPLETE: Device fingerprint captured -> Screen {hit['screen']}, Timezone {hit['timezone']}, OS {hit['platform']}, CPU Cores: {hit['cores']}.",
            level="critical",
            meta=hit,
        )
        await broadcast_alert(alert)

    await auto_submit_report(stage="final")
    return JSONResponse({"ok": True})


@app.post("/api/report")
def api_report(request: Request):
    if not state.BREACH:
        # Create a mock breach record if none exists for manual testing
        state.BREACH.update({
            "incident_id": "INC-" + uuid.uuid4().hex[:8].upper(),
            "detected_at": time.time() - 3600,
            "attacker_ip": "185.220.101.45",
            "download_ip": "185.220.101.45",
            "download_isp": "Tor Exit Node (Amsterdam)",
            "download_user_agent": "Mozilla/5.0 (Kali Linux x86_64)",
            "download_time": time.time() - 1800,
        })

    pdf_bytes = reports.build_breach_report_pdf(state.BREACH, state.ALERTS, state.CANARY_HITS)
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=DPDP_Breach_Report.pdf"},
    )


@app.get("/api/submitted-reports")
def api_submitted_reports(request: Request):
    return JSONResponse(list(reversed(state.SUBMITTED_REPORTS)))


@app.get("/api/submitted-reports/{filename}")
def download_submitted_report(filename: str, request: Request):
    path = reports.SUBMITTED_REPORTS_DIR / filename
    if not path.exists() or path.parent != reports.SUBMITTED_REPORTS_DIR:
        return JSONResponse({"error": "not found"}, status_code=404)
    return StreamingResponse(
        iter([path.read_bytes()]),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ------------------------------------------------------------- hardware --
@app.get("/api/hardware/status")
def hardware_status():
    """Returns status of integrated IoT hardware (NodeMCU ESP32, SSD1306 OLED, Active Buzzer)."""
    hw = hardware_service.get_hardware_controller()
    st = hw.get_status()
    port_label = f"{st['port']} (115200 baud)" if st["port"] else "Auto-scanning COM7"
    return JSONResponse({
        "status": "ONLINE" if st["connected"] else "ARMED",
        "nodes": [
            {
                "id": "NODE-01",
                "name": "NodeMCU ESP32 Threat Controller",
                "type": "Physical Intrusion Response MCU",
                "port": port_label,
                "status": "CONNECTED" if st["connected"] else "SEARCHING_COM_PORT",
                "last_trigger": "Active Listening" if st["connected"] else "Standing by"
            },
            {
                "id": "NODE-02",
                "name": "0.96\" I2C OLED Display (SSD1306)",
                "type": "Live Attacker IP & Alert HUD",
                "port": "GPIO 21 (SDA) / GPIO 22 (SCL)",
                "status": "ARMED",
                "resolution": "128x64 px"
            },
            {
                "id": "NODE-03",
                "name": "Active Piezo Buzzer",
                "type": "Physical Breach Audio Alarm",
                "port": "GPIO 19 (Signal)",
                "status": "ARMED",
                "tone": "2400 Hz Alarm Chirp"
            }
        ],
        "active_alarm": len(state.ALERTS) > 0 and state.ALERTS[-1].get("level") == "critical"
    })


@app.post("/api/hardware/trigger-test")
async def hardware_trigger_test():
    """Manual hardware test to trigger the physical siren and OLED on NodeMCU ESP32."""
    alert = state.new_alert(
        "⚡ HARDWARE INTEGRATION TEST: NodeMCU ESP32 Threat Siren & OLED Pulse Activated.",
        level="critical",
        meta={"attacker_ip": "185.220.101.45 (TEST)", "isp": "Hardware Diagnostic Test", "ip": "185.220.101.45"}
    )
    await broadcast_alert(alert)
    return JSONResponse({"ok": True, "message": "Hardware critical alarm test triggered successfully on COM7."})


@app.get("/api/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/company/login")


@app.websocket("/ws/alerts")
@app.websocket("/api/threat-stream")
async def ws_alerts(websocket: WebSocket):
    await websocket.accept()
    state.ADMIN_SOCKETS.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in state.ADMIN_SOCKETS:
            state.ADMIN_SOCKETS.remove(websocket)


# -------------------------------------------------------------- attacker --
@app.get("/attacker", response_class=HTMLResponse)
@app.get("/attacker/login", response_class=HTMLResponse)
def attacker_portal_redirect(request: Request):
    # Direct to port 9000 attacker console
    return RedirectResponse(url="http://127.0.0.1:9000/")


@app.get("/api/reset-demo")
def reset_demo():
    state.reset_all()
    dpb.reset()
    return JSONResponse({"ok": True})


if __name__ == "__main__":
    import uvicorn
    print("[COMPANY SERVER] Starting Defender Portal on http://127.0.0.1:8000 ...")
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
