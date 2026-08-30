"""
TRAPWIRE demo backend.

Run with:  uvicorn app.main:app --reload --port 8000
Then open: http://127.0.0.1:8000/

Two portals, one shared "brain":
  /company/...   -> the defender/admin side (login, dashboard, security center)
  /attacker/...  -> the simulated attacker side (VPN picker, brute-force console)

Everything here runs against this same local server / same in-memory data.
There is no real external network attack surface -- the "brute force" only
ever calls this app's own /api/login endpoint, and the "canary" only ever
pings this app's own /canary/{token} endpoint.
"""
import time
import uuid
import random

import requests
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import (HTMLResponse, JSONResponse, RedirectResponse,
                                Response, StreamingResponse)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app import state, data, reports, dpb

app = FastAPI(title="TRAPWIRE Demo")
app.add_middleware(SessionMiddleware, secret_key="trapwire-capstone-demo-secret-change-me")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
app.include_router(dpb.router)

REAL_CUSTOMERS = data.generate_customers(14)

VPN_NODES = [
    {"label": "Netherlands - Amsterdam", "fake_ip": "185.220.101.45"},
    {"label": "Singapore", "fake_ip": "103.253.24.19"},
    {"label": "USA - New York", "fake_ip": "198.51.100.77"},
    {"label": "Germany - Frankfurt", "fake_ip": "45.155.204.12"},
]


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def mock_geolocate(ip: str) -> dict:
    """Best-effort real lookup (if the machine running this has internet
    access to ip-api.com); falls back to a clearly-labeled simulated
    result so the demo still works completely offline."""
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=1.5)
        if resp.ok:
            j = resp.json()
            if j.get("status") == "success":
                return {
                    "isp": j.get("isp", "Unknown ISP"),
                    "city": j.get("city", ""),
                    "country": j.get("country", ""),
                }
    except Exception:
        pass
    return {"isp": "Simulated-ISP (offline demo)", "city": "Unknown", "country": "Unknown"}


async def auto_submit_report(stage: str):
    """Auto-generate the breach PDF from current state, then submit it to
    the (simulated) Data Protection Board portal and record the
    acknowledgement it issues back."""
    if not state.BREACH:
        return
    pdf_bytes = reports.build_breach_report_pdf(state.BREACH, state.ALERTS, state.CANARY_HITS, stage=stage)
    filename = reports.save_submitted_report(pdf_bytes, state.BREACH["incident_id"], stage)

    ack = dpb.receive_submission(pdf_bytes, {
        "incident_id": state.BREACH["incident_id"],
        "stage": stage,
        "company_name": "TrapWire Pvt Ltd",
        "attacker_ip": state.BREACH.get("download_ip") or state.BREACH.get("attacker_ip"),
        "attacker_isp": state.BREACH.get("download_isp"),
        "detected_at": state.BREACH.get("detected_at"),
    })

    record = {
        "incident_id": state.BREACH["incident_id"],
        "stage": stage,
        "filename": filename,
        "submitted_at": time.time(),
        "ack_number": ack["ack_number"],
        "ack_status": ack["status"],
    }
    state.SUBMITTED_REPORTS.append(record)
    label = "Preliminary" if stage == "preliminary" else "Final"
    alert = state.new_alert(
        f"{label} breach report submitted to the Data Protection Board (simulated). "
        f"Acknowledged — Ack No: {ack['ack_number']}",
        level="critical",
        meta=record,
    )
    await broadcast_alert(alert)


async def broadcast_alert(alert: dict):
    dead = []
    for ws in state.ADMIN_SOCKETS:
        try:
            await ws.send_json(alert)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in state.ADMIN_SOCKETS:
            state.ADMIN_SOCKETS.remove(ws)


# ---------------------------------------------------------------- landing --
@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# --------------------------------------------------------------- company --
@app.get("/company/login", response_class=HTMLResponse)
def company_login_page(request: Request):
    return templates.TemplateResponse("company_login.html", {"request": request})


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
                f"Unauthorized login succeeded after {failed} failed attempts "
                f"(source IP {ip}). Session isolated to decoy data.",
                level="critical",
                meta={"ip": ip, "incident_id": incident_id},
            )
            await broadcast_alert(alert)
        else:
            alert = state.new_alert(f"Admin '{username}' logged in normally.", level="info")
            await broadcast_alert(alert)

        return JSONResponse({"ok": True, "suspicious": suspicious})

    state.LOGIN_ATTEMPTS[ip] = state.LOGIN_ATTEMPTS.get(ip, 0) + 1
    return JSONResponse({"ok": False}, status_code=401)


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
    })


@app.get("/api/alerts")
def api_alerts(request: Request):
    if not request.session.get("authenticated") or request.session.get("suspicious"):
        return JSONResponse([], status_code=403)
    return JSONResponse(list(reversed(state.ALERTS[-50:])))


@app.get("/api/export")
async def api_export(request: Request):
    if not request.session.get("authenticated"):
        return JSONResponse({"error": "not authenticated"}, status_code=401)

    suspicious = request.session.get("suspicious", False)
    if suspicious:
        token = request.session.get("canary_token") or str(uuid.uuid4())
        base = str(request.base_url).rstrip("/")
        payload = data.generate_honeypot_export(base, token, n=14)

        # Capture attribution at the moment of download itself -- the
        # server always sees the real connecting IP regardless of any
        # client-side VPN display.
        ip = client_ip(request)
        geo = mock_geolocate(ip)
        state.BREACH.update({
            "download_ip": ip,
            "download_isp": geo["isp"],
            "download_user_agent": request.headers.get("user-agent", "unknown"),
            "download_time": time.time(),
        })

        alert = state.new_alert(
            "Flagged session attempted to export customer data. "
            "Decoy dataset (with tracking token) served instead of real data.",
            level="critical",
        )
        await broadcast_alert(alert)

        # Automatically generate + 'submit' the preliminary breach report
        await auto_submit_report(stage="preliminary")
    else:
        payload = REAL_CUSTOMERS

    filename = "customer_export.json"
    return JSONResponse(payload, headers={
        "Content-Disposition": f"attachment; filename={filename}"
    })


@app.get("/canary/{token}")
async def canary_hit(token: str, request: Request):
    """This is the 'phone home' step. In the real world this would be a
    tracking link/web-bug inside the leaked document. Hitting this URL is
    what deanonymizes the attacker -- no code runs on the attacker's
    machine beyond ordinary JavaScript in the one browser tab they/their
    own UI already opened to preview the file, same as any analytics
    script on any normal webpage."""
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
    alert = state.new_alert(
        f"Canary token triggered! Attacker de-anonymized -> IP {ip}, ISP {geo['isp']}. "
        f"Gathering device details...",
        level="critical",
        meta=hit,
    )
    await broadcast_alert(alert)

    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Loading document…</title></head>
<body style="font-family:sans-serif;color:#94a3b8;background:#0f172a;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
<p>Preparing preview…</p>
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
    """Receives the client-side fingerprint details gathered by the
    canary beacon page above, merges them into the matching hit record,
    and (now that attribution is as complete as it'll get) auto-submits
    the final breach report."""
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
            f"Device fingerprint captured -> Screen {hit['screen']}, "
            f"Timezone {hit['timezone']}, Platform {hit['platform']}.",
            level="critical",
            meta=hit,
        )
        await broadcast_alert(alert)

    await auto_submit_report(stage="final")
    return JSONResponse({"ok": True})


@app.post("/api/report")
def api_report(request: Request):
    if not request.session.get("authenticated") or request.session.get("suspicious"):
        return JSONResponse({"error": "not authorized"}, status_code=403)
    if not state.BREACH:
        return JSONResponse({"error": "no incident recorded yet"}, status_code=400)

    pdf_bytes = reports.build_breach_report_pdf(state.BREACH, state.ALERTS, state.CANARY_HITS)
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=DPDP_Breach_Report.pdf"},
    )


@app.get("/api/submitted-reports")
def api_submitted_reports(request: Request):
    if not request.session.get("authenticated") or request.session.get("suspicious"):
        return JSONResponse([], status_code=403)
    return JSONResponse(list(reversed(state.SUBMITTED_REPORTS)))


@app.get("/api/submitted-reports/{filename}")
def download_submitted_report(filename: str, request: Request):
    if not request.session.get("authenticated") or request.session.get("suspicious"):
        return JSONResponse({"error": "not authorized"}, status_code=403)
    path = reports.SUBMITTED_REPORTS_DIR / filename
    if not path.exists() or path.parent != reports.SUBMITTED_REPORTS_DIR:
        return JSONResponse({"error": "not found"}, status_code=404)
    return StreamingResponse(
        iter([path.read_bytes()]),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/api/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/company/login")


@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    await websocket.accept()
    if not websocket.session.get("authenticated") or websocket.session.get("suspicious"):
        # Confirmed: no alert data is ever sent here -- this socket is
        # closed before it's added to ADMIN_SOCKETS below, so a flagged
        # session can never receive a broadcast. Using an explicit policy
        # violation code (rather than a generic close) makes that intent
        # unambiguous on the wire too.
        await websocket.close(code=4003, reason="unauthorized")
        return
    state.ADMIN_SOCKETS.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in state.ADMIN_SOCKETS:
            state.ADMIN_SOCKETS.remove(websocket)


# -------------------------------------------------------------- attacker --
@app.get("/attacker", response_class=HTMLResponse)
def attacker_portal(request: Request):
    return templates.TemplateResponse("attacker_portal.html", {
        "request": request,
        "vpn_nodes": VPN_NODES,
        "wordlist": state.ATTACK_WORDLIST,
        "target_username": state.ADMIN_USERNAME,
    })


@app.get("/api/reset-demo")
def reset_demo():
    """Handy endpoint to reset all in-memory state between demo runs."""
    state.reset_all()
    dpb.reset()
    return JSONResponse({"ok": True})
