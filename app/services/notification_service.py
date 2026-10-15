"""
TRAPWIRE — Unified Notification & Security Alert Dispatcher
Centralizes in-app WebSocket threat broadcasts and database logging.
Note: Out-of-band phone/SMS dispatching has been removed per architecture requirements.
"""

from typing import Dict, Any
from app import state, database


async def broadcast_alert(alert: Dict[str, Any]) -> None:
    """
    Broadcasts security alert to connected admin WebSockets and records to database.
    Does NOT require any phone number or external SMS gateway.
    """
    # 1. Persist alert to Database (MySQL or SQLite fallback)
    try:
        database.db_save_alert(alert)
    except Exception as e:
        print(f"[ALERT DB ERROR] Failed to save alert {alert.get('id')}: {e}")

    # 2. Push in real-time via WebSocket to all active Defender SOC dashboards
    dead_sockets = []
    for ws in state.ADMIN_SOCKETS:
        try:
            await ws.send_json(alert)
        except Exception:
            dead_sockets.append(ws)

    for ws in dead_sockets:
        if ws in state.ADMIN_SOCKETS:
            state.ADMIN_SOCKETS.remove(ws)

    # 3. Print clean structured security log in console
    lvl = alert.get("level", "info").upper()
    print(f"[SOC NOTIFICATION - {lvl}] {alert.get('message')}")
