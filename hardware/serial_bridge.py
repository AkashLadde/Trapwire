"""
=====================================================================================
TRAPWIRE — Hardware Serial Bridge & GSM Modem Controller
=====================================================================================
Connects the TrapWire Defender Backend (FastAPI WebSocket) to physical hardware:
 1. USB Serial MCU (ESP32 / Arduino Threat Strobe Siren & OLED).
 2. USB / Serial GSM Module (SIM800L / SIM900) for Out-of-Band Hardware SMS to 9901625399.
 3. Dual-NIC Network Tap telemetry forwarder.

Usage:
    python hardware/serial_bridge.py --port COM3 --baud 115200 --gsm-port COM4
=====================================================================================
"""

import sys
import time
import json
import asyncio
import argparse
import requests

try:
    import serial
    import serial.tools.list_ports
    HAS_SERIAL = True
except ImportError:
    HAS_SERIAL = False

try:
    import websockets
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False

ADMIN_PHONE = "9901625399"
SERVER_WS_URL = "ws://127.0.0.1:8000/ws/alerts"
SERVER_HTTP_URL = "http://127.0.0.1:8000"


class GsmModem:
    """Controls a physical SIM800L / SIM900 GSM module over AT Commands via Serial."""
    def __init__(self, port: str = None, baud: int = 9600):
        self.port = port
        self.baud = baud
        self.ser = None
        if HAS_SERIAL and port:
            try:
                self.ser = serial.Serial(port, baud, timeout=3)
                time.sleep(1)
                self.send_at("AT")
                self.send_at("AT+CMGF=1") # Set SMS text mode
                print(f"[GSM MODEM] Initialized on {port} (Ready for SMS to +91 {ADMIN_PHONE})")
            except Exception as e:
                print(f"[GSM MODEM WARN] Could not open {port}: {e}")

    def send_at(self, cmd: str) -> str:
        if not self.ser:
            return ""
        self.ser.write((cmd + "\r\n").encode("utf-8"))
        time.sleep(0.5)
        resp = self.ser.read_all().decode("utf-8", errors="ignore")
        return resp

    def send_sms(self, phone: str, text: str):
        if not self.ser:
            print(f"[GSM SIMULATION] SMS to +91 {phone}: {text}")
            return True
        try:
            self.send_at("AT+CMGF=1")
            self.ser.write(f'AT+CMGS="+91{phone}"\r\n'.encode("utf-8"))
            time.sleep(0.5)
            self.ser.write(f"{text}\x1A".encode("utf-8")) # 0x1A = Ctrl+Z to send
            time.sleep(2)
            print(f"[GSM HARDWARE SMS SENT] To: +91 {phone} | Text: {text}")
            return True
        except Exception as e:
            print(f"[GSM SMS ERROR] {e}")
            return False


class HardwareBridge:
    def __init__(self, mcu_port: str = None, mcu_baud: int = 115200, gsm_port: str = None):
        self.mcu_port = mcu_port
        self.mcu_baud = mcu_baud
        self.mcu_ser = None
        self.gsm = GsmModem(gsm_port)

        if HAS_SERIAL and mcu_port:
            try:
                self.mcu_ser = serial.Serial(mcu_port, mcu_baud, timeout=1)
                print(f"[MCU BRIDGE] Connected to ESP32 / Arduino Siren on {mcu_port} @ {mcu_baud} baud.")
                print(f"[MCU BRIDGE] Synchronizing with ESP32 (waiting 2s for boot)...")
                time.sleep(2.0)
                try:
                    self.mcu_ser.reset_input_buffer()
                    self.mcu_ser.write(b'{"level":"info","message":"SOC LINK ESTABLISHED","attacker_ip":"ARMED"}\n')
                    print(f"[MCU BRIDGE] Sync packet dispatched to ESP32 on {mcu_port}.")
                except Exception:
                    pass
            except Exception as e:
                print(f"[MCU BRIDGE WARN] Could not connect to {mcu_port}: {e}")
        else:
            print("[MCU BRIDGE] Running in Virtual/Emulated mode (No physical USB MCU detected).")

    def forward_to_mcu(self, alert: dict):
        """Sends JSON alert packet to ESP32 NodeMCU over serial."""
        meta = alert.get("meta", {})
        
        # Priority resolution for Attacker IP (VPN node IP, public IP, or honeypot hit)
        attacker_ip = (
            meta.get("attacker_ip")
            or meta.get("ip")
            or alert.get("attacker_ip")
            or alert.get("ip")
            or "185.220.101.45"
        )
        if isinstance(attacker_ip, str):
            attacker_ip = attacker_ip.split(" ")[0].strip()

        # Clean non-ASCII characters & emojis for crisp 0.96" SSD1306 OLED display
        raw_msg = alert.get("message", "Threat event detected")
        clean_msg = "".join([c for c in raw_msg if ord(c) < 128]).strip()
        while "  " in clean_msg:
            clean_msg = clean_msg.replace("  ", " ")

        payload = json.dumps({
            "level": alert.get("level", "info"),
            "message": clean_msg[:42],
            "attacker_ip": str(attacker_ip),
            "timestamp": int(alert.get("timestamp", time.time()))
        }) + "\n"

        if self.mcu_ser:
            try:
                self.mcu_ser.write(payload.encode("utf-8"))
                print(f"[SERIAL -> ESP32 NODEMCU] Sent: {payload.strip()}")
            except Exception as e:
                print(f"[SERIAL WRITE ERROR] {e}")
        else:
            print(f"[VIRTUAL SERIAL -> ESP32 NODEMCU] {payload.strip()}")

    def handle_critical_alert(self, alert: dict):
        # 1. Strobe Siren
        self.forward_to_mcu(alert)

        # 2. Hardware Out-of-Band SMS Dispatch
        msg = f"TRAPWIRE INTRUSION: {alert.get('message', 'Breach detected')} | Attacker IP: {alert.get('meta',{}).get('attacker_ip', '127.0.0.1')}"
        self.gsm.send_sms(ADMIN_PHONE, msg)

    async def listen_threat_stream(self, ws_url: str = SERVER_WS_URL):
        """Connects to TrapWire WebSocket on port 8000 and listens for live attacks."""
        candidate_urls = [ws_url]
        if ws_url == SERVER_WS_URL:
            candidate_urls.append("ws://127.0.0.1:8000/api/threat-stream")
        elif ws_url == "ws://127.0.0.1:8000/api/threat-stream":
            candidate_urls.append("ws://127.0.0.1:8000/ws/alerts")

        url_index = 0
        while True:
            current_url = candidate_urls[url_index % len(candidate_urls)]
            print(f"[*] Connecting to TrapWire WebSocket: {current_url} ...")
            try:
                if HAS_WEBSOCKETS:
                    async with websockets.connect(current_url) as ws:
                        print(f"[+] Successfully connected to Live SOC Threat Stream on {current_url}!")
                        while True:
                            data_raw = await ws.recv()
                            alert = json.loads(data_raw)
                            print(f"\n[⚡ LIVE THREAT EVENT] [{alert.get('level', 'INFO').upper()}] {alert.get('message')}")
                            
                            level = alert.get("level", "info")
                            if level in ("critical", "warning", "emergency"):
                                self.handle_critical_alert(alert)
                            else:
                                self.forward_to_mcu(alert)
                else:
                    # Polling Fallback if websockets package not installed
                    resp = requests.get(f"{SERVER_HTTP_URL}/api/alerts/recent", timeout=2)
                    if resp.ok:
                        alerts = resp.json().get("alerts", [])
                        if alerts:
                            latest = alerts[0]
                            print(f"[POLL ALERT] {latest.get('message')}")
                            self.forward_to_mcu(latest)
                    await asyncio.sleep(2)
            except Exception as e:
                print(f"[STREAM RECONNECTING] Server offline or disconnected ({e}).")
                print("  ↳ Tip: Make sure the Defender server is running (run 'python run_servers.py'). Retrying in 3s...")
                url_index += 1
                await asyncio.sleep(3)


def auto_detect_ports():
    if not HAS_SERIAL:
        print("Note: pyserial is not installed. To connect physical hardware, install with: pip install pyserial websockets")
        return None
    ports = list(serial.tools.list_ports.comports())
    print("\n--- Available Serial / COM Ports ---")
    if not ports:
        print(" No USB Serial hardware currently plugged in.")
        print("------------------------------------\n")
        return None
    
    best_port = None
    for p in ports:
        print(f"  • Port: {p.device} | Description: {p.description} | Hardware ID: {p.hwid}")
        desc = (p.description or "").lower()
        hwid = (p.hwid or "").lower()
        if any(k in desc or k in hwid for k in ["cp210", "ch340", "ch341", "ch9102", "silicon labs", "esp32", "usb-serial", "uart", "ftdi"]):
            if not best_port:
                best_port = p.device
    print("------------------------------------\n")
    if not best_port and ports:
        best_port = ports[0].device
    return best_port


def main():
    parser = argparse.ArgumentParser(description="TRAPWIRE Physical Hardware Serial & GSM Bridge")
    parser.add_argument("--port", type=str, default=None, help="COM port for ESP32 / Arduino Siren (e.g. COM3 or COM7)")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate for ESP32 (default: 115200)")
    parser.add_argument("--gsm-port", type=str, default=None, help="COM port for SIM800L GSM modem (e.g. COM4 or COM8)")
    parser.add_argument("--ws-url", type=str, default=SERVER_WS_URL, help="Custom WebSocket URL for threat stream")
    parser.add_argument("--test-alarm", action="store_true", help="Send an immediate test critical alarm to the ESP32 and exit")
    args = parser.parse_args()

    print("=" * 70)
    print(" TRAPWIRE — Physical Threat Siren & GSM Bridge v2.5")
    print(" Target Admin SMS: +91 99016 25399")
    print(" Defender Server:  http://127.0.0.1:8000")
    print("=" * 70)

    detected_port = auto_detect_ports()
    target_port = args.port or detected_port
    if target_port:
        print(f"[+] Using MCU Port: {target_port} (Baud: {args.baud})")
    else:
        print("[-] No USB serial port detected. Running in virtual emulation mode.")

    bridge = HardwareBridge(mcu_port=target_port, mcu_baud=args.baud, gsm_port=args.gsm_port)

    if args.test_alarm:
        print("\n[*] Triggering immediate physical hardware test alarm...")
        test_alert = {
            "level": "critical",
            "message": "DIAGNOSTIC ALARM TEST",
            "attacker_ip": "185.220.101.45",
            "meta": {"attacker_ip": "185.220.101.45", "isp": "Local Test"}
        }
        bridge.handle_critical_alert(test_alert)
        time.sleep(3)
        print("[OK] Diagnostic alarm pulse sent to ESP32! Exiting test.")
        return

    try:
        asyncio.run(bridge.listen_threat_stream(ws_url=args.ws_url))
    except KeyboardInterrupt:
        print("\n[*] Hardware bridge stopped by user.")


if __name__ == "__main__":
    main()
