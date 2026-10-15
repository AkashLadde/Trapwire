"""
TRAPWIRE — Native Hardware Serial Controller & Threat Dispatcher
Directly interfaces the FastAPI Backend with the physical ESP32 Threat Siren & OLED HUD.
Automatically detects COM7 (or any Silicon Labs CP210x / CH340 ESP32) and streams live breach alerts.
"""

import sys
import time
import json
import threading
from typing import Optional

try:
    import serial
    import serial.tools.list_ports
    HAS_SERIAL = True
except ImportError:
    HAS_SERIAL = False


class HardwareController:
    _instance: Optional["HardwareController"] = None

    def __init__(self, target_port: Optional[str] = None, baud: int = 115200):
        self.target_port = target_port
        self.baud = baud
        self.ser: Optional[serial.Serial] = None
        self.is_connected = False
        self.last_alert: Optional[dict] = None
        self.lock = threading.Lock()
        self._running = True
        self._worker_thread = threading.Thread(target=self._connection_supervisor, daemon=True)
        self._worker_thread.start()

    @classmethod
    def get_instance(cls) -> "HardwareController":
        if cls._instance is None:
            cls._instance = HardwareController()
        return cls._instance

    def find_esp32_port(self) -> Optional[str]:
        if not HAS_SERIAL:
            return None
        ports = list(serial.tools.list_ports.comports())
        for p in ports:
            desc = (p.description or "").lower()
            hwid = (p.hwid or "").lower()
            if any(k in desc or k in hwid for k in ["cp210", "ch340", "ch341", "ch9102", "silicon labs", "esp32", "usb-serial", "uart"]):
                return p.device
        if ports:
            return ports[0].device
        return None

    def _connection_supervisor(self):
        """Continuously supervises and maintains the serial link to the ESP32."""
        while self._running:
            if not self.is_connected:
                port = self.target_port or self.find_esp32_port()
                if port and HAS_SERIAL:
                    try:
                        with self.lock:
                            print(f"[HARDWARE CONTROLLER] Attempting connection to ESP32 on {port} @ {self.baud} baud...")
                            self.ser = serial.Serial(port, self.baud, timeout=1)
                            self.is_connected = True
                            self.target_port = port
                        print(f"[HARDWARE CONTROLLER] [OK] Connected to ESP32 on {port}! Waiting 2s for boot stabilization...")
                        time.sleep(2.0)
                        with self.lock:
                            if self.ser and self.ser.is_open:
                                self.ser.reset_input_buffer()
                                welcome_packet = json.dumps({
                                    "level": "info",
                                    "message": "TRAPWIRE SOC ARMED",
                                    "attacker_ip": "STANDBY"
                                }) + "\n"
                                self.ser.write(welcome_packet.encode("utf-8"))
                                print(f"[HARDWARE CONTROLLER] Sent SOC Link Established packet to ESP32 on {port}.")
                    except Exception as e:
                        self.is_connected = False
                        self.ser = None
                        # Don't spam if port is temporarily unavailable
                        time.sleep(4)
                else:
                    time.sleep(4)
            else:
                # Periodic heartbeat check
                time.sleep(2)
                try:
                    with self.lock:
                        if self.ser and not self.ser.is_open:
                            self.is_connected = False
                except Exception:
                    self.is_connected = False

    def dispatch_alert(self, alert: dict) -> bool:
        """Sends live threat telemetry immediately to the ESP32 OLED, Buzzer, and Blue LED."""
        meta = alert.get("meta", {})
        
        # Priority resolution for Attacker IP (VPN node IP, public IP, honeypot hit)
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

        self.last_alert = alert

        with self.lock:
            if self.ser and self.ser.is_open:
                try:
                    self.ser.write(payload.encode("utf-8"))
                    print(f"[HARDWARE DISPATCH -> ESP32 COM7] Alert: {payload.strip()}")
                    return True
                except Exception as e:
                    print(f"[HARDWARE DISPATCH ERROR] {e}")
                    self.is_connected = False
                    try:
                        self.ser.close()
                    except Exception:
                        pass
                    self.ser = None
                    return False
            else:
                print(f"[HARDWARE OFFLINE / VIRTUAL] No serial hardware connected: {payload.strip()}")
                return False

    def get_status(self) -> dict:
        return {
            "status": "ONLINE" if self.is_connected else "STANDBY",
            "port": self.target_port or "Auto-scanning COM7",
            "connected": self.is_connected,
            "last_alert": self.last_alert
        }


def get_hardware_controller() -> HardwareController:
    return HardwareController.get_instance()
