"""
TRAPWIRE — Master Dual-Server Launcher
Runs both independent servers concurrently:
  1. Company Defender Portal & DPDP Engine on http://127.0.0.1:8000
  2. Kali Linux Attacker Pentest Console on http://127.0.0.1:9000
"""

import sys
import time
import subprocess
import threading


def run_company_server():
    print("[SERVER 1] Launching Company Portal on http://127.0.0.1:8000 ...")
    subprocess.run([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000", "--reload"])


def run_attacker_server():
    print("[SERVER 2] Launching Attacker Portal on http://127.0.0.1:9000 ...")
    subprocess.run([sys.executable, "-m", "uvicorn", "app.attacker_server:app", "--host", "127.0.0.1", "--port", "9000", "--reload"])


def run_hardware_bridge():
    # Wait for Defender server to initialize on port 8000
    time.sleep(3)
    print("[HARDWARE] Launching Physical Hardware Serial Bridge (Auto-detecting ESP32 on COM7) ...")
    subprocess.run([sys.executable, "hardware/serial_bridge.py"])


if __name__ == "__main__":
    print("=" * 72)
    print("  TRAPWIRE — MASTER DUAL-SERVER & HARDWARE LAUNCHER")
    print("  Company Portal (Defender):  http://127.0.0.1:8000")
    print("  Attacker Portal (OffSec):   http://127.0.0.1:9000")
    print("  Hardware Physical Node:     Auto-scanning COM7 (ESP32 Strobe & Siren)")
    print("  Target Admin Number:        +91 99016 25399")
    print("=" * 72)

    t1 = threading.Thread(target=run_company_server, daemon=True)
    t2 = threading.Thread(target=run_attacker_server, daemon=True)
    t3 = threading.Thread(target=run_hardware_bridge, daemon=True)

    t1.start()
    time.sleep(1)
    t2.start()
    t3.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] Terminating servers and hardware bridge...")
        sys.exit(0)
