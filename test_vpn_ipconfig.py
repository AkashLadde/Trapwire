"""
Verification test for Country VPN switching, Attacker IP assignment, and IPConfig telemetry
"""
import requests
import json
import re

DEFENDER_BASE = "http://127.0.0.1:8000"
ATTACKER_BASE = "http://127.0.0.1:9000"

def test_static_files():
    print("[TEST 1] Checking attacker_terminal.js and attacker_portal.html on Port 9000...")
    res = requests.get(f"{ATTACKER_BASE}/console")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    assert "ipconfig" in res.text, "Expected 'ipconfig' quick button in attacker_portal.html"
    assert "vpn connect India" in res.text or "vpn India" in res.text, "Expected 'vpn India' button in attacker_portal.html"
    print("  -> Portal HTML verified.")

    js_res = requests.get(f"{ATTACKER_BASE}/static/js/attacker_terminal.js")
    assert js_res.status_code == 200
    assert "ipconfig: async" in js_res.text, "Expected 'ipconfig' in COMMANDS"
    assert "resolveCountryNode" in js_res.text, "Expected 'resolveCountryNode' in attacker_terminal.js"
    assert "COUNTRY_NODES" in js_res.text, "Expected 'COUNTRY_NODES' in attacker_terminal.js"
    print("  -> Terminal JS engine verified.")

def test_vpn_hop_india():
    print("\n[TEST 2] Testing VPN switch to India (103.152.112.45)...")
    payload = {
        "event": "vpn_hop",
        "user": "root",
        "ip": "103.152.112.45",
        "country": "India",
        "city": "Mumbai",
        "isp": "Reliance Jio Infocomm / Tata Communications Mumbai Relay",
        "node": "India (Mumbai)",
        "tool": "Kali Pentest Console"
    }
    headers = {
        "x-attacker-ip": "103.152.112.45",
        "x-vpn-ip": "103.152.112.45"
    }
    res = requests.post(f"{DEFENDER_BASE}/api/attacker-session-event", json=payload, headers=headers)
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    data = res.json()
    print(f"  -> Defender Response: {data}")
    assert data.get("ok") is True

def test_vpn_hop_usa():
    print("\n[TEST 3] Testing VPN switch to USA (198.51.100.77)...")
    payload = {
        "event": "vpn_hop",
        "user": "root",
        "ip": "198.51.100.77",
        "country": "United States",
        "city": "New York",
        "isp": "DigitalOcean LLC / Equinix NY4 Datacenter",
        "node": "United States (New York)",
        "tool": "Kali Pentest Console"
    }
    headers = {
        "x-attacker-ip": "198.51.100.77",
        "x-vpn-ip": "198.51.100.77"
    }
    res = requests.post(f"{DEFENDER_BASE}/api/attacker-session-event", json=payload, headers=headers)
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    data = res.json()
    print(f"  -> Defender Response: {data}")
    assert data.get("ok") is True

def test_exploit_with_switched_ip():
    print("\n[TEST 4] Testing exploit execution with Switched India IP (103.152.112.45)...")
    headers = {
        "X-Attacker-IP": "103.152.112.45",
        "X-VPN-IP": "103.152.112.45"
    }
    res = requests.get(f"{DEFENDER_BASE}/api/search-customer?q=' OR 1=1 --", headers=headers)
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    data = res.json()
    print(f"  -> SQLi response status 200, honeypot results count: {len(data.get('results', []))}")

def test_country_registry_in_python():
    print("\n[TEST 5] Checking COUNTRY_VPN_REGISTRY and mock_geolocate in app.core.network...")
    from app.core.network import mock_geolocate, COUNTRY_VPN_REGISTRY
    geo_in = mock_geolocate("103.152.112.45", hint_country="India")
    print(f"  -> 103.152.112.45 resolved to: {geo_in['country']} ({geo_in['city']}), ISP: {geo_in['isp']}")
    assert geo_in['country'] == "India"
    assert "Reliance Jio" in geo_in['isp'] or "Tata" in geo_in['isp']

    geo_us = mock_geolocate("198.51.100.77", hint_country="United States")
    print(f"  -> 198.51.100.77 resolved to: {geo_us['country']} ({geo_us['city']}), ISP: {geo_us['isp']}")
    assert geo_us['country'] == "United States"
    assert "DigitalOcean" in geo_us['isp']

    geo_de = mock_geolocate("45.155.204.12", hint_country="Germany")
    print(f"  -> 45.155.204.12 resolved to: {geo_de['country']} ({geo_de['city']}), ISP: {geo_de['isp']}")
    assert geo_de['country'] == "Germany"

if __name__ == "__main__":
    test_static_files()
    test_vpn_hop_india()
    test_vpn_hop_usa()
    test_exploit_with_switched_ip()
    test_country_registry_in_python()
    print("\n==========================================")
    print("ALL TESTS PASSED SUCCESSFULLY!")
    print("==========================================")
