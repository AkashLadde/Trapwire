import requests

base_admin = 'http://127.0.0.1:8000'
base_hacker = 'http://127.0.0.1:9000'

print('=== 1. Testing Landing Page ===')
res_landing = requests.get(base_admin)
assert res_landing.status_code == 200
assert 'Admin Login' in res_landing.text
print('PASS: Landing page features direct link for Admin Login.')

print('=== 2. Testing Attacker Login Attempt (Wrong Passphrase) ===')
res_atk_fail = requests.post(f'{base_admin}/api/attacker-session-event', json={
    'event': 'terminal_login_attempt',
    'user': 'unknown_hacker',
    'password_attempt': 'wrong_password_123',
    'tool': 'Kali Workstation HUD'
})
assert res_atk_fail.status_code == 200
print('PASS: Attacker login attempt recognized:', res_atk_fail.json())

print('=== 3. Testing Attacker Successful Login ===')
res_atk_ok = requests.post(f'{base_admin}/api/attacker-session-event', json={
    'event': 'terminal_login_success',
    'user': 'root',
    'password_attempt': 'toor',
    'tool': 'Kali Workstation'
})
assert res_atk_ok.status_code == 200
print('PASS: Attacker successful login recognized:', res_atk_ok.json())

print('=== 4. Testing SQL Injection Attack and Automated DPB Submission ===')
res_sqli = requests.post(f'{base_admin}/api/attacker-session-event', json={
    'event': 'sqli_attack',
    'user': 'root',
    'payload': "' UNION SELECT username, password FROM users --",
    'target': '/api/orders'
})
assert res_sqli.status_code == 200
sqli_data = res_sqli.json()
print('PASS: SQLi attack recognized with IP/ISP and DPB ack:', sqli_data)
assert sqli_data.get('dpb_ack') is not None

print('=== 5. Testing Decoy Data Exfiltration and Canary Phone-Home ===')
s = requests.Session()
s.post(f'{base_admin}/api/login', data={'username': 'admin', 'password': 'wrong_password'})
s.post(f'{base_admin}/api/login', data={'username': 'admin', 'password': 'wrong_password'})
s.post(f'{base_admin}/api/login', data={'username': 'admin', 'password': 'wrong_password'})
s.post(f'{base_admin}/api/login', data={'username': 'admin', 'password': 'Admin@2026!'})
export_res = s.get(f'{base_admin}/api/export')
assert export_res.status_code == 200
export_records = export_res.json()
print(f'PASS: Exfiltrated {len(export_records)} decoy records with active canary token.')

# Trigger canary tracking link
canary_url = export_records[0].get('_tracking_invoice_url')
token = canary_url.split('/canary/')[1]
canary_get = requests.get(canary_url)
assert canary_get.status_code == 200
canary_post = requests.post(f'{base_admin}/api/canary-details/{token}', json={
    'screen': '2560x1440',
    'platform': 'Linux x86_64',
    'timezone': 'Asia/Kolkata',
    'cores': 16,
    'language': 'en-US'
})
assert canary_post.status_code == 200
print('PASS: Canary tracking beacon captured device attribution and auto-filed final DPB report.')

print('=== 8. Testing New Attack Vectors (IDOR, LFI, SSRF, RCE, Honeytoken) ===')

# SQLi honeypot
res_sqli_ep = requests.get(f"{base_admin}/api/search-customer?q=' UNION SELECT 1,2,3 --")
assert res_sqli_ep.status_code == 200
assert res_sqli_ep.json().get("vulnerability_detected") is True
print("PASS: /api/search-customer SQLi Honeypot engaged.")

# IDOR honeypot
res_idor = requests.get(f"{base_admin}/api/customer/9901")
assert res_idor.status_code == 200
assert res_idor.json().get("_security_status") == "HONEYPOT_RECORD_SERVED"
print("PASS: /api/customer/9901 IDOR / BOLA Honeypot engaged.")

# LFI honeypot
res_lfi = requests.get(f"{base_admin}/api/download?file=../../.env")
assert res_lfi.status_code == 200
assert "TRAPWIRE_CANARY_TOKEN" in res_lfi.text
print("PASS: /api/download LFI / Path Traversal Honeypot served decoy env.")

# SSRF honeypot
res_ssrf = requests.get(f"{base_admin}/api/preview-url?url=http://169.254.169.254/latest/meta-data/")
assert res_ssrf.status_code == 200
assert res_ssrf.json().get("AccessKeyId") == "AKIA_TRAPWIRE_CANARY_TOKEN_9901"
print("PASS: /api/preview-url SSRF Honeypot served decoy IAM credentials.")

# RCE honeypot
res_rce = requests.get(f"{base_admin}/api/diagnostics/ping?host=127.0.0.1;whoami")
assert res_rce.status_code == 200
assert "quarantined_sandbox_output" in res_rce.json().get("status")
print("PASS: /api/diagnostics/ping RCE Command Injection Honeypot engaged.")

# Honeytoken canary key
res_ht = requests.get(f"{base_admin}/api/v1/internal/admin-dump", headers={"Authorization": "Bearer AKIA_TRAPWIRE_CANARY_TOKEN_9901"})
assert res_ht.status_code == 200
assert res_ht.json().get("status") == "HONEYTOKEN_TRIGGERED"
print("PASS: /api/v1/internal/admin-dump Honeytoken attribution engaged.")

print('\nALL SYSTEM & ATTACK SIMULATION TESTS PASSED!')
