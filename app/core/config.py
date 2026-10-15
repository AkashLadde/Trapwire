"""
TRAPWIRE — Centralized Configuration & Environment Settings
"""

import os
from typing import List

# Server Network Settings
SERVER_HOST: str = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT: int = int(os.getenv("SERVER_PORT", "8000"))
ATTACKER_PORT: int = int(os.getenv("ATTACKER_PORT", "9000"))
TARGET_COMPANY_URL: str = os.getenv("TARGET_COMPANY_URL", f"http://{SERVER_HOST}:{SERVER_PORT}")

# Security & Session Settings
SESSION_SECRET_KEY: str = os.getenv("SESSION_SECRET_KEY", "trapwire-capstone-demo-secret-change-me")
CORS_ORIGINS: List[str] = ["*"]

# Database Settings
MYSQL_HOST: str = os.getenv("MYSQL_HOST", "localhost")
MYSQL_PORT: int = int(os.getenv("MYSQL_PORT", "3306"))
MYSQL_USER: str = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD: str = os.getenv("MYSQL_PASSWORD", "")
MYSQL_DATABASE: str = os.getenv("MYSQL_DATABASE", "trapwire_db")

# Admin Credentials
DEFAULT_ADMIN_USER: str = os.getenv("ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "Admin@2026!")

# Simulated VPN Nodes for Attacker Console
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

# Wordlist for credential attack demonstration
ATTACK_WORDLIST = [
    "123456",
    "password",
    "admin123",
    "admin@123",
    "Welcome@123",
    "qwerty123",
    "Admin@2026!",
    "letmein123",
]
