"""
TRAPWIRE — Network Intelligence, Geolocation, and Client IP Resolution
"""

from typing import Optional, Tuple
import requests
from fastapi import Request
from app import state

# Global in-memory cache for host machine public network intelligence
REAL_PUBLIC_IP_CACHE: Optional[str] = None
REAL_PUBLIC_GEO_CACHE: Optional[dict] = None


def get_real_network_intel() -> Tuple[str, dict]:
    """Resolves real public IP and ISP of the running host with caching."""
    global REAL_PUBLIC_IP_CACHE, REAL_PUBLIC_GEO_CACHE
    if REAL_PUBLIC_IP_CACHE and REAL_PUBLIC_GEO_CACHE:
        return REAL_PUBLIC_IP_CACHE, REAL_PUBLIC_GEO_CACHE
    try:
        resp = requests.get(
            "http://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query",
            timeout=2.0
        )
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
                    "timezone": data.get("timezone", "Asia/Kolkata"),
                }
                return REAL_PUBLIC_IP_CACHE, REAL_PUBLIC_GEO_CACHE
    except Exception:
        pass

    # Fallback to high-fidelity enterprise IP & ISP if offline
    REAL_PUBLIC_IP_CACHE = "152.58.21.144"
    REAL_PUBLIC_GEO_CACHE = {
        "isp": "Reliance Jio Infocomm Ltd (Fiber Broadband)",
        "city": "Mumbai",
        "country": "India",
        "region": "Maharashtra",
        "org": "Reliance Jio Infocomm",
        "as": "AS55836 Jio Broadband",
        "timezone": "Asia/Kolkata",
    }
    return REAL_PUBLIC_IP_CACHE, REAL_PUBLIC_GEO_CACHE


def client_ip(request: Request) -> str:
    """Extracts client IP address supporting simulated VPN headers and proxy headers."""
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


COUNTRY_VPN_REGISTRY = {
    "india": {
        "country": "India", "flag": "🇮🇳", "city": "Mumbai",
        "ip": "103.152.112.45", "gateway": "103.152.112.1",
        "isp": "Reliance Jio Infocomm Ltd (Fiber Broadband)",
        "org": "Reliance Jio Infocomm", "region": "Maharashtra", "as": "AS55836 Jio Broadband",
        "aliases": ["india", "in", "bharat", "mumbai", "delhi", "bangalore"]
    },
    "united states": {
        "country": "United States", "flag": "🇺🇸", "city": "New York",
        "ip": "198.51.100.77", "gateway": "198.51.100.1",
        "isp": "DigitalOcean LLC (US-East Datacenter)",
        "org": "DigitalOcean Cloud Infrastructure", "region": "New York", "as": "AS14061 DigitalOcean",
        "aliases": ["usa", "us", "united states", "united states of america", "america", "new york", "california"]
    },
    "netherlands": {
        "country": "Netherlands", "flag": "🇳🇱", "city": "Amsterdam",
        "ip": "185.220.101.45", "gateway": "185.220.101.1",
        "isp": "DataCamp Limited - Anonymous Tor/VPN Relay",
        "org": "DataCamp Global Relays", "region": "North Holland", "as": "AS60068 DataCamp",
        "aliases": ["netherlands", "holland", "amsterdam", "nl", "dutch"]
    },
    "germany": {
        "country": "Germany", "flag": "🇩🇪", "city": "Frankfurt",
        "ip": "45.155.204.12", "gateway": "45.155.204.1",
        "isp": "Hetzner Online GmbH (Frankfurt DC)",
        "org": "Hetzner Cloud Infrastructure", "region": "Hesse", "as": "AS24940 Hetzner Online",
        "aliases": ["germany", "deutschland", "de", "frankfurt", "berlin"]
    },
    "singapore": {
        "country": "Singapore", "flag": "🇸🇬", "city": "Singapore",
        "ip": "103.253.24.19", "gateway": "103.253.24.1",
        "isp": "Singtel Cyber Security Subnet",
        "org": "Singapore Telecommunications Limited", "region": "Central Singapore", "as": "AS7473 Singtel",
        "aliases": ["singapore", "sg"]
    },
    "japan": {
        "country": "Japan", "flag": "🇯🇵", "city": "Tokyo",
        "ip": "103.4.17.88", "gateway": "103.4.17.1",
        "isp": "Sakura Internet Tokyo Datacenter",
        "org": "Sakura Internet Inc.", "region": "Kanto", "as": "AS9370 SAKURA-BGP",
        "aliases": ["japan", "jp", "tokyo", "osaka", "nippon"]
    },
    "united kingdom": {
        "country": "United Kingdom", "flag": "🇬🇧", "city": "London",
        "ip": "185.220.101.5", "gateway": "185.220.101.1",
        "isp": "M247 Ltd London Relay",
        "org": "M247 Europe Backbone", "region": "England", "as": "AS9009 M247 Ltd",
        "aliases": ["uk", "united kingdom", "gb", "great britain", "britain", "england", "london"]
    },
    "canada": {
        "country": "Canada", "flag": "🇨🇦", "city": "Montreal",
        "ip": "198.50.200.41", "gateway": "198.50.200.1",
        "isp": "OVH Hosting Canada Inc.",
        "org": "OVH Canada Cloud", "region": "Quebec", "as": "AS16276 OVH",
        "aliases": ["canada", "ca", "montreal", "toronto"]
    },
    "france": {
        "country": "France", "flag": "🇫🇷", "city": "Paris",
        "ip": "51.255.45.10", "gateway": "51.255.45.1",
        "isp": "OVH SAS Paris Datacenter",
        "org": "OVH Groupe", "region": "Ile-de-France", "as": "AS16276 OVH",
        "aliases": ["france", "fr", "paris"]
    },
    "australia": {
        "country": "Australia", "flag": "🇦🇺", "city": "Sydney",
        "ip": "139.99.130.20", "gateway": "139.99.130.1",
        "isp": "Telstra Internet Australia Backbone",
        "org": "Telstra Corporation", "region": "New South Wales", "as": "AS1221 Telstra",
        "aliases": ["australia", "au", "sydney", "melbourne"]
    },
    "russia": {
        "country": "Russia", "flag": "🇷🇺", "city": "Moscow",
        "ip": "95.173.136.25", "gateway": "95.173.136.1",
        "isp": "Rostelecom Moscow Relay",
        "org": "PJSC Rostelecom", "region": "Moscow Federal City", "as": "AS12389 Rostelecom",
        "aliases": ["russia", "ru", "moscow", "saint petersburg", "russian federation"]
    },
    "china": {
        "country": "China", "flag": "🇨🇳", "city": "Beijing",
        "ip": "114.114.114.114", "gateway": "114.114.114.1",
        "isp": "China Telecom Backbone Relay",
        "org": "China Telecom", "region": "Beijing", "as": "AS4134 CHINANET",
        "aliases": ["china", "cn", "beijing", "shanghai"]
    },
    "switzerland": {
        "country": "Switzerland", "flag": "🇨🇭", "city": "Zurich",
        "ip": "185.107.56.23", "gateway": "185.107.56.1",
        "isp": "ProtonVPN AG / Private Layer Zurich",
        "org": "Proton AG", "region": "Zurich", "as": "AS51852 Private Layer",
        "aliases": ["switzerland", "ch", "swiss", "zurich", "geneva"]
    },
    "sweden": {
        "country": "Sweden", "flag": "🇸🇪", "city": "Stockholm",
        "ip": "193.180.119.2", "gateway": "193.180.119.1",
        "isp": "Mullvad VPN / Bahnhof AB",
        "org": "Bahnhof AB", "region": "Stockholm", "as": "AS8473 Bahnhof",
        "aliases": ["sweden", "se", "stockholm"]
    },
    "brazil": {
        "country": "Brazil", "flag": "🇧🇷", "city": "São Paulo",
        "ip": "177.54.144.10", "gateway": "177.54.144.1",
        "isp": "Claro Brasil Backbone Subnet",
        "org": "Claro NXT Telecomunicacoes", "region": "Sao Paulo", "as": "AS28573 Claro Brasil",
        "aliases": ["brazil", "brasil", "br", "sao paulo"]
    },
    "united arab emirates": {
        "country": "United Arab Emirates", "flag": "🇦🇪", "city": "Dubai",
        "ip": "94.200.12.18", "gateway": "94.200.12.1",
        "isp": "Etisalat Telecommunications Dubai",
        "org": "Emirates Telecommunications Group", "region": "Dubai", "as": "AS8966 Emirates Telecom",
        "aliases": ["uae", "united arab emirates", "dubai", "ae", "abu dhabi"]
    },
    "south korea": {
        "country": "South Korea", "flag": "🇰🇷", "city": "Seoul",
        "ip": "211.234.118.50", "gateway": "211.234.118.1",
        "isp": "KT Corporation Telecom Relay",
        "org": "KT Corporation", "region": "Seoul", "as": "AS4766 Korea Telecom",
        "aliases": ["south korea", "korea", "kr", "seoul"]
    },
    "italy": {
        "country": "Italy", "flag": "🇮🇹", "city": "Milan",
        "ip": "185.25.204.10", "gateway": "185.25.204.1",
        "isp": "Telecom Italia Sparkle Milan",
        "org": "Telecom Italia", "region": "Lombardy", "as": "AS6762 Sparkle",
        "aliases": ["italy", "italia", "it", "milan", "rome"]
    },
    "spain": {
        "country": "Spain", "flag": "🇪🇸", "city": "Madrid",
        "ip": "84.120.50.15", "gateway": "84.120.50.1",
        "isp": "Telefonica de España Madrid",
        "org": "Telefonica de Espana S.A.U.", "region": "Madrid", "as": "AS3352 Telefonica",
        "aliases": ["spain", "espana", "es", "madrid"]
    },
    "norway": {
        "country": "Norway", "flag": "🇳🇴", "city": "Oslo",
        "ip": "185.125.204.5", "gateway": "185.125.204.1",
        "isp": "Telenor Norge AS Oslo",
        "org": "Telenor Norge", "region": "Oslo", "as": "AS2119 Telenor",
        "aliases": ["norway", "no", "oslo"]
    },
    "finland": {
        "country": "Finland", "flag": "🇫🇮", "city": "Helsinki",
        "ip": "185.100.86.12", "gateway": "185.100.86.1",
        "isp": "Telia Finland Oy Helsinki",
        "org": "Telia Finland", "region": "Uusimaa", "as": "AS1759 Telia",
        "aliases": ["finland", "fi", "helsinki"]
    },
    "ireland": {
        "country": "Ireland", "flag": "🇮🇪", "city": "Dublin",
        "ip": "185.145.128.4", "gateway": "185.145.128.1",
        "isp": "Amazon Ireland Datacenter",
        "org": "Amazon Data Services Ireland", "region": "Leinster", "as": "AS16509 Amazon",
        "aliases": ["ireland", "ie", "dublin"]
    },
    "poland": {
        "country": "Poland", "flag": "🇵🇱", "city": "Warsaw",
        "ip": "185.240.244.15", "gateway": "185.240.244.1",
        "isp": "Orange Polska S.A.",
        "org": "Orange Polska", "region": "Mazovia", "as": "AS5617 Orange Polska",
        "aliases": ["poland", "pl", "warsaw", "polska"]
    },
    "israel": {
        "country": "Israel", "flag": "🇮🇱", "city": "Tel Aviv",
        "ip": "185.191.171.12", "gateway": "185.191.171.1",
        "isp": "Bezeq International Tel Aviv",
        "org": "Bezeq The Israel Telecommunication", "region": "Tel Aviv", "as": "AS8551 Bezeq",
        "aliases": ["israel", "il", "tel aviv"]
    },
    "hong kong": {
        "country": "Hong Kong", "flag": "🇭🇰", "city": "Hong Kong",
        "ip": "103.214.144.8", "gateway": "103.214.144.1",
        "isp": "HKBN Enterprise Solutions",
        "org": "Hong Kong Broadband Network", "region": "Hong Kong", "as": "AS9269 HKBN",
        "aliases": ["hong kong", "hk"]
    },
    "mexico": {
        "country": "Mexico", "flag": "🇲🇽", "city": "Mexico City",
        "ip": "189.240.12.5", "gateway": "189.240.12.1",
        "isp": "Telmex Red de Acceso",
        "org": "Uninet S.A. de C.V.", "region": "CDMX", "as": "AS8151 Uninet",
        "aliases": ["mexico", "mx", "mexico city"]
    },
    "turkey": {
        "country": "Turkey", "flag": "🇹🇷", "city": "Istanbul",
        "ip": "185.184.24.5", "gateway": "185.184.24.1",
        "isp": "Turk Telekomunikasyon Istanbul",
        "org": "Turk Telekom", "region": "Istanbul", "as": "AS9121 Turk Telekom",
        "aliases": ["turkey", "turkiye", "tr", "istanbul"]
    },
    "ukraine": {
        "country": "Ukraine", "flag": "🇺🇦", "city": "Kyiv",
        "ip": "185.156.172.4", "gateway": "185.156.172.1",
        "isp": "Kyivstar Telecommunications",
        "org": "JSC Kyivstar", "region": "Kyiv City", "as": "AS15895 Kyivstar",
        "aliases": ["ukraine", "ua", "kyiv", "kiev"]
    },
    "south africa": {
        "country": "South Africa", "flag": "🇿🇦", "city": "Johannesburg",
        "ip": "102.165.32.14", "gateway": "102.165.32.1",
        "isp": "Vodacom SA Internet Backbone",
        "org": "Vodacom", "region": "Gauteng", "as": "AS36937 Vodacom",
        "aliases": ["south africa", "za", "johannesburg"]
    }
}

# Reverse mapping: IP -> Country Details
KNOWN_COUNTRY_IPS = {entry["ip"]: entry for entry in COUNTRY_VPN_REGISTRY.values()}


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
                    "as": j.get("as", ""),
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
        "as": "AS60068",
    }
