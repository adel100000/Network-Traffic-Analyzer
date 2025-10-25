import os
import requests
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# API keys (make sure these exist in your .env file)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Cache for geolocation lookups to avoid hitting the API too often
_geo_cache = {}

# VirusTotal IP reputation lookup

def check_ip_virustotal(ip: str) -> dict:
    """Check IP reputation using VirusTotal API."""
    if not VIRUSTOTAL_API_KEY:
        print(" Missing VirusTotal API key in .env")
        return {}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return stats
        else:
            print(f"VirusTotal error: {resp.status_code} {resp.text[:100]}")
    except Exception as e:
        print(f"VT error: {e}")
    return {}
# AbuseIPDB IP reputation lookup

def check_ip_abuseipdb(ip: str) -> int:
    """Check IP threat score using AbuseIPDB."""
    if not ABUSEIPDB_API_KEY:
        print("⚠️ Missing AbuseIPDB API key in .env")
        return 0
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("data", {}).get("abuseConfidenceScore", 0)
        else:
            print(f"AbuseIPDB error: {resp.status_code} {resp.text[:100]}")
    except Exception as e:
        print(f"AbuseIPDB error: {e}")
    return 0

# Geolocation lookup

def geolocate_ip(ip: str) -> dict:
    """Get IP geolocation info using ipapi.co."""
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=4)
        if resp.status_code == 200:
            data = resp.json()
            result = {
                "city": data.get("city", "unknown"),
                "region": data.get("region", "unknown"),
                "country": data.get("country_name", "unknown"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "timezone": data.get("timezone", "unknown"),
                "org": data.get("org", "unknown"),
            }
            _geo_cache[ip] = result
            return result
        else:
            print(f"Geo API error: {resp.status_code}")
    except Exception as e:
        print(f"Geo error: {e}")
    return {"city": "unknown", "region": "unknown", "country": "unknown"}

def lookup_isp(ip: str) -> str:
    """Get ISP name using ipinfo.io."""
    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("org", "unknown")
        else:
            print(f"ISP API error: {resp.status_code}")
    except Exception as e:
        print(f"ISP error: {e}")
    return "unknown"

# Threat scoring logic

def compute_threat_score(vt_stats: dict, abuse_score: int) -> int:
    """Compute a combined threat score (0–100) from VT and AbuseIPDB data."""
    vt_mal = vt_stats.get("malicious", 0) + vt_stats.get("suspicious", 0) if vt_stats else 0
    score = min(100, vt_mal * 10 + abuse_score)
    return int(score)
