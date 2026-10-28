import os
import requests

API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")


def check_ip_reputation(ip):
    r = requests.get("https://api.abuseipdb.com/api/v2/check",
                     headers={"Key": API_KEY, "Accept": "application/json"},
                     params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=10)
    r.raise_for_status()
    return r.json()
