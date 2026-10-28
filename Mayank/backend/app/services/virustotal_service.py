import os
import requests

API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")


def check_ip(ip):
    r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                     headers={"x-apikey": API_KEY}, timeout=10)
    r.raise_for_status()
    return r.json()
