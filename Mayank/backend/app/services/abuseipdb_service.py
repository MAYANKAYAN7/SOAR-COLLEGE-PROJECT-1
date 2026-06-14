import requests

API_KEY = "c8712d700e8db10911322b1d04d96cfc686c23b358826073d8ae6cc1217e388d928e83e78317ac5c"

def check_ip_reputation(ip):

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(
        url,
        headers=headers,
        params=params
    )

    return response.json()