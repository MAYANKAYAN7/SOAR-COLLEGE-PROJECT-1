import requests

API_KEY = "a04fe867fe56e309b5fcc7e16434d95c46af78031b2077d88adab46b15ab973f"

def check_ip(ip):

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)

    return response.json()