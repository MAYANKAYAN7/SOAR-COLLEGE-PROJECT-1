import re

def extract_iocs(text):

    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)

    domains = re.findall(
        r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
        text
    )

    return {
        "ips": ips,
        "domains": domains
    }