import ipaddress

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def normalize_alert(data):
    ip = data.get("source_ip") or data.get("ip")

    return {
        "alert_type": data.get("alert_type"),
        "source_ip": ip,
        "ip_valid": validate_ip(ip),
        "timestamp": data.get("timestamp") or data.get("time")
    }