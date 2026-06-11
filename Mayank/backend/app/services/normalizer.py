def normalize_alert(data):
    return {
        "alert_type": data.get("alert_type"),
        "source_ip": data.get("source_ip") or data.get("ip"),
        "timestamp": data.get("timestamp") or data.get("time")
    }