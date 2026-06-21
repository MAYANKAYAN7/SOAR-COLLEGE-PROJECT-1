from app.services.abuseipdb_service import check_ip_reputation
from app.services.virustotal_service import check_ip
from app.services.risk_engine import calculate_risk

def enrich_alert(ip):

    # AbuseIPDB
    abuse_data = check_ip_reputation(ip)

    abuse_score = abuse_data["data"]["abuseConfidenceScore"]

    # VirusTotal
    vt_data = check_ip(ip)

    vt_stats = vt_data["data"]["attributes"]["last_analysis_stats"]

    # Risk
    risk = calculate_risk(abuse_score)

    return {
        "abuse_score": abuse_score,
        "risk": risk,
        "country": abuse_data["data"]["countryCode"],
        "isp": abuse_data["data"]["isp"],
        "vt_malicious": vt_stats["malicious"],
        "vt_harmless": vt_stats["harmless"]
    }