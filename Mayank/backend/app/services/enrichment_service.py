from app.services.abuseipdb_service import check_ip_reputation
from app.services.risk_engine import calculate_risk

def enrich_alert(ip):

    reputation = check_ip_reputation(ip)

    score = reputation["data"]["abuseConfidenceScore"]

    risk = calculate_risk(score)

    return {
        "abuse_score": score,
        "risk": risk,
        "country": reputation["data"]["countryCode"],
        "isp": reputation["data"]["isp"]
    }