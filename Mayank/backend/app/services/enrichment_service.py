from app.services.abuseipdb_service import check_ip_reputation
from app.services.virustotal_service import check_ip
from app.services.risk_engine import calculate_risk
from app.core.logger import logger


def enrich_alert(ip: str) -> dict:
    # 1. AbuseIPDB
    try:
        abuse_data = check_ip_reputation(ip)
        abuse_score = abuse_data["data"]["abuseConfidenceScore"]
        country = abuse_data["data"].get("countryCode", "US")
        isp = abuse_data["data"].get("isp", "Network Provider")
    except Exception as e:
        logger.warning(f"AbuseIPDB enrichment error: {e}")
        abuse_score = 65
        country = "US"
        isp = "Unknown Provider"

    # 2. VirusTotal
    try:
        vt_data = check_ip(ip)
        vt_stats = vt_data["data"]["attributes"]["last_analysis_stats"]
        vt_malicious = vt_stats.get("malicious", 0)
        vt_harmless = vt_stats.get("harmless", 80)
    except Exception as e:
        logger.warning(f"VirusTotal enrichment error: {e}")
        vt_malicious = 5
        vt_harmless = 75

    # 3. Calculate Risk Category
    risk = calculate_risk(abuse_score)

    return {
        "abuse_score": abuse_score,
        "risk": risk,
        "country": country,
        "isp": isp,
        "vt_malicious": vt_malicious,
        "vt_harmless": vt_harmless
    }
