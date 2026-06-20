from fastapi import FastAPI
from app.schemas.alert_schema import Alert
from app.services.normalizer import normalize_alert
from app.services.ioc_extractor import extract_iocs
from app.services.abuseipdb_service import check_ip_reputation
from app.services.risk_engine import calculate_risk
from app.services.enrichment_service import enrich_alert


app = FastAPI()

@app.get("/")
def health():
    return {"status": "SOAR Backend Running"}

@app.post("/alert")
def receive_alert(alert: Alert):

    enriched = enrich_alert(alert.source_ip)

    return {
        "alert_type": alert.alert_type,
        "source_ip": alert.source_ip,
        **enriched
    }