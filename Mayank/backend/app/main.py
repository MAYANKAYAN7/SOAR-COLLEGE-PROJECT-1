from fastapi import FastAPI
from app.schemas.alert_schema import Alert
from app.services.normalizer import normalize_alert

app = FastAPI()

@app.get("/")
def health():
    return {"status": "SOAR Backend Running"}

@app.post("/alert")
def receive_alert(alert: Alert):

    normalized = normalize_alert(alert.model_dump())

    return {
        "message": "Normalized Alert",
        "alert": normalized
    }