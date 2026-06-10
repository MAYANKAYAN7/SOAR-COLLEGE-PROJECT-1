from fastapi import FastAPI
from app.schemas.alert_schema import Alert

app = FastAPI()

@app.get("/")
def health():
    return {"status": "SOAR Backend Running"}

@app.post("/alert")
def receive_alert(alert: Alert):
    return {
        "message": "Alert Received",
        "alert": alert
    }