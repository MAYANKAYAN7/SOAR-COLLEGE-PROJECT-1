from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def health():
    return {"status": "SOAR Backend Running"}

@app.post("/alert")
def receive_alert(alert: dict):
    return {
        "message":"Alert Received",
        "data":alert
    }