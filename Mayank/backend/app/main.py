import time

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.core.exception import validation_exception_handler, generic_exception_handler
from app.core.logger import logger
from app.playbooks.playbook_engine import execute_playbook
from app.routes.alerts import router as alert_router, record_alert
from app.routes.auth import router as auth_router
from app.routes.cases import router as case_router
from app.routes.dashboard import router as dashboard_router
from app.routes.health import router as health_router
from app.routes.timeline import router as timeline_router
from app.schemas.alert_schema import Alert
from app.services.enrichment_service import enrich_alert

app = FastAPI(title="SOAR Incident Containment Engine")
for r in (alert_router, case_router, dashboard_router, timeline_router, auth_router, health_router):
    app.include_router(r)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, generic_exception_handler)
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
async def dashboard():
    return FileResponse("static/dashboard.html")


@app.post("/alert")
def receive_alert(alert: Alert):
    t0 = time.perf_counter()
    logger.info(f"Alert received from {alert.source_ip}")
    try:
        enriched = enrich_alert(alert.source_ip)
    except Exception as exc:  # network error, bad key, rate limit, unknown IP
        logger.error(f"Enrichment failed for {alert.source_ip}: {exc}")
        raise HTTPException(status_code=502, detail="Threat-intel lookup failed. Check the API keys and network.")
    actions = execute_playbook({"risk": enriched["risk"], "source_ip": alert.source_ip, "hostname": "SERVER-01"})
    entry = record_alert(alert, enriched, actions, round((time.perf_counter() - t0) * 1000))
    return {"alert_type": alert.alert_type, "source_ip": alert.source_ip, **enriched,
            "playbook_actions": actions, "alert_id": entry["alert_id"], "case_id": entry["case_id"]}
