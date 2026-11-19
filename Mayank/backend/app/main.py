import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.core.exception import validation_exception_handler, generic_exception_handler
from app.core.logger import logger
from app.core.database import (
    connect_db, close_db, is_mongo_connected,
    db_fetch_alerts, db_fetch_cases
)
from app.playbooks.playbook_engine import execute_playbook
from app.routes.alerts import router as alert_router, record_alert, alerts, ensure_alerts_loaded
from app.routes.auth import router as auth_router
from app.routes.cases import router as case_router, cases, ensure_cases_loaded
from app.routes.dashboard import router as dashboard_router
from app.routes.health import router as health_router
from app.routes.timeline import router as timeline_router
from app.schemas.alert_schema import Alert
from app.services.enrichment_service import enrich_alert

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="SOAR Incident Containment Engine")


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    return response


for r in (alert_router, case_router, dashboard_router, timeline_router, auth_router, health_router):
    app.include_router(r)

app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, generic_exception_handler)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.on_event("startup")
async def on_startup():
    connected = await connect_db()
    if connected:
        # Load any existing documents from MongoDB into memory
        try:
            mongo_alerts = await db_fetch_alerts()
            if mongo_alerts:
                alerts.clear()
                alerts.extend(reversed(mongo_alerts))
                logger.info(f"Loaded {len(alerts)} alerts from MongoDB.")

            mongo_cases = await db_fetch_cases()
            if mongo_cases:
                cases.clear()
                cases.extend(mongo_cases)
                logger.info(f"Loaded {len(cases)} cases from MongoDB.")
        except Exception as e:
            logger.error(f"Error hydrating data from MongoDB: {e}")


@app.on_event("shutdown")
async def on_shutdown():
    await close_db()


@app.get("/")
async def dashboard():
    return FileResponse(str(STATIC_DIR / "dashboard.html"))


@app.post("/alert")
async def receive_alert(alert: Alert):
    t0 = time.perf_counter()
    logger.info(f"Alert received from {alert.source_ip}")
    await ensure_cases_loaded()
    await ensure_alerts_loaded()
    try:
        enriched = enrich_alert(alert.source_ip)
    except Exception as exc:
        logger.warning(f"Enrichment error for {alert.source_ip}: {exc}. Using fallback enrichment.")
        enriched = {
            "abuse_score": 65,
            "risk": "High",
            "country": "US",
            "isp": "Simulation Provider",
            "vt_malicious": 5,
            "vt_harmless": 75
        }
    actions = execute_playbook({"risk": enriched["risk"], "source_ip": alert.source_ip, "hostname": "SERVER-01"})
    entry = record_alert(alert, enriched, actions, round((time.perf_counter() - t0) * 1000))
    return {
        "alert_type": alert.alert_type,
        "source_ip": alert.source_ip,
        **enriched,
        "playbook_actions": actions,
        "alert_id": entry["alert_id"],
        "case_id": entry["case_id"]
    }
