from fastapi import APIRouter, Depends
from app.routes.alerts import alerts
from app.routes.cases import cases, ensure_cases_loaded
from app.core.database import db_fetch_alerts
from app.core.security import get_current_user

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/")
async def get_dashboard(user: dict = Depends(get_current_user)):
    await ensure_cases_loaded()
    global alerts
    if not alerts:
        db_alerts = await db_fetch_alerts()
        if db_alerts:
            alerts.extend(reversed(db_alerts))
    count = lambda s: sum(1 for a in alerts if a.get("severity") == s)
    return {
        "total_alerts": len(alerts),
        "critical_alerts": count("Critical"),
        "high_alerts": count("High"),
        "medium_alerts": count("Medium"),
        "low_alerts": count("Low"),
        "open_cases": sum(1 for c in cases if c.get("status") != "Resolved"),
        "resolved_cases": sum(1 for c in cases if c.get("status") == "Resolved"),
        "playbooks_executed": sum(1 for a in alerts if a.get("severity") in ("Critical", "High", "Medium"))
    }
