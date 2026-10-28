from fastapi import APIRouter
from app.routes.alerts import alerts
from app.routes.cases import cases

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/")
def get_dashboard():
    count = lambda s: sum(1 for a in alerts if a["severity"] == s)
    return {"total_alerts": len(alerts), "critical_alerts": count("Critical"), "high_alerts": count("High"),
            "medium_alerts": count("Medium"), "low_alerts": count("Low"),
            "open_cases": sum(1 for c in cases if c["status"] != "Resolved"),
            "resolved_cases": sum(1 for c in cases if c["status"] == "Resolved"),
            "playbooks_executed": sum(1 for a in alerts if a["severity"] in ("Critical", "High"))}
