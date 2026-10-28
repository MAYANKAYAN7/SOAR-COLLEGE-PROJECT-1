from datetime import datetime
from fastapi import APIRouter
from app.routes.cases import cases
from app.routes.timeline import timeline_db

router = APIRouter(prefix="/alerts", tags=["Alerts"])
alerts = []  # in-memory for now; move to a database next


def _now():
    return datetime.now().isoformat(timespec="seconds")


def record_alert(alert, enriched, actions, response_ms=None):
    risk = enriched["risk"]
    urgent = risk in ("Critical", "High")
    entry = {"alert_id": len(alerts) + 1, "source_ip": alert.source_ip, "alert_type": alert.alert_type,
             "severity": risk, "status": "Contained" if urgent else "Monitoring",
             "abuse_score": enriched["abuse_score"], "country": enriched["country"], "isp": enriched["isp"],
             "time": _now(), "playbook_actions": actions, "case_id": None,
             "response_ms": response_ms}
    if urgent:
        case_id = max((c["case_id"] for c in cases), default=0) + 1
        cases.append({"case_id": case_id, "title": f"{alert.alert_type} from {alert.source_ip}",
                      "severity": risk, "status": "Open", "assigned_to": "Unassigned"})
        timeline_db[case_id] = [
            {"timestamp": _now(), "action": "Alert received", "performed_by": "system"},
            {"timestamp": _now(), "action": f"Risk scored {risk} (abuse score {enriched['abuse_score']})", "performed_by": "system"},
            {"timestamp": _now(), "action": "Playbook executed", "performed_by": "system"},
            {"timestamp": _now(), "action": "Case opened", "performed_by": "system"}]
        entry["case_id"] = case_id
    alerts.append(entry)
    return entry


@router.get("/")
def list_alerts():
    return list(reversed(alerts))
