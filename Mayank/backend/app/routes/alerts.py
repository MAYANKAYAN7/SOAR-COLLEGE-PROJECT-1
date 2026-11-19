import asyncio
from datetime import datetime
from fastapi import APIRouter, Depends
from app.routes import cases as cases_mod
from app.routes.timeline import timeline_db
from app.core.database import db_save_alert, db_save_case, db_save_timeline_event, db_fetch_alerts
from app.core.security import get_current_user

router = APIRouter(prefix="/alerts", tags=["Alerts"])
alerts = []


def _now():
    return datetime.now().isoformat(timespec="seconds")


async def ensure_alerts_loaded():
    """Ensure alerts cache is populated from MongoDB Atlas."""
    global alerts
    if not alerts:
        db_alerts = await db_fetch_alerts()
        if db_alerts:
            alerts.clear()
            alerts.extend(reversed(db_alerts))
    return alerts


def record_alert(alert, enriched, actions, response_ms=None):
    risk = enriched["risk"]
    # Any simulated security alert or High/Critical risk triggers an incident case in SOAR
    is_incident = risk in ("Critical", "High", "Medium") or alert.alert_type in (
        "Malware", "Brute Force", "Phishing", "Port Scan", "DDoS", "SQL Injection", "Ransomware", "Data Exfiltration"
    )
    effective_severity = risk if risk in ("Critical", "High", "Medium") else ("Medium" if is_incident else "Low")
    status_label = "Contained" if risk in ("Critical", "High") else ("Active" if is_incident else "Monitoring")

    next_alert_id = max((int(a.get("alert_id", 0)) for a in alerts if isinstance(a, dict)), default=0) + 1

    entry = {
        "alert_id": next_alert_id,
        "source_ip": alert.source_ip,
        "alert_type": alert.alert_type,
        "severity": effective_severity,
        "status": status_label,
        "abuse_score": enriched["abuse_score"],
        "country": enriched["country"],
        "isp": enriched["isp"],
        "time": _now(),
        "playbook_actions": actions,
        "case_id": None,
        "response_ms": response_ms
    }

    if is_incident:
        case_id = max((int(c.get("case_id", 0)) for c in cases_mod.cases if isinstance(c, dict)), default=0) + 1
        case_data = {
            "case_id": case_id,
            "title": f"{alert.alert_type} from {alert.source_ip}",
            "severity": effective_severity,
            "status": "Open",
            "assigned_to": "Unassigned",
            "created_at": _now()
        }
        cases_mod.cases.append(case_data)

        actions_summary = ", ".join(actions.keys()) if isinstance(actions, dict) else "Executed"
        if isinstance(actions, dict) and "host" in actions:
            host_act = actions["host"]
            playbook_action_desc = f"Automated Playbook executed: {host_act.get('edr_platform', 'Wazuh EDR')} isolated {host_act.get('agent_id', 'Agent-001')} ({host_act.get('command', 'firewall-drop')}) & blocked IP"
        else:
            playbook_action_desc = f"Automated Playbook executed ({actions_summary})"

        t_events = [
            {"timestamp": _now(), "action": f"Alert detected: {alert.alert_type} from {alert.source_ip}", "performed_by": "Detection Engine"},
            {"timestamp": _now(), "action": f"Threat-Intel lookup: Risk {risk} (Abuse Score: {enriched['abuse_score']}/100, Country: {enriched['country']}, ISP: {enriched['isp']})", "performed_by": "Threat Intel"},
            {"timestamp": _now(), "action": playbook_action_desc, "performed_by": "SOAR Playbook Engine"},
            {"timestamp": _now(), "action": f"Incident Case #{case_id} registered and marked Open for investigation", "performed_by": "SOAR Core"}
        ]
        timeline_db[case_id] = t_events
        entry["case_id"] = case_id

        # Async persist case & timeline to MongoDB
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(db_save_case(case_data))
            for ev in t_events:
                loop.create_task(db_save_timeline_event(case_id, ev))
        except RuntimeError:
            pass

    alerts.append(entry)

    # Async persist alert to MongoDB
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(db_save_alert(entry))
    except RuntimeError:
        pass

    return entry


@router.get("/")
async def list_alerts(user: dict = Depends(get_current_user)):
    global alerts
    if not alerts:
        db_alerts = await db_fetch_alerts()
        if db_alerts:
            alerts.clear()
            alerts.extend(reversed(db_alerts))
    return list(reversed(alerts))
