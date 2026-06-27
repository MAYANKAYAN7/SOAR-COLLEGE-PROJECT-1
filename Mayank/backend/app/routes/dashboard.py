from fastapi import APIRouter

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"]
)

dashboard_data = {
    "total_alerts": 150,
    "critical_alerts": 12,
    "high_alerts": 25,
    "medium_alerts": 45,
    "low_alerts": 68,
    "open_cases": 18,
    "resolved_cases": 132,
    "playbooks_executed": 95
}

@router.get("/")
def get_dashboard():
    return dashboard_data