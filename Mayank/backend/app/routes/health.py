from fastapi import APIRouter
from datetime import datetime

router = APIRouter(
    prefix="/health",
    tags=["Health"]
)

@router.get("/")
def health_check():

    return {
        "status": "Running",
        "application": "SOAR Incident Containment Engine",
        "version": "1.0",
        "database": "Connected",
        "server_time": datetime.now().isoformat()
    }