from fastapi import APIRouter
from datetime import datetime
from app.core.database import get_db_info, is_mongo_connected, connect_db

router = APIRouter(
    prefix="/health",
    tags=["Health"]
)

@router.get("/")
async def health_check():
    if not is_mongo_connected():
        await connect_db()
    db_info = get_db_info()
    return {
        "status": "Running",
        "application": "SOAR Incident Containment Engine",
        "version": "1.0",
        "database": db_info["status"],
        "database_connected": db_info["connected"],
        "database_details": db_info,
        "server_time": datetime.now().isoformat()
    }
