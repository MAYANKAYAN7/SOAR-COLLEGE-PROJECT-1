import asyncio
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from app.core.database import db_save_timeline_event, db_fetch_timeline
from app.core.security import get_current_user

router = APIRouter(
    prefix="/timeline",
    tags=["Timeline"]
)

timeline_db = {}


class TimelineEvent(BaseModel):
    action: str
    performed_by: str
    timestamp: Optional[str] = None


@router.post("/{case_id}")
async def add_event(case_id: int, event: TimelineEvent, user: dict = Depends(get_current_user)):
    if case_id not in timeline_db:
        # Attempt to load existing events from MongoDB
        db_events = await db_fetch_timeline(case_id)
        timeline_db[case_id] = db_events if db_events else []

    ev_dict = event.dict()
    if not ev_dict.get("timestamp"):
        ev_dict["timestamp"] = datetime.now().isoformat(timespec="seconds")
    if not ev_dict.get("performed_by") or ev_dict.get("performed_by") == "system":
        ev_dict["performed_by"] = user.get("sub", "analyst")

    timeline_db[case_id].append(ev_dict)
    await db_save_timeline_event(case_id, ev_dict)

    return {
        "message": "Timeline event added",
        "case_id": case_id,
        "timeline": timeline_db[case_id]
    }


@router.get("/{case_id}")
async def get_timeline(case_id: int, user: dict = Depends(get_current_user)):
    if case_id not in timeline_db or not timeline_db[case_id]:
        db_events = await db_fetch_timeline(case_id)
        if db_events:
            timeline_db[case_id] = db_events

    return {
        "case_id": case_id,
        "timeline": timeline_db.get(case_id, [])
    }

