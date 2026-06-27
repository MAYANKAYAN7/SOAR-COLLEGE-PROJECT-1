from fastapi import APIRouter
from pydantic import BaseModel
from typing import List

router = APIRouter(
    prefix="/timeline",
    tags=["Timeline"]
)

timeline_db = {}


class TimelineEvent(BaseModel):
    action: str
    performed_by: str


@router.post("/{case_id}")
def add_event(case_id: int, event: TimelineEvent):

    if case_id not in timeline_db:
        timeline_db[case_id] = []

    timeline_db[case_id].append(event.dict())

    return {
        "message": "Timeline event added",
        "case_id": case_id,
        "timeline": timeline_db[case_id]
    }


@router.get("/{case_id}")
def get_timeline(case_id: int):

    return {
        "case_id": case_id,
        "timeline": timeline_db.get(case_id, [])
    }