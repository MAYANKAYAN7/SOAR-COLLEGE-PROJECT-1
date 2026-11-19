import asyncio
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
from app.core.database import db_save_case, db_update_case, db_delete_case, db_fetch_cases, db_save_timeline_event
from app.routes.timeline import timeline_db
from app.core.security import get_current_user, require_role

router = APIRouter(prefix="/cases", tags=["Case Management"])


class Case(BaseModel):
    title: str
    severity: str
    status: str
    assigned_to: str


class CaseCreate(BaseModel):
    title: str
    severity: str = "Medium"
    assigned_to: str = "Unassigned"


class CaseAssign(BaseModel):
    assigned_to: str


cases = []


async def ensure_cases_loaded():
    """Ensure cases are loaded from MongoDB Atlas if memory cache is empty."""
    global cases
    if not cases:
        db_cases = await db_fetch_cases()
        if db_cases:
            cases.clear()
            cases.extend(db_cases)
    return cases


@router.post("/")
async def create_case(case: CaseCreate, user: dict = Depends(get_current_user)):
    await ensure_cases_loaded()
    case_id = max((c["case_id"] for c in cases), default=0) + 1
    assigned = user.get("sub", "Unassigned") if case.assigned_to == "Unassigned" else case.assigned_to
    case_data = {
        "case_id": case_id,
        "title": case.title,
        "severity": case.severity,
        "status": "Open",
        "assigned_to": assigned,
        "created_at": datetime.now().isoformat()
    }
    cases.append(case_data)
    await db_save_case(case_data)

    return {
        "message": "Incident case created successfully",
        "case": case_data
    }


@router.get("/")
async def get_all_cases(user: dict = Depends(get_current_user)):
    await ensure_cases_loaded()
    return cases


@router.get("/{case_id}")
async def get_case(case_id: int, user: dict = Depends(get_current_user)):
    await ensure_cases_loaded()
    for case in cases:
        if case["case_id"] == case_id:
            return case
    raise HTTPException(status_code=404, detail="Case not found")


@router.put("/{case_id}")
async def update_case(case_id: int, updated_case: Case, user: dict = Depends(get_current_user)):
    await ensure_cases_loaded()
    for index, case in enumerate(cases):
        if case["case_id"] == case_id:
            cases[index] = {
                "case_id": case_id,
                **updated_case.dict()
            }
            await db_update_case(case_id, cases[index])
            return {
                "message": "Case updated successfully",
                "case": cases[index]
            }
    raise HTTPException(status_code=404, detail="Case not found")


@router.put("/{case_id}/assign")
async def assign_case(case_id: int, req: CaseAssign, user: dict = Depends(get_current_user)):
    await ensure_cases_loaded()
    for index, case in enumerate(cases):
        if case["case_id"] == case_id:
            old_assigned = cases[index].get("assigned_to", "Unassigned")
            cases[index]["assigned_to"] = req.assigned_to
            if cases[index]["status"] == "Open":
                cases[index]["status"] = "In Progress"
            await db_update_case(case_id, cases[index])

            # Append to timeline
            ev = {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "action": f"Case reassigned from {old_assigned} to {req.assigned_to}",
                "performed_by": user.get("sub", req.assigned_to)
            }
            if case_id not in timeline_db:
                timeline_db[case_id] = []
            timeline_db[case_id].append(ev)
            await db_save_timeline_event(case_id, ev)

            return {
                "message": f"Case assigned to {req.assigned_to}",
                "case": cases[index]
            }
    raise HTTPException(status_code=404, detail="Case not found")


@router.delete("/{case_id}")
async def delete_case(case_id: int, user: dict = Depends(require_role("Admin"))):
    await ensure_cases_loaded()
    for index, case in enumerate(cases):
        if case["case_id"] == case_id:
            deleted = cases.pop(index)
            await db_delete_case(case_id)
            return {
                "message": "Case deleted successfully",
                "case": deleted
            }
    raise HTTPException(status_code=404, detail="Case not found")
