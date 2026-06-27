from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List

router = APIRouter(prefix="/cases", tags=["Case Management"])


class Case(BaseModel):
    title: str
    severity: str
    status: str
    assigned_to: str


cases = []


@router.post("/")
def create_case(case: Case):
    case_data = case.dict()
    case_data["case_id"] = len(cases) + 1

    cases.append(case_data)

    return {
        "message": "Case created successfully",
        "case": case_data
    }


@router.get("/")
def get_all_cases():
    return cases


@router.get("/{case_id}")
def get_case(case_id: int):

    for case in cases:
        if case["case_id"] == case_id:
            return case

    raise HTTPException(status_code=404, detail="Case not found")


@router.put("/{case_id}")
def update_case(case_id: int, updated_case: Case):

    for index, case in enumerate(cases):

        if case["case_id"] == case_id:

            cases[index] = {
                "case_id": case_id,
                **updated_case.dict()
            }

            return {
                "message": "Case updated successfully",
                "case": cases[index]
            }

    raise HTTPException(status_code=404, detail="Case not found")


@router.delete("/{case_id}")
def delete_case(case_id: int):

    for index, case in enumerate(cases):

        if case["case_id"] == case_id:

            deleted = cases.pop(index)

            return {
                "message": "Case deleted successfully",
                "case": deleted
            }

    raise HTTPException(status_code=404, detail="Case not found")