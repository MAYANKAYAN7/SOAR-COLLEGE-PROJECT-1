from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)

users = {
    "analyst": {
        "password": "analyst123",
        "role": "Analyst"
    },
    "senior": {
        "password": "senior123",
        "role": "Senior Analyst"
    },
    "admin": {
        "password": "admin123",
        "role": "Admin"
    }
}


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(request: LoginRequest):

    user = users.get(request.username)

    if not user or user["password"] != request.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {
        "message": "Login successful",
        "username": request.username,
        "role": user["role"]
    }


@router.get("/users")
def get_users():

    return [
        {"username": username, "role": info["role"]}
        for username, info in users.items()
    ]


@router.post("/approve-playbook")
def approve_playbook(role: str):

    if role != "Senior Analyst" and role != "Admin":
        raise HTTPException(
            status_code=403,
            detail="Approval denied"
        )

    return {
        "message": "Playbook approved",
        "approved_by": role
    }