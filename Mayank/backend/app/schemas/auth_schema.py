"""
Pydantic schemas for authentication.
"""
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(..., examples=["analyst"])
    password: str = Field(..., examples=["analyst123"])


class LoginResponse(BaseModel):
    message: str
    username: str
    role: str
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    username: str
    role: str

