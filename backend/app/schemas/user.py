from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr
    name: str
    password: str
    role: str = Field(default="viewer")


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    name: str
    role: str
    is_active: bool
    must_change_password: bool = False
    created_at: datetime
    org_id: UUID | None = None


class UserUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    must_change_password: bool = False


class AdminCreateUser(BaseModel):
    email: EmailStr
    name: str
    role: str = Field(default="viewer")
    password: Optional[str] = None  # auto-generated if omitted


class AdminCreateUserResult(BaseModel):
    user: UserResponse
    temporary_password: str  # shown once to the admin


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)
