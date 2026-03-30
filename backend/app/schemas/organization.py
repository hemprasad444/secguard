from pydantic import BaseModel, ConfigDict
from uuid import UUID
from datetime import datetime
from typing import Optional

class OrgCreate(BaseModel):
    name: str
    slug: str
    description: Optional[str] = None

class OrgResponse(BaseModel):
    id: UUID
    name: str
    slug: str
    description: Optional[str]
    is_active: bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class SignUpRequest(BaseModel):
    org_name: str
    org_slug: str
    admin_name: str
    admin_email: str
    admin_password: str
