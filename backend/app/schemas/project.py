from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ProjectCreate(BaseModel):
    name: str
    repo_url: Optional[str] = None
    description: Optional[str] = None


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    repo_url: Optional[str] = None
    description: Optional[str] = None


class ProjectResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    repo_url: Optional[str] = None
    description: Optional[str] = None
    created_by: Optional[UUID] = None
    created_at: datetime

    # SonarQube — token never returned, only "configured" hint
    sonarqube_url: Optional[str] = None
    sonarqube_project_key: Optional[str] = None
    sonarqube_token_configured: bool = False
    sonarqube_last_synced_at: Optional[datetime] = None


class SonarQubeConfig(BaseModel):
    """Write-only payload for configuring SonarQube on a project."""
    url: str
    project_key: str
    token: Optional[str] = None  # omit to keep existing token unchanged

