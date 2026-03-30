from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ControlFixResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    control_id: str
    title: str
    scanner: str
    description: Optional[str] = None
    patch_type: str
    applicable_kinds: Optional[List[str]] = None
    patch_template: str
    notes: Optional[str] = None
    risk_level: str
    created_at: datetime


class ControlFixCreate(BaseModel):
    control_id: str
    title: str
    scanner: str
    description: Optional[str] = None
    patch_type: str = "strategic_merge"
    applicable_kinds: Optional[List[str]] = None
    patch_template: str
    notes: Optional[str] = None
    risk_level: str = "low"


class GeneratedPatchResponse(BaseModel):
    control_id: str
    title: str
    patch_type: str
    resource_kind: str
    resource_name: str
    namespace: str
    patch_yaml: str
    kubectl_command: str
    notes: Optional[str] = None
    risk_level: str = "low"
