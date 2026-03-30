from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ScanTrigger(BaseModel):
    project_id: UUID
    tool_name: str
    config: Optional[Dict[str, Any]] = None


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    tool_name: str
    scan_type: str
    status: str
    triggered_by: Optional[UUID] = None
    findings_count: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    output_data: Optional[Dict[str, Any]] = None
    config_json: Optional[Dict[str, Any]] = None
    created_at: datetime


class ScanScheduleCreate(BaseModel):
    project_id: UUID
    tool_name: str
    cron_expression: str


class ScanScheduleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    tool_name: str
    cron_expression: str
    enabled: bool
    last_run_at: Optional[datetime] = None
    created_at: datetime
