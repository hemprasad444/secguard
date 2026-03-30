from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    uploaded_by: Optional[UUID] = None
    file_name: str
    tool_name: Optional[str] = None
    parsed: bool
    findings_count: int
    created_at: datetime
