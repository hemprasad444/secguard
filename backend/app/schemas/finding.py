from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scan_id: Optional[UUID] = None
    project_id: UUID
    tool_name: str
    severity: str
    title: str
    description: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    status: str
    assigned_to: Optional[UUID] = None
    fingerprint: Optional[str] = None
    remediation: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None
    resolved_at: Optional[datetime] = None
    closed_by: Optional[UUID] = None
    close_reason: Optional[str] = None
    justification: Optional[str] = None
    closed_at: Optional[datetime] = None
    created_at: datetime


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[UUID] = None


class FindingCloseRequest(BaseModel):
    """Close a finding with a reason and optional justification."""
    status: str  # resolved, accepted, false_positive
    close_reason: str  # rescan_verified, accepted_risk, false_positive, manual_fix
    justification: Optional[str] = None


class FindingReopenRequest(BaseModel):
    justification: Optional[str] = None


class VerifyResponse(BaseModel):
    verified: bool
    message: str
    finding: Optional[FindingResponse] = None


class FindingBulkUpdate(BaseModel):
    ids: List[UUID]
    status: Optional[str] = None
    assigned_to: Optional[UUID] = None


class FindingFilters(BaseModel):
    severity: Optional[str] = None
    tool_name: Optional[str] = None
    status: Optional[str] = None
    project_id: Optional[UUID] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
