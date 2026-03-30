import os
import uuid as uuid_mod
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user, require_role
from app.models.report import Report
from app.models.user import User
from app.schemas.report import ReportResponse
from app.tasks.scan_tasks import parse_report_task

router = APIRouter(prefix="/api/reports", tags=["reports"])

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/tmp/secguard_uploads")


@router.post("/upload", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
async def upload_report(
    project_id: UUID = Form(...),
    tool_name: str = Form(...),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("security_engineer")),
):
    """Upload a report file. Requires security_engineer role."""
    # Ensure upload directory exists
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    # Generate unique filename
    file_uuid = uuid_mod.uuid4()
    safe_filename = f"{file_uuid}_{file.filename}"
    file_path = os.path.join(UPLOAD_DIR, safe_filename)

    # Save the uploaded file
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)

    # Create the report record
    report = Report(
        project_id=project_id,
        tool_name=tool_name,
        file_path=file_path,
        original_filename=file.filename,
        status="pending",
        uploaded_by=current_user.id,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    # Dispatch the parse task to Celery
    parse_report_task.delay(str(report.id))

    return report


@router.get("/", response_model=list[ReportResponse])
async def list_reports(
    project_id: UUID | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List reports with optional project_id filter, paginated."""
    offset = (page - 1) * page_size
    query = select(Report)

    if project_id is not None:
        query = query.where(Report.project_id == project_id)

    query = query.order_by(Report.created_at.desc()).offset(offset).limit(page_size)
    result = await db.execute(query)
    reports = result.scalars().all()
    return reports


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a single report by ID."""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report
