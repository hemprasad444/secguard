import os
import shutil
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.middleware.auth import get_current_user, require_role
from app.models.scan import Scan
from app.models.project import Project
from app.models.finding import Finding
from app.models.user import User
from app.schemas.scan import ScanTrigger, ScanResponse
from app.schemas.finding import FindingResponse
from app.tasks.scan_tasks import run_scan_task

router = APIRouter(prefix="/api/scans", tags=["scans"])

TOOL_SCAN_TYPE_MAP: dict[str, str] = {
    "trivy": "dependency",
    "gitleaks": "secrets",
    "semgrep": "sast",
    "kubescape": "k8s",
    "zap": "dast",
}


@router.post("/trigger", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def trigger_scan(
    body: ScanTrigger,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("security_engineer")),
):
    """Trigger a new security scan. Requires security_engineer role."""
    scan_type = TOOL_SCAN_TYPE_MAP.get(body.tool_name)
    if scan_type is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported tool: {body.tool_name}. Supported tools: {list(TOOL_SCAN_TYPE_MAP.keys())}",
        )
    # Override scan_type for Trivy K8s scans
    if body.tool_name == "trivy" and body.config and body.config.get("scan_subtype") == "k8s":
        scan_type = "k8s"

    scan = Scan(
        project_id=body.project_id,
        tool_name=body.tool_name,
        scan_type=scan_type,
        status="pending",
        triggered_by=current_user.id,
        config_json=body.config or {},
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)
    await db.commit()  # commit before dispatching so worker can find the row

    run_scan_task.delay(str(scan.id))

    return scan


@router.post("/trigger-image-upload", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def trigger_image_upload_scan(
    project_id: UUID = Form(...),
    registry_username: str = Form(""),
    registry_password: str = Form(""),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("security_engineer")),
):
    """Upload a Docker image tar/tar.gz and scan it with Trivy."""
    if not file.filename.endswith((".tar", ".tar.gz", ".tgz")):
        raise HTTPException(status_code=400, detail="Only .tar, .tar.gz, or .tgz files are supported.")

    upload_dir = os.path.join(settings.UPLOAD_DIR, "images")
    os.makedirs(upload_dir, exist_ok=True)
    dest = os.path.join(upload_dir, f"{project_id}_{file.filename}")

    with open(dest, "wb") as f:
        shutil.copyfileobj(file.file, f)

    config = {"scan_type": "image", "target": dest}
    if registry_username:
        config["registry_username"] = registry_username
    if registry_password:
        config["registry_password"] = registry_password

    scan = Scan(
        project_id=project_id,
        tool_name="trivy",
        scan_type="dependency",
        status="pending",
        triggered_by=current_user.id,
        config_json=config,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)
    await db.commit()  # commit before dispatching so worker can find the row

    run_scan_task.delay(str(scan.id))
    return scan


@router.get("/", response_model=list[ScanResponse])
async def list_scans(
    project_id: UUID | None = Query(None),
    tool_name: str | None = Query(None),
    status: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List scans with optional filters and pagination."""
    offset = (page - 1) * page_size
    query = select(Scan)

    if project_id is not None:
        query = query.where(Scan.project_id == project_id)
    if tool_name is not None:
        query = query.where(Scan.tool_name == tool_name)
    if status is not None:
        query = query.where(Scan.status == status)

    # Tenant isolation: filter scans by org_id through the project relationship
    if current_user.org_id:
        org_project_ids = select(Project.id).where(Project.org_id == current_user.org_id).scalar_subquery()
        query = query.where(Scan.project_id.in_(org_project_ids))

    query = query.order_by(Scan.created_at.desc()).offset(offset).limit(page_size)
    result = await db.execute(query)
    scans = list(result.scalars().all())

    # Compute unique package counts for completed scans in one batch query
    completed_ids = [s.id for s in scans if s.status == "completed" and s.findings_count > 0]
    if completed_ids:
        pkg_rows = await db.execute(
            select(
                Finding.scan_id,
                func.count(
                    func.distinct(
                        func.concat(
                            func.coalesce(Finding.raw_data["PkgName"].astext, ""),
                            "||",
                            func.coalesce(Finding.raw_data["InstalledVersion"].astext, ""),
                        )
                    )
                ).label("cnt"),
            )
            .where(Finding.scan_id.in_(completed_ids))
            .where(Finding.raw_data["PkgName"].astext.isnot(None))
            .group_by(Finding.scan_id)
        )
        pkg_map = {row.scan_id: row.cnt for row in pkg_rows.all()}
        for scan in scans:
            if scan.id in pkg_map:
                scan.config_json = {**(scan.config_json or {}), "unique_packages_count": pkg_map[scan.id]}

    return scans


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("security_engineer")),
):
    """Delete a scan and all its findings. Requires security_engineer role."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    # Delete associated findings first (FK constraint)
    findings_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    for finding in findings_result.scalars().all():
        await db.delete(finding)

    await db.delete(scan)
    await db.commit()


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a single scan by ID."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


@router.get("/{scan_id}/sbom")
async def get_scan_sbom(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get SBOM output for an SBOM scan."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan.output_data or {}


@router.get("/{scan_id}/findings", response_model=list[FindingResponse])
async def get_scan_findings(
    scan_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get all findings for a specific scan, paginated."""
    # Verify the scan exists
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    offset = (page - 1) * page_size
    result = await db.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    findings = result.scalars().all()
    return findings
