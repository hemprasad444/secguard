from uuid import UUID

import yaml
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user, require_role, get_current_org_id
from app.models.finding import Finding
from app.models.project import Project
from app.models.report import Report
from app.models.scan import Scan
from app.models.user import User
from app.schemas.project import ProjectCreate, ProjectUpdate, ProjectResponse, SonarQubeConfig

router = APIRouter(prefix="/api/projects", tags=["projects"])


@router.get("/", response_model=list[ProjectResponse])
async def list_projects(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all projects with pagination."""
    offset = (page - 1) * page_size
    query = select(Project)
    if current_user.org_id:
        query = query.where(Project.org_id == current_user.org_id)
    query = query.order_by(Project.created_at.desc()).offset(offset).limit(page_size)
    result = await db.execute(query)
    projects = result.scalars().all()
    return projects


@router.post("/", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    body: ProjectCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("security_engineer")),
):
    """Create a new project. Requires security_engineer role."""
    project = Project(**body.model_dump(), created_by=current_user.id, org_id=current_user.org_id)
    db.add(project)
    await db.commit()
    await db.refresh(project)
    return project


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a single project by ID."""
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return project


@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: UUID,
    body: ProjectUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("security_engineer")),
):
    """Update a project. Requires security_engineer role."""
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    update_data = body.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(project, field, value)

    await db.commit()
    await db.refresh(project)
    return project


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Delete a project and all associated data. Requires admin role."""
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    # Delete related records before the project (no DB-level cascade)
    await db.execute(delete(Finding).where(Finding.project_id == project_id))
    await db.execute(delete(Report).where(Report.project_id == project_id))
    await db.execute(delete(Scan).where(Scan.project_id == project_id))
    await db.delete(project)
    await db.commit()


# ── Kubeconfig management ────────────────────────────────────────────────────

@router.put("/{project_id}/kubeconfig")
async def upload_kubeconfig(
    project_id: UUID,
    kubeconfig: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("security_engineer")),
):
    """Upload a kubeconfig file for K8s scanning."""
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    content = await kubeconfig.read()
    try:
        parsed = yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}")

    if not isinstance(parsed, dict) or "clusters" not in parsed:
        raise HTTPException(status_code=400, detail="Invalid kubeconfig: missing 'clusters' key")

    project.kubeconfig_data = parsed
    await db.commit()
    return {
        "status": "ok",
        "clusters": len(parsed.get("clusters", [])),
        "contexts": len(parsed.get("contexts", [])),
    }


@router.delete("/{project_id}/kubeconfig", status_code=status.HTTP_204_NO_CONTENT)
async def delete_kubeconfig(
    project_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("security_engineer")),
):
    """Remove stored kubeconfig for a project."""
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    project.kubeconfig_data = None
    await db.commit()


@router.get("/{project_id}/kubeconfig/status")
async def kubeconfig_status(
    project_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Check whether a kubeconfig is configured for a project."""
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    configured = project.kubeconfig_data is not None
    clusters = len(project.kubeconfig_data.get("clusters", [])) if configured else 0
    return {"configured": configured, "clusters": clusters}


# ── SonarQube integration ────────────────────────────────────────────────────

@router.put("/{project_id}/sonarqube", response_model=ProjectResponse)
async def configure_sonarqube(
    project_id: UUID,
    config: SonarQubeConfig,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("security_engineer")),
):
    """Persist SonarQube URL/project key/token on a project. Token is optional on update."""
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    project.sonarqube_url = config.url.rstrip("/") if config.url else None
    project.sonarqube_project_key = config.project_key or None
    if config.token is not None:
        # Allow clearing the token by sending an empty string
        project.sonarqube_token = config.token or None
    await db.commit()
    await db.refresh(project)
    return project


@router.delete("/{project_id}/sonarqube", status_code=status.HTTP_204_NO_CONTENT)
async def remove_sonarqube(
    project_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("security_engineer")),
):
    """Disconnect SonarQube from a project (clears URL, key, token)."""
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    project.sonarqube_url = None
    project.sonarqube_project_key = None
    project.sonarqube_token = None
    await db.commit()


@router.post("/{project_id}/sonarqube/test")
async def test_sonarqube(
    project_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Test the configured SonarQube connection (auth + ping)."""
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not project.sonarqube_url:
        raise HTTPException(status_code=400, detail="SonarQube URL not configured")

    # ping is sync — run in default executor to avoid blocking the event loop
    import asyncio
    from app.integrations.sonarqube import ping
    ok, detail = await asyncio.to_thread(ping, project.sonarqube_url, project.sonarqube_token)
    return {"ok": ok, "detail": detail}


@router.post("/{project_id}/sonarqube/sync")
async def sync_sonarqube(
    project_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("security_engineer")),
):
    """Queue a celery task to pull the latest SonarQube issues for the project."""
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not project.sonarqube_url or not project.sonarqube_project_key:
        raise HTTPException(status_code=400, detail="SonarQube URL and project key are required")

    from app.tasks.scan_tasks import sync_sonarqube_project_task
    task = sync_sonarqube_project_task.delay(str(project.id))
    return {"task_id": task.id, "status": "queued"}
