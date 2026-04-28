"""Organization-scoped settings.

Today this only covers SonarQube (URL + token shared by every project in the org)
plus a bulk import flow that pulls the org's SonarQube projects into OpenSentinel.
Per-project SonarQube fields still win when set; org values are the fallback.
"""
import asyncio
import logging
import uuid
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user, require_role
from app.models.organization import Organization
from app.models.project import Project
from app.models.user import User
from app.integrations.sonarqube import ping as sq_ping

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/organizations", tags=["organizations"])


# ── Schemas ─────────────────────────────────────────────────────────────────

class SonarqubeOrgConfig(BaseModel):
    url: str
    token: Optional[str] = None  # omit to keep existing token unchanged


class SonarqubeOrgStatus(BaseModel):
    url: Optional[str] = None
    token_configured: bool = False


class SonarqubeProjectListItem(BaseModel):
    key: str
    name: str
    last_analysis_date: Optional[str] = None
    qualifier: Optional[str] = None
    visibility: Optional[str] = None


class SonarqubeProjectList(BaseModel):
    items: list[SonarqubeProjectListItem]
    total: int
    page: int
    page_size: int


class SonarqubeImportItem(BaseModel):
    key: str
    name: str
    description: Optional[str] = None


class SonarqubeImportRequest(BaseModel):
    projects: list[SonarqubeImportItem]
    sync_immediately: bool = True


class SonarqubeImportResult(BaseModel):
    created: list[str]   # OpenSentinel project IDs
    skipped: list[str]   # SonarQube keys we skipped (already mapped)
    failed: list[dict]   # [{key, error}]
    queued_syncs: int


# ── Helpers ─────────────────────────────────────────────────────────────────

async def _require_org(current_user: User, db: AsyncSession) -> Organization:
    if not current_user.org_id:
        raise HTTPException(status_code=400, detail="User is not in an organization")
    result = await db.execute(select(Organization).where(Organization.id == current_user.org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


# ── SonarQube settings ──────────────────────────────────────────────────────

@router.get("/me/sonarqube", response_model=SonarqubeOrgStatus)
async def get_org_sonarqube(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    org = await _require_org(current_user, db)
    return SonarqubeOrgStatus(
        url=org.sonarqube_url,
        token_configured=bool(org.sonarqube_token),
    )


@router.put("/me/sonarqube", response_model=SonarqubeOrgStatus)
async def put_org_sonarqube(
    config: SonarqubeOrgConfig,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("security_engineer")),
):
    org = await _require_org(current_user, db)
    org.sonarqube_url = (config.url or "").rstrip("/") or None
    if config.token is not None:
        org.sonarqube_token = config.token or None
    await db.commit()
    await db.refresh(org)
    return SonarqubeOrgStatus(
        url=org.sonarqube_url,
        token_configured=bool(org.sonarqube_token),
    )


@router.delete("/me/sonarqube", status_code=status.HTTP_204_NO_CONTENT)
async def delete_org_sonarqube(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("security_engineer")),
):
    org = await _require_org(current_user, db)
    org.sonarqube_url = None
    org.sonarqube_token = None
    await db.commit()


@router.post("/me/sonarqube/test")
async def test_org_sonarqube(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    org = await _require_org(current_user, db)
    if not org.sonarqube_url:
        raise HTTPException(status_code=400, detail="SonarQube URL not configured for this organization")
    ok, detail = await asyncio.to_thread(sq_ping, org.sonarqube_url, org.sonarqube_token)
    return {"ok": ok, "detail": detail}


# ── Project listing + bulk import ──────────────────────────────────────────

@router.get("/me/sonarqube/projects", response_model=SonarqubeProjectList)
async def list_sonarqube_projects(
    page: int = 1,
    page_size: int = 100,
    q: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Proxy SonarQube /api/projects/search using org credentials."""
    org = await _require_org(current_user, db)
    if not org.sonarqube_url:
        raise HTTPException(status_code=400, detail="SonarQube URL not configured for this organization")
    if page_size < 1 or page_size > 500:
        page_size = 100
    if page < 1:
        page = 1

    auth = (org.sonarqube_token, "") if org.sonarqube_token else None

    def _fetch():
        with httpx.Client(base_url=org.sonarqube_url.rstrip("/"), timeout=30.0, auth=auth) as c:
            params = {"ps": page_size, "p": page}
            if q:
                params["q"] = q
            resp = c.get("/api/projects/search", params=params)
            resp.raise_for_status()
            return resp.json()

    try:
        data = await asyncio.to_thread(_fetch)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code in (401, 403):
            raise HTTPException(status_code=401, detail="SonarQube authentication failed")
        raise HTTPException(status_code=502, detail=f"SonarQube error: HTTP {exc.response.status_code}")
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"SonarQube unreachable: {exc}")

    components = data.get("components", []) or []
    paging = data.get("paging", {}) or {}
    items = [
        SonarqubeProjectListItem(
            key=c.get("key", ""),
            name=c.get("name", ""),
            last_analysis_date=c.get("lastAnalysisDate"),
            qualifier=c.get("qualifier"),
            visibility=c.get("visibility"),
        )
        for c in components if c.get("key")
    ]
    return SonarqubeProjectList(
        items=items,
        total=int(paging.get("total", len(items))),
        page=int(paging.get("pageIndex", page)),
        page_size=int(paging.get("pageSize", page_size)),
    )


@router.post("/me/sonarqube/import", response_model=SonarqubeImportResult)
async def import_sonarqube_projects(
    body: SonarqubeImportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("security_engineer")),
):
    """Create one OpenSentinel project per selected SonarQube project.

    - Skips SonarQube keys already mapped to a project in this org.
    - When `sync_immediately`, queues a celery sync for each created project.
    """
    org = await _require_org(current_user, db)
    if not org.sonarqube_url:
        raise HTTPException(status_code=400, detail="SonarQube URL not configured for this organization")

    # Pull existing project_keys in this org so we can skip duplicates
    existing = await db.execute(
        select(Project.sonarqube_project_key)
        .where(Project.org_id == org.id)
        .where(Project.sonarqube_project_key.is_not(None))
    )
    existing_keys = {row[0] for row in existing.all() if row[0]}

    created_ids: list[str] = []
    skipped: list[str] = []
    failed: list[dict] = []

    for item in body.projects:
        key = (item.key or "").strip()
        name = (item.name or "").strip() or key
        if not key:
            failed.append({"key": item.key, "error": "missing key"})
            continue
        if key in existing_keys:
            skipped.append(key)
            continue
        try:
            project = Project(
                id=uuid.uuid4(),
                name=name,
                description=item.description,
                created_by=current_user.id,
                org_id=org.id,
                sonarqube_project_key=key,
                # URL/token left null → falls back to org credentials at sync time
            )
            db.add(project)
            created_ids.append(str(project.id))
            existing_keys.add(key)
        except Exception as exc:
            failed.append({"key": key, "error": str(exc)})

    await db.commit()

    queued = 0
    if body.sync_immediately and created_ids:
        from app.tasks.scan_tasks import sync_sonarqube_project_task
        for pid in created_ids:
            try:
                sync_sonarqube_project_task.delay(pid)
                queued += 1
            except Exception:
                logger.exception("Failed to queue initial SonarQube sync for %s", pid)

    return SonarqubeImportResult(
        created=created_ids,
        skipped=skipped,
        failed=failed,
        queued_syncs=queued,
    )
