import asyncio
import time
from datetime import datetime, timezone, timedelta
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import select, func, extract, case, cast, String, text, or_
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

# ── Simple in-process cache (TTL = 5 min) ─────────────────────────────────────
_CACHE: dict = {}
_CACHE_TTL = 300  # seconds

def _cache_get(key: str):
    entry = _CACHE.get(key)
    if entry and time.monotonic() - entry["ts"] < _CACHE_TTL:
        return entry["val"]
    return None

def _cache_set(key: str, val):
    _CACHE[key] = {"val": val, "ts": time.monotonic()}

def _cache_key(*parts) -> str:
    return "|".join(str(p) for p in parts)

from app.database import get_db
from app.middleware.auth import get_current_user
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.project import Project
from app.models.user import User
from app.schemas.dashboard import (
    DashboardSummary,
    DashboardTrends,
    TrendPoint,
    ToolBreakdown,
    ToolCount,
    ImageBreakdown,
    ImageBreakdownItem,
    ProjectsOverview,
    ProjectOverviewItem,
    ScanTypeSeverity,
    ScanTypeSeverityBreakdown,
    SecretsCategoryItem,
    SecretsCategoryBreakdown,
    SbomLicenseBreakdown,
    SbomLicenseCategoryItem,
    SbomPackageItem,
    ProjectSbomOverviewItem,
    ProjectsSbomOverview,
)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


def _build_org_project_ids(current_user: User):
    """Return a scalar subquery of project IDs for the user's org, or None."""
    if current_user.org_id:
        return select(Project.id).where(Project.org_id == current_user.org_id).scalar_subquery()
    return None


# Maps friendly label → list of (tool_name, scan_subtype) pairs that produce that label
_REVERSE_LABEL_MAP: dict[str, list[tuple]] = {
    "Dependency": [("trivy", "dependency"), ("trivy", None)],
    "Secrets":    [("trivy", "secrets"), ("gitleaks", None), ("gitleaks", "secret")],
    "SBOM":       [("trivy", "sbom"), ("sbom", None)],
    "SAST":       [("semgrep", None), ("semgrep", "sast")],
    "DAST":       [("zap", None), ("zap", "dast")],
    "K8s":        [("kubescape", None), ("kubescape", "k8s"), ("trivy", "k8s")],
}


def _scan_type_filter(scan_type_label: str):
    """Return a Finding.scan_id IN (...) condition for the given friendly label."""
    pairs = _REVERSE_LABEL_MAP.get(scan_type_label)
    if not pairs:
        return None
    subtype_col = Scan.config_json["scan_subtype"].as_string()
    conds = []
    for tn, st in pairs:
        if st is None:
            conds.append((Scan.tool_name == tn) & subtype_col.is_(None))
        else:
            conds.append((Scan.tool_name == tn) & (subtype_col == st))
    scan_subq = select(Scan.id).where(or_(*conds))
    return Finding.scan_id.in_(scan_subq)


@router.get("/summary", response_model=DashboardSummary)
async def get_summary(
    project_id: Optional[UUID] = None,
    scan_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    ck = _cache_key("summary", current_user.org_id, project_id, scan_type)
    cached = _cache_get(ck)
    if cached:
        return cached

    # Tenant isolation
    org_project_ids = _build_org_project_ids(current_user)

    filters = []
    if org_project_ids is not None:
        filters.append(Finding.project_id.in_(org_project_ids))
    if project_id is not None:
        filters.append(Finding.project_id == project_id)
    if scan_type is not None:
        cond = _scan_type_filter(scan_type)
        if cond is not None:
            filters.append(cond)

    severity_query = select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
    if filters:
        severity_query = severity_query.where(*filters)
    severity_result = await db.execute(severity_query)
    sev = {row[0]: row[1] for row in severity_result.all()}

    status_query = select(Finding.status, func.count(Finding.id)).group_by(Finding.status)
    if filters:
        status_query = status_query.where(*filters)
    status_result = await db.execute(status_query)
    st = {row[0]: row[1] for row in status_result.all()}

    total_findings = sum(sev.values())

    scans_query = select(func.count(Scan.id))
    projects_query = select(func.count(Project.id))
    if org_project_ids is not None:
        scans_query = scans_query.where(Scan.project_id.in_(org_project_ids))
        projects_query = projects_query.where(Project.org_id == current_user.org_id)
    if project_id is not None:
        scans_query = scans_query.where(Scan.project_id == project_id)
        projects_query = projects_query.where(Project.id == project_id)
    if scan_type is not None:
        _pairs = _REVERSE_LABEL_MAP.get(scan_type, [])
        _subtype_col = Scan.config_json["scan_subtype"].as_string()
        _scan_conds = []
        for _tn, _st in _pairs:
            if _st is None:
                _scan_conds.append((Scan.tool_name == _tn) & _subtype_col.is_(None))
            else:
                _scan_conds.append((Scan.tool_name == _tn) & (_subtype_col == _st))
        if _scan_conds:
            scans_query = scans_query.where(or_(*_scan_conds))
    total_scans_r = await db.execute(scans_query)
    total_projects_r = await db.execute(projects_query)

    # Composite key: project_id || pkg_name — so same package in different projects counts separately
    fixed_version_col = Finding.raw_data["FixedVersion"].as_string()
    pkg_key_col = Finding.raw_data["PkgName"].as_string()
    proj_pkg_key = cast(Finding.project_id, String) + pkg_key_col

    pkg_base = (
        select(
            func.count(func.distinct(proj_pkg_key)).label("cnt"),
            case(
                (func.length(func.coalesce(fixed_version_col, "")) > 0, "fixable"),
                else_="no_fix",
            ).label("fix_status"),
        )
        .where(pkg_key_col.isnot(None))
        .group_by(text("fix_status"))
    )
    if filters:
        pkg_base = pkg_base.where(*filters)
    pkg_result = await db.execute(pkg_base)
    pkg_map = {row.fix_status: row.cnt for row in pkg_result.all()}

    # Total unique packages
    total_pkg_q = select(func.count(func.distinct(proj_pkg_key))).where(pkg_key_col.isnot(None))
    if filters:
        total_pkg_q = total_pkg_q.where(*filters)
    total_pkg_r = await db.execute(total_pkg_q)

    # Actionable: fixable packages still open or in_progress
    actionable_q = (
        select(func.count(func.distinct(proj_pkg_key)))
        .where(pkg_key_col.isnot(None))
        .where(func.length(func.coalesce(fixed_version_col, "")) > 0)
        .where(Finding.status.in_(["open", "in_progress"]))
    )
    if filters:
        actionable_q = actionable_q.where(*filters)
    actionable_r = await db.execute(actionable_q)

    # Severity breakdown by unique packages — each package counted once at its highest severity
    SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    pkg_sev_q = (
        select(proj_pkg_key.label("pkg_key"), Finding.severity.label("severity"))
        .where(pkg_key_col.isnot(None))
    )
    if filters:
        pkg_sev_q = pkg_sev_q.where(*filters)
    pkg_sev_rows = (await db.execute(pkg_sev_q)).all()
    pkg_max_sev: dict[str, str] = {}
    for row in pkg_sev_rows:
        cur = pkg_max_sev.get(row.pkg_key)
        if cur is None or SEV_RANK.get(row.severity, 0) > SEV_RANK.get(cur, 0):
            pkg_max_sev[row.pkg_key] = row.severity
    pkg_sev_counts: dict[str, int] = {}
    for s in pkg_max_sev.values():
        pkg_sev_counts[s] = pkg_sev_counts.get(s, 0) + 1

    result = DashboardSummary(
        total_findings=total_findings,
        critical=sev.get("critical", 0),
        high=sev.get("high", 0),
        medium=sev.get("medium", 0),
        low=sev.get("low", 0),
        info=sev.get("info", 0),
        open_findings=st.get("open", 0) + st.get("in_progress", 0),
        resolved_findings=st.get("resolved", 0),
        total_scans=total_scans_r.scalar() or 0,
        total_projects=total_projects_r.scalar() or 0,
        total_packages=total_pkg_r.scalar() or 0,
        fixable_packages=pkg_map.get("fixable", 0),
        no_fix_packages=pkg_map.get("no_fix", 0),
        actionable_packages=actionable_r.scalar() or 0,
        pkg_critical=pkg_sev_counts.get("critical", 0),
        pkg_high=pkg_sev_counts.get("high", 0),
        pkg_medium=pkg_sev_counts.get("medium", 0),
        pkg_low=pkg_sev_counts.get("low", 0),
        pkg_info=pkg_sev_counts.get("info", 0),
    )
    _cache_set(ck, result)
    return result


@router.get("/trends", response_model=DashboardTrends)
async def get_trends(
    project_id: Optional[UUID] = None,
    scan_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    twelve_months_ago = datetime.now(timezone.utc) - timedelta(days=365)

    org_project_ids = _build_org_project_ids(current_user)

    trends_query = (
        select(
            extract("year", Finding.created_at).label("year"),
            extract("month", Finding.created_at).label("month"),
            func.count(
                case((Finding.status.in_(["open", "in_progress"]), Finding.id), else_=None)
            ).label("open_count"),
            func.count(
                case((Finding.status == "resolved", Finding.id), else_=None)
            ).label("resolved_count"),
        )
        .where(Finding.created_at >= twelve_months_ago)
        .group_by(extract("year", Finding.created_at), extract("month", Finding.created_at))
        .order_by(extract("year", Finding.created_at), extract("month", Finding.created_at))
    )
    if org_project_ids is not None:
        trends_query = trends_query.where(Finding.project_id.in_(org_project_ids))
    if project_id is not None:
        trends_query = trends_query.where(Finding.project_id == project_id)
    if scan_type is not None:
        cond = _scan_type_filter(scan_type)
        if cond is not None:
            trends_query = trends_query.where(cond)

    result = await db.execute(trends_query)

    data = []
    for row in result.all():
        month_str = f"{int(row.year)}-{int(row.month):02d}"
        data.append(TrendPoint(month=month_str, open=row.open_count, resolved=row.resolved_count))

    return DashboardTrends(data=data)


@router.get("/tool-breakdown", response_model=ToolBreakdown)
async def get_tool_breakdown(
    project_id: Optional[UUID] = None,
    scan_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    ck = _cache_key("tool-breakdown", current_user.org_id, project_id, scan_type)
    cached = _cache_get(ck)
    if cached:
        return cached
    org_project_ids = _build_org_project_ids(current_user)

    # Join findings → scans to get scan_subtype from config_json
    subtype_col = Scan.config_json["scan_subtype"].as_string()
    tool_query = (
        select(
            Finding.tool_name,
            subtype_col.label("scan_subtype"),
            func.count(Finding.id).label("count"),
        )
        .join(Scan, Finding.scan_id == Scan.id, isouter=True)
        .group_by(Finding.tool_name, subtype_col)
    )
    if org_project_ids is not None:
        tool_query = tool_query.where(Finding.project_id.in_(org_project_ids))
    if project_id is not None:
        tool_query = tool_query.where(Finding.project_id == project_id)
    if scan_type is not None:
        cond = _scan_type_filter(scan_type)
        if cond is not None:
            tool_query = tool_query.where(cond)

    result = await db.execute(tool_query)

    # Map (tool_name, scan_subtype) → friendly label
    label_map = {
        ("trivy", "dependency"): "Dependency",
        ("trivy", "secrets"):    "Secrets",
        ("trivy", "sbom"):       "SBOM",
        ("trivy", "k8s"):        "K8s",
        ("trivy", None):         "Dependency",   # trivy with no subtype → Dependency
        ("semgrep", None):       "SAST",
        ("zap", None):           "DAST",
        ("kubescape", None):     "K8s",
        ("kubescape", "k8s"):    "K8s",
        ("gitleaks", None):      "Secrets",
    }
    # When filtering by K8s scan type, show actual tool names instead of friendly labels
    use_tool_names = scan_type and scan_type.lower() == "k8s"
    counts: dict[str, int] = {}
    for row in result.all():
        tool = (row.tool_name or "").lower()
        sub  = (row.scan_subtype or "").lower() or None
        if use_tool_names:
            label = tool  # show "trivy", "kubescape"
        else:
            label = label_map.get((tool, sub)) or label_map.get((tool, None)) or tool
        counts[label] = counts.get(label, 0) + row.count

    data = [ToolCount(tool_name=label, count=cnt) for label, cnt in sorted(counts.items(), key=lambda x: -x[1])]
    result_obj = ToolBreakdown(data=data)
    _cache_set(_cache_key("tool-breakdown", current_user.org_id, project_id), result_obj)
    return result_obj


LABEL_MAP = {
    ("trivy", "dependency"): "Dependency",
    ("trivy", "secrets"):    "Secrets",
    ("trivy", "sbom"):       "SBOM",
    ("trivy", "k8s"):        "K8s",
    ("trivy", None):         "Dependency",
    ("semgrep", None):       "SAST",
    ("zap", None):           "DAST",
    ("kubescape", None):     "K8s",
    ("kubescape", "k8s"):    "K8s",
    ("gitleaks", None):      "Secrets",
}


@router.get("/scan-type-severity", response_model=ScanTypeSeverityBreakdown)
async def get_scan_type_severity(
    project_id: Optional[UUID] = None,
    scan_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    ck = _cache_key("scan-type-severity", current_user.org_id, project_id, scan_type)
    cached = _cache_get(ck)
    if cached:
        return cached
    org_project_ids = _build_org_project_ids(current_user)

    fixed_col = Finding.raw_data["FixedVersion"].as_string()
    pkg_col   = Finding.raw_data["PkgName"].as_string()
    proj_pkg  = cast(Finding.project_id, String) + pkg_col

    subtype_col = Scan.config_json["scan_subtype"].as_string()

    # Query 1: finding counts grouped by (tool, subtype, severity)
    sev_q = (
        select(
            Finding.tool_name,
            subtype_col.label("scan_subtype"),
            Finding.severity,
            func.count(Finding.id).label("cnt"),
        )
        .join(Scan, Finding.scan_id == Scan.id, isouter=True)
        .group_by(Finding.tool_name, subtype_col, Finding.severity)
    )
    if org_project_ids is not None:
        sev_q = sev_q.where(Finding.project_id.in_(org_project_ids))
    if project_id is not None:
        sev_q = sev_q.where(Finding.project_id == project_id)
    if scan_type is not None:
        cond = _scan_type_filter(scan_type)
        if cond is not None:
            sev_q = sev_q.where(cond)

    # Query 2: unique package counts grouped by (tool, subtype) ONLY
    # NOT grouped by severity — avoids double-counting packages that appear in multiple severity buckets
    pkg_q = (
        select(
            Finding.tool_name,
            subtype_col.label("scan_subtype"),
            func.count(func.distinct(
                case((pkg_col.isnot(None), proj_pkg), else_=None)
            )).label("pkg_total"),
            func.count(func.distinct(
                case((pkg_col.isnot(None) & (func.length(func.coalesce(fixed_col, "")) > 0), proj_pkg), else_=None)
            )).label("pkg_fixable"),
            func.count(func.distinct(
                case((pkg_col.isnot(None) & (func.length(func.coalesce(fixed_col, "")) == 0), proj_pkg), else_=None)
            )).label("pkg_no_fix"),
        )
        .join(Scan, Finding.scan_id == Scan.id, isouter=True)
        .group_by(Finding.tool_name, subtype_col)
    )
    if org_project_ids is not None:
        pkg_q = pkg_q.where(Finding.project_id.in_(org_project_ids))
    if project_id is not None:
        pkg_q = pkg_q.where(Finding.project_id == project_id)
    if scan_type is not None:
        cond = _scan_type_filter(scan_type)
        if cond is not None:
            pkg_q = pkg_q.where(cond)

    sev_result, pkg_result = await asyncio.gather(db.execute(sev_q), db.execute(pkg_q))

    # Aggregate severity counts
    agg: dict[str, dict] = {}
    for row in sev_result.all():
        tool = (row.tool_name or "").lower()
        sub  = (row.scan_subtype or "").lower() or None
        label = LABEL_MAP.get((tool, sub)) or LABEL_MAP.get((tool, None)) or tool
        if label not in agg:
            agg[label] = {"pkg_total": 0, "pkg_fixable": 0, "pkg_no_fix": 0}
        agg[label][row.severity] = agg[label].get(row.severity, 0) + row.cnt

    # Merge correct package counts (no double-counting)
    for row in pkg_result.all():
        tool = (row.tool_name or "").lower()
        sub  = (row.scan_subtype or "").lower() or None
        label = LABEL_MAP.get((tool, sub)) or LABEL_MAP.get((tool, None)) or tool
        if label not in agg:
            agg[label] = {"pkg_total": 0, "pkg_fixable": 0, "pkg_no_fix": 0}
        agg[label]["pkg_total"]   += row.pkg_total
        agg[label]["pkg_fixable"] += row.pkg_fixable
        agg[label]["pkg_no_fix"]  += row.pkg_no_fix

    # Check if SBOM scans exist (they store data in output_data, not findings)
    sbom_check_q = select(func.count(Scan.id)).where(
        (Scan.tool_name == "trivy") & (Scan.config_json["scan_subtype"].as_string() == "sbom"),
        Scan.output_data.isnot(None),
    )
    if org_project_ids is not None:
        sbom_check_q = sbom_check_q.where(Scan.project_id.in_(org_project_ids))
    if project_id is not None:
        sbom_check_q = sbom_check_q.where(Scan.project_id == project_id)
    sbom_count = (await db.execute(sbom_check_q)).scalar() or 0
    if sbom_count > 0 and "SBOM" not in agg:
        agg["SBOM"] = {"pkg_total": 0, "pkg_fixable": 0, "pkg_no_fix": 0}

    ORDER = ["Dependency", "Secrets", "SBOM", "SAST", "DAST", "K8s"]
    sorted_labels = sorted(agg.keys(), key=lambda x: ORDER.index(x) if x in ORDER else 99)

    data = [
        ScanTypeSeverity(
            scan_type=label,
            total=sum(v for k, v in agg[label].items() if k not in ("pkg_total", "pkg_fixable", "pkg_no_fix")),
            critical=agg[label].get("critical", 0),
            high=agg[label].get("high", 0),
            medium=agg[label].get("medium", 0),
            low=agg[label].get("low", 0),
            info=agg[label].get("info", 0),
            total_packages=agg[label]["pkg_total"],
            fixable_packages=agg[label]["pkg_fixable"],
            no_fix_packages=agg[label]["pkg_no_fix"],
        )
        for label in sorted_labels
    ]
    result_obj = ScanTypeSeverityBreakdown(data=data)
    _cache_set(ck, result_obj)
    return result_obj


@router.get("/image-breakdown", response_model=ImageBreakdown)
async def get_image_breakdown(
    scan_type: Optional[str] = None,
    project_id: Optional[UUID] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns top images by findings count.
    Joins findings -> scans, groups by config_json->>'target'.
    """
    org_project_ids = _build_org_project_ids(current_user)

    # Build query: join findings to scans on scan_id, group by target from config_json
    target_col = Scan.config_json["target"].as_string()
    fixed_col = Finding.raw_data["FixedVersion"].as_string()

    image_query = (
        select(
            target_col.label("image"),
            func.count(Finding.id).label("count"),
            func.count(
                case((func.length(func.coalesce(fixed_col, "")) > 0, Finding.id), else_=None)
            ).label("fixable_count"),
            func.count(
                case((func.length(func.coalesce(fixed_col, "")) == 0, Finding.id), else_=None)
            ).label("no_fix_count"),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .where(target_col.isnot(None))
        .group_by(target_col)
        .order_by(func.count(Finding.id).desc())
        .limit(20)
    )

    if org_project_ids is not None:
        image_query = image_query.where(Finding.project_id.in_(org_project_ids))
    if project_id is not None:
        image_query = image_query.where(Finding.project_id == project_id)
    if scan_type is not None:
        cond = _scan_type_filter(scan_type)
        if cond is not None:
            image_query = image_query.where(cond)

    result = await db.execute(image_query)
    data = [
        ImageBreakdownItem(
            image=row.image, count=row.count,
            fixable_count=row.fixable_count, no_fix_count=row.no_fix_count,
        )
        for row in result.all()
    ]
    return ImageBreakdown(data=data)


@router.get("/projects-overview", response_model=ProjectsOverview)
async def get_projects_overview(
    scan_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns one row per project with findings counts by severity.
    """
    # Build base project query with org isolation
    projects_query = select(Project.id, Project.name)
    if current_user.org_id:
        projects_query = projects_query.where(Project.org_id == current_user.org_id)
    projects_query = projects_query.order_by(Project.name)

    projects_result = await db.execute(projects_query)
    projects = projects_result.all()

    if not projects:
        return ProjectsOverview(data=[])

    project_ids = [p.id for p in projects]
    fixed_col = Finding.raw_data["FixedVersion"].as_string()
    pkg_col = Finding.raw_data["PkgName"].as_string()

    # Severity counts per project
    sev_query = (
        select(
            Finding.project_id,
            Finding.severity,
            func.count(Finding.id).label("cnt"),
        )
        .where(Finding.project_id.in_(project_ids))
        .group_by(Finding.project_id, Finding.severity)
    )
    if scan_type is not None:
        cond = _scan_type_filter(scan_type)
        if cond is not None:
            sev_query = sev_query.where(cond)
    sev_result = await db.execute(sev_query)
    sev_map: dict = {}
    for row in sev_result.all():
        pid = str(row.project_id)
        if pid not in sev_map:
            sev_map[pid] = {}
        sev_map[pid][row.severity] = row.cnt

    # Fixable / no-fix unique package counts per project
    pkg_query = (
        select(
            Finding.project_id,
            func.count(func.distinct(pkg_col)).filter(
                func.length(func.coalesce(fixed_col, "")) > 0
            ).label("fixable"),
            func.count(func.distinct(pkg_col)).filter(
                func.length(func.coalesce(fixed_col, "")) == 0
            ).label("no_fix"),
        )
        .where(Finding.project_id.in_(project_ids))
        .where(pkg_col.isnot(None))
        .group_by(Finding.project_id)
    )
    if scan_type is not None:
        cond = _scan_type_filter(scan_type)
        if cond is not None:
            pkg_query = pkg_query.where(cond)
    pkg_result = await db.execute(pkg_query)
    pkg_map: dict = {str(row.project_id): {"fixable": row.fixable, "no_fix": row.no_fix} for row in pkg_result.all()}

    data = []
    for p in projects:
        pid = str(p.id)
        counts = sev_map.get(pid, {})
        pkgs = pkg_map.get(pid, {"fixable": 0, "no_fix": 0})
        total = sum(counts.values())
        data.append(
            ProjectOverviewItem(
                project_id=pid,
                project_name=p.name,
                total_findings=total,
                critical=counts.get("critical", 0),
                high=counts.get("high", 0),
                medium=counts.get("medium", 0),
                low=counts.get("low", 0),
                fixable_packages=pkgs["fixable"],
                no_fix_packages=pkgs["no_fix"],
            )
        )

    return ProjectsOverview(data=data)


@router.get("/category-breakdown", response_model=SecretsCategoryBreakdown)
async def get_category_breakdown(
    project_id: Optional[UUID] = None,
    scan_type: Optional[str] = "Secrets",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Category breakdown for secrets (or any scan type that stores Category in raw_data)."""
    ck = _cache_key("category-breakdown", current_user.org_id, project_id, scan_type)
    cached = _cache_get(ck)
    if cached:
        return cached

    org_project_ids = _build_org_project_ids(current_user)
    category_col = Finding.raw_data["Category"].as_string()

    q = (
        select(
            category_col.label("category"),
            Finding.severity,
            func.count(Finding.id).label("cnt"),
        )
        .join(Scan, Finding.scan_id == Scan.id, isouter=True)
        .where(category_col.isnot(None))
        .group_by(category_col, Finding.severity)
    )
    if org_project_ids is not None:
        q = q.where(Finding.project_id.in_(org_project_ids))
    if project_id is not None:
        q = q.where(Finding.project_id == project_id)
    label = scan_type or "Secrets"
    cond = _scan_type_filter(label)
    if cond is not None:
        q = q.where(cond)

    result = await db.execute(q)
    agg: dict[str, dict] = {}
    for row in result.all():
        cat = row.category or "Unknown"
        if cat not in agg:
            agg[cat] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        agg[cat][row.severity] = agg[cat].get(row.severity, 0) + row.cnt

    data = [
        SecretsCategoryItem(
            category=cat,
            total=sum(v.values()),
            critical=v.get("critical", 0),
            high=v.get("high", 0),
            medium=v.get("medium", 0),
            low=v.get("low", 0),
            info=v.get("info", 0),
        )
        for cat, v in sorted(agg.items(), key=lambda x: -sum(x[1].values()))
    ]
    result_obj = SecretsCategoryBreakdown(data=data)
    _cache_set(ck, result_obj)
    return result_obj


# ── SBOM License helpers ──────────────────────────────────────────────────────

# Permissiveness rank: higher = more permissive.  When a package has multiple
# licences we pick the *most* permissive one (user request: "take the lowest
# restriction").
_LICENSE_PERMISSIVENESS: dict[str, int] = {
    "AGPL":          1,
    "GPL":           2,
    "LGPL":          3,
    "MPL":           4,
    "EPL":           5,
    "Apache":        6,
    "BSD":           7,
    "MIT":           8,
    "ISC":           9,
    "Public Domain": 10,
    "Other":         0,
    "Unknown":       0,
}

# Categories that are copyleft — packages whose effective license falls
# in one of these are actionable (only application-level packages, not OS).
_COPYLEFT_CATEGORIES = {"GPL", "AGPL", "LGPL"}

# OS-level package types — these ship with the base image and aren't modified,
# so they don't create license obligations.  Only application-level packages
# (python-pkg, node-pkg, jar, gobinary, etc.) are considered actionable.
_OS_PKG_TYPES = {"redhat", "debian", "ubuntu", "alpine", "bitnami"}


def _categorise_license(lic_str: str) -> str:
    """Map a single SPDX id / license name string to a broad category."""
    up = lic_str.upper()
    if "AGPL" in up:
        return "AGPL"
    if "LGPL" in up:
        return "LGPL"
    if "GPL" in up:
        return "GPL"
    if "APACHE" in up:
        return "Apache"
    if "BSD" in up:
        return "BSD"
    if "MIT" in up:
        return "MIT"
    if "MPL" in up:
        return "MPL"
    if "ISC" in up:
        return "ISC"
    if "EPL" in up:
        return "EPL"
    if "PUBLIC" in up or "CC0" in up or "UNLICENSE" in up:
        return "Public Domain"
    if lic_str in ("UNKNOWN", ""):
        return "Unknown"
    return "Other"


def _extract_licenses(component: dict) -> list[str]:
    """Extract individual license strings from a CycloneDX component."""
    licenses_arr = component.get("licenses") or []
    raw: list[str] = []
    for entry in licenses_arr:
        lic = entry.get("license", {})
        lic_str = lic.get("id") or lic.get("name") or ""
        if not lic_str:
            continue
        # A single license entry can itself be a compound SPDX expression
        # (e.g. "GPL-3.0 AND BSD-3-Clause AND MIT").  Split on AND / OR so
        # we can categorise each part independently.
        for part in lic_str.replace(" AND ", "\n").replace(" OR ", "\n").split("\n"):
            cleaned = part.strip()
            # Strip SPDX exception suffixes like "WITH GCC-exception-3.1"
            if " WITH " in cleaned:
                cleaned = cleaned.split(" WITH ")[0].strip()
            if cleaned:
                raw.append(cleaned)
    return raw if raw else ["UNKNOWN"]


def _get_pkg_type(component: dict) -> str:
    for prop in component.get("properties", []):
        if prop.get("name") == "aquasecurity:trivy:PkgType":
            return prop.get("value", "unknown")
    return "unknown"


def _effective_license(raw_licenses: list[str]) -> tuple[str, str]:
    """Return (effective_license_string, category) picking the most permissive."""
    if not raw_licenses:
        return "UNKNOWN", "Unknown"
    best_lic = raw_licenses[0]
    best_cat = _categorise_license(best_lic)
    best_rank = _LICENSE_PERMISSIVENESS.get(best_cat, 0)
    for lic in raw_licenses[1:]:
        cat = _categorise_license(lic)
        rank = _LICENSE_PERMISSIVENESS.get(cat, 0)
        if rank > best_rank:
            best_lic = lic
            best_cat = cat
            best_rank = rank
    return best_lic, best_cat


@router.get("/sbom-license-breakdown", response_model=SbomLicenseBreakdown)
async def get_sbom_license_breakdown(
    project_id: Optional[UUID] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Analyse SBOM CycloneDX components for license risk."""
    ck = _cache_key("sbom-license", current_user.org_id, project_id)
    cached = _cache_get(ck)
    if cached:
        return cached

    org_project_ids = _build_org_project_ids(current_user)

    # Fetch all SBOM scans' output_data
    subtype_col = Scan.config_json["scan_subtype"].as_string()
    q = select(Scan.output_data, Scan.config_json["target"].as_string().label("target")).where(
        (Scan.tool_name == "trivy") & (subtype_col == "sbom"),
        Scan.output_data.isnot(None),
    )
    if org_project_ids is not None:
        q = q.where(Scan.project_id.in_(org_project_ids))
    if project_id is not None:
        q = q.where(Scan.project_id == project_id)

    result = await db.execute(q)
    rows = result.all()

    # De-duplicate packages across scans: key = (name, version, pkg_type)
    # Keep the first occurrence's image for display.
    seen: dict[tuple, dict] = {}
    for row in rows:
        output = row.output_data
        if not output or not isinstance(output, dict):
            continue
        target = row.target or "unknown"
        for comp in output.get("components", []):
            name = comp.get("name", "")
            version = comp.get("version", "")
            pkg_type = _get_pkg_type(comp)
            key = (name, version, pkg_type)
            if key in seen:
                continue
            raw_lics = _extract_licenses(comp)
            eff_lic, eff_cat = _effective_license(raw_lics)
            is_actionable = (
                eff_cat in _COPYLEFT_CATEGORIES
                and pkg_type not in _OS_PKG_TYPES
            )
            seen[key] = {
                "name": name,
                "version": version,
                "pkg_type": pkg_type,
                "image": target,
                "raw_licenses": raw_lics,
                "effective_license": eff_lic,
                "license_category": eff_cat,
                "actionable": is_actionable,
            }

    # Build category aggregation
    cat_agg: dict[str, dict] = {}
    actionable_list: list[dict] = []
    for pkg in seen.values():
        cat = pkg["license_category"]
        if cat not in cat_agg:
            cat_agg[cat] = {"total": 0, "actionable": 0, "not_actionable": 0}
        cat_agg[cat]["total"] += 1
        if pkg["actionable"]:
            cat_agg[cat]["actionable"] += 1
            actionable_list.append(pkg)
        else:
            cat_agg[cat]["not_actionable"] += 1

    # Sort categories by total descending
    by_category = [
        SbomLicenseCategoryItem(
            category=cat,
            total_packages=vals["total"],
            actionable=vals["actionable"],
            not_actionable=vals["not_actionable"],
        )
        for cat, vals in sorted(cat_agg.items(), key=lambda x: -x[1]["total"])
    ]

    total_actionable = sum(1 for p in seen.values() if p["actionable"])
    result_obj = SbomLicenseBreakdown(
        total_packages=len(seen),
        total_actionable=total_actionable,
        total_not_actionable=len(seen) - total_actionable,
        by_category=by_category,
        actionable_packages=[
            SbomPackageItem(**p) for p in sorted(actionable_list, key=lambda x: x["name"])
        ],
    )
    _cache_set(ck, result_obj)
    return result_obj


@router.get("/projects-sbom-overview", response_model=ProjectsSbomOverview)
async def get_projects_sbom_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Per-project SBOM license actionability summary."""
    ck = _cache_key("projects-sbom", current_user.org_id)
    cached = _cache_get(ck)
    if cached:
        return cached

    # Get all projects
    projects_q = select(Project.id, Project.name)
    if current_user.org_id:
        projects_q = projects_q.where(Project.org_id == current_user.org_id)
    projects_q = projects_q.order_by(Project.name)
    projects = (await db.execute(projects_q)).all()

    if not projects:
        return ProjectsSbomOverview(data=[])

    # Fetch SBOM scans with project_id
    subtype_col = Scan.config_json["scan_subtype"].as_string()
    q = select(
        Scan.project_id,
        Scan.output_data,
    ).where(
        (Scan.tool_name == "trivy") & (subtype_col == "sbom"),
        Scan.output_data.isnot(None),
        Scan.project_id.in_([p.id for p in projects]),
    )
    result = await db.execute(q)

    # Aggregate per project
    project_data: dict[str, dict] = {}
    for row in result.all():
        pid = str(row.project_id)
        if pid not in project_data:
            project_data[pid] = {"seen": set(), "actionable": 0, "not_actionable": 0, "total": 0}
        output = row.output_data
        if not output or not isinstance(output, dict):
            continue
        for comp in output.get("components", []):
            name = comp.get("name", "")
            version = comp.get("version", "")
            pkg_type = _get_pkg_type(comp)
            key = (name, version, pkg_type)
            if key in project_data[pid]["seen"]:
                continue
            project_data[pid]["seen"].add(key)
            raw_lics = _extract_licenses(comp)
            _, eff_cat = _effective_license(raw_lics)
            project_data[pid]["total"] += 1
            if eff_cat in _COPYLEFT_CATEGORIES and pkg_type not in _OS_PKG_TYPES:
                project_data[pid]["actionable"] += 1
            else:
                project_data[pid]["not_actionable"] += 1

    data = []
    for p in projects:
        pid = str(p.id)
        pd = project_data.get(pid)
        if pd:
            data.append(ProjectSbomOverviewItem(
                project_id=pid, project_name=p.name,
                total_packages=pd["total"],
                actionable=pd["actionable"],
                not_actionable=pd["not_actionable"],
            ))
        else:
            data.append(ProjectSbomOverviewItem(
                project_id=pid, project_name=p.name,
                total_packages=0, actionable=0, not_actionable=0,
            ))

    result_obj = ProjectsSbomOverview(data=data)
    _cache_set(ck, result_obj)
    return result_obj


# ── K8s Dashboard endpoints ───────────────────────────────────────────────────

from app.schemas.dashboard import (
    K8sCategoryBreakdown, K8sCategoryItem,
    K8sResourceBreakdown, K8sResourceItem,
    K8sNamespaceBreakdown, K8sNamespaceItem,
)


def _k8s_tool_filter(tool_name: Optional[str] = None):
    """Return a WHERE clause for K8s tool filtering."""
    if tool_name:
        tn = tool_name.lower()
        if tn == "kubescape":
            return Scan.tool_name == "kubescape"
        elif tn == "trivy":
            return (Scan.tool_name == "trivy") & (Scan.config_json["scan_subtype"].as_string() == "k8s")
    return or_(
        Scan.tool_name == "kubescape",
        (Scan.tool_name == "trivy") & (Scan.config_json["scan_subtype"].as_string() == "k8s"),
    )

def _k8s_apply_filters(q, project_id: Optional[UUID], org_id: Optional[UUID], tool_name: Optional[str] = None):
    """Apply K8s tool, project, and org filters to a query that already has a Scan join."""
    q = q.where(_k8s_tool_filter(tool_name))
    if project_id:
        q = q.where(Finding.project_id == project_id)
    if org_id:
        q = q.where(Finding.project_id.in_(
            select(Project.id).where(Project.org_id == org_id)
        ))
    return q


@router.get("/k8s-categories", response_model=K8sCategoryBreakdown)
async def get_k8s_categories(
    project_id: Optional[UUID] = None,
    tool_name: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """K8s finding categories with severity breakdown."""
    ck = _cache_key("k8s-categories", current_user.org_id, project_id, tool_name)
    cached = _cache_get(ck)
    if cached:
        return cached

    cat_col = Finding.raw_data["category"].as_string()

    cat_col = Finding.raw_data["category"].as_string()
    q = (
        select(
            cat_col.label("category"),
            func.count().label("total"),
            func.count().filter(Finding.severity == "critical").label("critical"),
            func.count().filter(Finding.severity == "high").label("high"),
            func.count().filter(Finding.severity == "medium").label("medium"),
            func.count().filter(Finding.severity == "low").label("low"),
            func.count().filter(Finding.severity == "info").label("info"),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .group_by(cat_col)
        .order_by(func.count().desc())
    )
    q = _k8s_apply_filters(q, project_id, current_user.org_id, tool_name)

    rows = (await db.execute(q)).all()
    data = [
        K8sCategoryItem(
            category=r.category or "Unknown", total=r.total,
            critical=r.critical, high=r.high, medium=r.medium, low=r.low, info=r.info,
        )
        for r in rows
    ]
    result_obj = K8sCategoryBreakdown(data=data)
    _cache_set(ck, result_obj)
    return result_obj


@router.get("/k8s-resources", response_model=K8sResourceBreakdown)
async def get_k8s_resources(
    project_id: Optional[UUID] = None,
    tool_name: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Affected K8s resources with finding counts."""
    ck = _cache_key("k8s-resources", current_user.org_id, project_id, tool_name)
    cached = _cache_get(ck)
    if cached:
        return cached

    kind_col = Finding.raw_data["k8s_resource_kind"].as_string()
    name_col = Finding.raw_data["k8s_resource_name"].as_string()
    ns_col = Finding.raw_data["k8s_namespace"].as_string()
    q = (
        select(
            kind_col.label("kind"),
            name_col.label("name"),
            ns_col.label("namespace"),
            func.count().label("total_findings"),
            func.count().filter(Finding.severity == "critical").label("critical"),
            func.count().filter(Finding.severity == "high").label("high"),
            func.count().filter(Finding.severity == "medium").label("medium"),
            func.count().filter(Finding.severity == "low").label("low"),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .group_by(kind_col, name_col, ns_col)
        .order_by(func.count().desc())
        .limit(100)
    )
    q = _k8s_apply_filters(q, project_id, current_user.org_id, tool_name)

    rows = (await db.execute(q)).all()
    data = [
        K8sResourceItem(
            kind=r.kind or "", name=r.name or "", namespace=r.namespace or "",
            total_findings=r.total_findings, critical=r.critical, high=r.high,
            medium=r.medium, low=r.low,
        )
        for r in rows
    ]
    result_obj = K8sResourceBreakdown(data=data)
    _cache_set(ck, result_obj)
    return result_obj


@router.get("/k8s-namespaces", response_model=K8sNamespaceBreakdown)
async def get_k8s_namespaces(
    project_id: Optional[UUID] = None,
    tool_name: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """K8s findings grouped by namespace."""
    ck = _cache_key("k8s-namespaces", current_user.org_id, project_id, tool_name)
    cached = _cache_get(ck)
    if cached:
        return cached

    ns_col = Finding.raw_data["k8s_namespace"].as_string()
    q = (
        select(
            ns_col.label("namespace"),
            func.count().label("total_findings"),
            func.count().filter(Finding.severity == "critical").label("critical"),
            func.count().filter(Finding.severity == "high").label("high"),
            func.count().filter(Finding.severity == "medium").label("medium"),
            func.count().filter(Finding.severity == "low").label("low"),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .group_by(ns_col)
        .order_by(func.count().desc())
    )
    q = _k8s_apply_filters(q, project_id, current_user.org_id, tool_name)

    rows = (await db.execute(q)).all()
    data = [
        K8sNamespaceItem(
            namespace=r.namespace or "cluster-wide",
            total_findings=r.total_findings, critical=r.critical,
            high=r.high, medium=r.medium, low=r.low,
        )
        for r in rows
    ]
    result_obj = K8sNamespaceBreakdown(data=data)
    _cache_set(ck, result_obj)
    return result_obj
