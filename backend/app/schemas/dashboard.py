from typing import List

from pydantic import BaseModel


class SeverityCount(BaseModel):
    severity: str
    count: int


class ToolCount(BaseModel):
    tool_name: str
    count: int


class StatusCount(BaseModel):
    status: str
    count: int


class DashboardSummary(BaseModel):
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    open_findings: int
    resolved_findings: int
    total_scans: int
    total_projects: int
    total_packages: int
    fixable_packages: int
    no_fix_packages: int
    actionable_packages: int   # fixable + still open/in_progress
    # Severity breakdown by unique packages (each pkg counted at its max severity)
    pkg_critical: int
    pkg_high: int
    pkg_medium: int
    pkg_low: int
    pkg_info: int


class TrendPoint(BaseModel):
    month: str
    open: int
    resolved: int


class DashboardTrends(BaseModel):
    data: List[TrendPoint]


class ToolBreakdown(BaseModel):
    data: List[ToolCount]


class ScanTypeSeverity(BaseModel):
    scan_type: str
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    total_packages: int
    fixable_packages: int
    no_fix_packages: int


class ScanTypeSeverityBreakdown(BaseModel):
    data: List[ScanTypeSeverity]


class ImageBreakdownItem(BaseModel):
    image: str
    count: int
    fixable_count: int
    no_fix_count: int


class ImageBreakdown(BaseModel):
    data: List[ImageBreakdownItem]


class ProjectOverviewItem(BaseModel):
    project_id: str
    project_name: str
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    fixable_packages: int
    no_fix_packages: int


class ProjectsOverview(BaseModel):
    data: List[ProjectOverviewItem]


class SecretsCategoryItem(BaseModel):
    category: str
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


class SecretsCategoryBreakdown(BaseModel):
    data: List[SecretsCategoryItem]


# ── SBOM License Breakdown ────────────────────────────────────────────────────

class SbomLicenseCategoryItem(BaseModel):
    category: str          # GPL, AGPL, LGPL, Apache, BSD, MIT, MPL, Public Domain, Other, Unknown
    total_packages: int
    actionable: int        # packages where this is the *effective* license and it's copyleft-only
    not_actionable: int

class SbomPackageItem(BaseModel):
    name: str
    version: str
    pkg_type: str          # python-pkg, redhat, node-pkg, etc.
    image: str
    raw_licenses: List[str]
    effective_license: str  # most permissive license chosen
    license_category: str   # category of effective license
    actionable: bool

class SbomLicenseBreakdown(BaseModel):
    total_packages: int
    total_actionable: int
    total_not_actionable: int
    by_category: List[SbomLicenseCategoryItem]
    actionable_packages: List[SbomPackageItem]  # only the actionable ones for the table


class ProjectSbomOverviewItem(BaseModel):
    project_id: str
    project_name: str
    total_packages: int
    actionable: int
    not_actionable: int

class ProjectsSbomOverview(BaseModel):
    data: List[ProjectSbomOverviewItem]


# ── K8s Dashboard ────────────────────────────────────────────────────────────

class K8sCategoryItem(BaseModel):
    category: str
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int

class K8sCategoryBreakdown(BaseModel):
    data: List[K8sCategoryItem]

class K8sResourceItem(BaseModel):
    kind: str
    name: str
    namespace: str
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int

class K8sResourceBreakdown(BaseModel):
    data: List[K8sResourceItem]

class K8sNamespaceItem(BaseModel):
    namespace: str
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int

class K8sNamespaceBreakdown(BaseModel):
    data: List[K8sNamespaceItem]
