import json
import logging
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user, require_role
from app.models.finding import Finding
from app.models.project import Project
from app.models.user import User
from app.schemas.finding import (
    FindingResponse, FindingUpdate, FindingBulkUpdate,
    FindingCloseRequest, FindingReopenRequest, VerifyResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/findings", tags=["findings"])

# Valid close statuses and reasons
CLOSE_STATUSES = {"resolved", "accepted", "false_positive"}
CLOSE_REASONS = {"rescan_verified", "accepted_risk", "false_positive", "manual_fix"}
REASONS_REQUIRING_JUSTIFICATION = {"accepted_risk", "false_positive"}


@router.get("/", response_model=list[FindingResponse])
async def list_findings(
    severity: str | None = Query(None),
    tool_name: str | None = Query(None),
    status: str | None = Query(None),
    project_id: UUID | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List findings with optional filters, ordered by created_at desc."""
    offset = (page - 1) * page_size
    query = select(Finding)

    if severity is not None:
        query = query.where(Finding.severity == severity)
    if tool_name is not None:
        query = query.where(Finding.tool_name == tool_name)
    if status is not None:
        query = query.where(Finding.status == status)
    if project_id is not None:
        query = query.where(Finding.project_id == project_id)

    # Tenant isolation: filter findings by org_id through the project relationship
    if current_user.org_id:
        org_project_ids = select(Project.id).where(Project.org_id == current_user.org_id).scalar_subquery()
        query = query.where(Finding.project_id.in_(org_project_ids))

    query = query.order_by(Finding.created_at.desc()).offset(offset).limit(page_size)
    result = await db.execute(query)
    findings = result.scalars().all()
    return findings


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a single finding by ID."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: UUID,
    body: FindingUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("developer")),
):
    """Update a finding (status, assigned_to). For closing, use /close endpoint."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    update_data = body.model_dump(exclude_unset=True)

    if "status" in update_data and update_data["status"] == "resolved":
        finding.resolved_at = datetime.now(timezone.utc)

    for field, value in update_data.items():
        setattr(finding, field, value)

    await db.commit()
    await db.refresh(finding)
    return finding


@router.patch("/{finding_id}/close", response_model=FindingResponse)
async def close_finding(
    finding_id: UUID,
    body: FindingCloseRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("developer")),
):
    """Close a finding with a reason and optional justification."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    if finding.status in CLOSE_STATUSES:
        raise HTTPException(status_code=400, detail="Finding is already closed")

    if body.status not in CLOSE_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid close status. Must be one of: {', '.join(CLOSE_STATUSES)}")

    if body.close_reason not in CLOSE_REASONS:
        raise HTTPException(status_code=400, detail=f"Invalid close reason. Must be one of: {', '.join(CLOSE_REASONS)}")

    if body.close_reason in REASONS_REQUIRING_JUSTIFICATION and not body.justification:
        raise HTTPException(status_code=400, detail="Justification is required for this close reason")

    now = datetime.now(timezone.utc)
    finding.status = body.status
    finding.close_reason = body.close_reason
    finding.justification = body.justification
    finding.closed_by = current_user.id
    finding.closed_at = now
    finding.resolved_at = now

    await db.commit()
    await db.refresh(finding)
    return finding


@router.patch("/{finding_id}/reopen", response_model=FindingResponse)
async def reopen_finding(
    finding_id: UUID,
    body: FindingReopenRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("developer")),
):
    """Reopen a closed finding."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    if finding.status not in CLOSE_STATUSES:
        raise HTTPException(status_code=400, detail="Finding is not closed")

    finding.status = "open"
    finding.close_reason = None
    finding.justification = None
    finding.closed_by = None
    finding.closed_at = None
    finding.resolved_at = None

    await db.commit()
    await db.refresh(finding)
    return finding


@router.post("/{finding_id}/verify", response_model=VerifyResponse)
async def verify_k8s_finding(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("developer")),
):
    """Re-verify a K8s finding by running a targeted scan on the specific control+resource."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    rd = finding.raw_data or {}
    control_id = rd.get("controlID") or rd.get("ID")
    resource_kind = rd.get("k8s_resource_kind", "")
    resource_name = rd.get("k8s_resource_name", "")
    namespace = rd.get("k8s_namespace", "")

    if not control_id:
        raise HTTPException(status_code=400, detail="Finding has no control ID — cannot verify")

    # Get project kubeconfig
    proj_result = await db.execute(select(Project).where(Project.id == finding.project_id))
    project = proj_result.scalar_one_or_none()
    if not project or not project.kubeconfig_data:
        raise HTTPException(status_code=400, detail="Project has no kubeconfig configured — upload one first")

    # Write kubeconfig to temp file
    import yaml as _yaml
    kubeconfig_path = None
    report_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as kf:
            _yaml.dump(project.kubeconfig_data, kf)
            kubeconfig_path = kf.name

        report_path = f"/tmp/verify_{finding_id}.json"

        is_kubescape = finding.tool_name == "kubescape"

        if is_kubescape:
            # Targeted kubescape scan for specific control
            cmd = [
                "kubescape", "scan", "control", control_id,
                "--format", "json", "--output", report_path,
                "--kubeconfig", kubeconfig_path,
            ]
            if namespace:
                cmd.extend(["--include-namespaces", namespace])
        else:
            # Trivy K8s scan — can't target a single control, so run full misconfig scan
            cmd = [
                "trivy", "k8s", "--format", "json",
                "--kubeconfig", kubeconfig_path,
                "--timeout", "5m0s", "--report", "all",
                "--scanners", "misconfig", "--disable-node-collector",
                "--output", report_path,
            ]
            if namespace:
                cmd.extend(["--include-namespaces", namespace])

        logger.info("Verify command: %s", " ".join(cmd))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if not os.path.exists(report_path):
            raise HTTPException(status_code=500, detail=f"Scan tool did not produce output. stderr: {proc.stderr[:500]}")

        with open(report_path, "r") as f:
            report = json.load(f)

        # Check if the specific control+resource was scanned AND passed.
        # "resource_found" = we saw the resource in the scan results
        # "control_passed" = the control status for that resource is explicitly "passed"
        # "control_failed" = still failing
        # If resource not found at all → cannot verify (scan scope too narrow)
        resource_found = False
        control_passed = False
        control_failed = False
        remediation_hint = finding.remediation or rd.get("Resolution", "")

        if is_kubescape:
            # Kubescape v4: results[] are per-resource, each has controls[]
            for res in report.get("results", []):
                rid = res.get("resourceID", "")
                # Match: resource name must appear in resourceID
                if resource_name and resource_name.lower() not in rid.lower():
                    continue
                # Also check kind if present in resourceID
                if resource_kind and resource_kind.lower() not in rid.lower():
                    continue
                resource_found = True
                for ctrl in res.get("controls", []):
                    cid = ctrl.get("controlID", "")
                    if cid != control_id:
                        continue
                    st = ctrl.get("status", {})
                    st_str = st.get("status", "") if isinstance(st, dict) else str(st)
                    if st_str.lower() in ("failed", "fail"):
                        control_failed = True
                    elif st_str.lower() in ("passed", "pass", "skipped"):
                        control_passed = True
                    break
                if control_failed:
                    break
        else:
            # Trivy K8s: Resources[] → each has Kind, Name, Results[] → Misconfigurations[]
            for res_entry in report.get("Resources", report.get("Results", [])):
                res_kind = res_entry.get("Kind", "")
                res_name_trivy = res_entry.get("Name", "")
                # Also support flat Results[] format (Target field)
                target = res_entry.get("Target", "")

                # Match by kind+name or target string
                matched = False
                if res_kind and res_name_trivy:
                    matched = (
                        res_name_trivy.lower() == resource_name.lower()
                        and (not resource_kind or res_kind.lower() == resource_kind.lower())
                    )
                elif target and resource_name:
                    matched = resource_name.lower() in target.lower()

                if not matched:
                    continue

                resource_found = True
                for inner_result in res_entry.get("Results", [res_entry]):
                    for mc in inner_result.get("Misconfigurations", []):
                        mc_id = mc.get("ID", "")
                        if mc_id != control_id:
                            continue
                        if mc.get("Status", "").upper() == "FAIL":
                            control_failed = True
                            remediation_hint = mc.get("Resolution", remediation_hint)
                        elif mc.get("Status", "").upper() == "PASS":
                            control_passed = True
                        break
                    if control_failed:
                        break
                if control_failed:
                    break

        # Decision logic:
        # 1. Still failing → reject
        if control_failed:
            return VerifyResponse(
                verified=False,
                message=f"NOT FIXED: {control_id} is still failing on {resource_kind}/{resource_name}. "
                        f"Remediation: {remediation_hint}" if remediation_hint else
                        f"NOT FIXED: {control_id} is still failing on {resource_kind}/{resource_name}.",
                finding=FindingResponse.model_validate(finding),
            )

        # 2. Resource found and control NOT failing → verified fixed
        #    Trivy only reports FAIL statuses — if the control is absent from
        #    misconfigurations, it means the check passed. Kubescape may report
        #    explicit "passed" status. Either way: resource scanned + no failure = fixed.
        if resource_found and not control_failed:
            now = datetime.now(timezone.utc)
            finding.status = "resolved"
            finding.close_reason = "rescan_verified"
            finding.justification = (
                f"Automated re-verification confirmed {control_id} is no longer failing "
                f"on {resource_kind}/{resource_name}"
                + (f" in namespace {namespace}" if namespace else "")
            )
            finding.closed_by = current_user.id
            finding.closed_at = now
            finding.resolved_at = now
            await db.commit()
            await db.refresh(finding)

            return VerifyResponse(
                verified=True,
                message=f"Verified: {control_id} is no longer failing on {resource_kind}/{resource_name}. Finding closed.",
                finding=FindingResponse.model_validate(finding),
            )

        # 3. Resource not found in scan → inconclusive
        return VerifyResponse(
            verified=False,
            message=f"Could not verify: {resource_kind}/{resource_name} was not found in the scan results. "
                    f"The resource may have been deleted or the scan scope was too narrow. "
                    f"If the resource was intentionally removed, use 'Accept Risk' to close.",
            finding=FindingResponse.model_validate(finding),
        )

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Verification scan timed out")
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Verify error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(exc)}")
    finally:
        if kubeconfig_path and os.path.exists(kubeconfig_path):
            os.remove(kubeconfig_path)
        if report_path and os.path.exists(report_path):
            os.remove(report_path)


@router.post("/{finding_id}/generate-fix")
async def generate_fix(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("developer")),
):
    """Generate a kubectl patch for a K8s finding using the control fix registry."""
    from app.models.control_fix import ControlFix
    from app.schemas.control_fix import GeneratedPatchResponse
    from app.services.patch_generator import render_patch

    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    rd = finding.raw_data or {}
    control_id = rd.get("controlID") or rd.get("ID") or ""
    if not control_id:
        raise HTTPException(status_code=400, detail="Finding has no control ID")

    # Look up fix template
    fix_result = await db.execute(
        select(ControlFix).where(ControlFix.control_id == control_id)
    )
    fix = fix_result.scalar_one_or_none()
    if not fix:
        raise HTTPException(
            status_code=404,
            detail=f"No fix template available for control {control_id}. This control requires manual remediation.",
        )

    resource_kind = rd.get("k8s_resource_kind", "")
    resource_name = rd.get("k8s_resource_name", "")
    namespace = rd.get("k8s_namespace", "")

    # Validate applicable kinds
    if fix.applicable_kinds and resource_kind and resource_kind not in fix.applicable_kinds:
        raise HTTPException(
            status_code=400,
            detail=f"Fix template for {control_id} applies to {', '.join(fix.applicable_kinds)} but this finding is on {resource_kind}.",
        )

    patch_yaml, kubectl_cmd = render_patch(
        template=fix.patch_template,
        patch_type=fix.patch_type,
        resource_kind=resource_kind,
        resource_name=resource_name,
        namespace=namespace,
        control_id=control_id,
    )

    # Enrich with finding-specific context (CauseMetadata, Message)
    message = rd.get("Message", "")
    resolution = finding.remediation or rd.get("Resolution", "")
    cause_lines = rd.get("CauseMetadata", {}).get("Code", {}).get("Lines", [])
    start_line = rd.get("CauseMetadata", {}).get("StartLine")
    end_line = rd.get("CauseMetadata", {}).get("EndLine")

    # For manual/RBAC fixes, build a richer output with the actual affected config
    if fix.patch_type == "manual" or cause_lines:
        sections = []
        sections.append(f"# Fix for: {control_id} — {fix.title}")
        sections.append(f"# Resource: {resource_kind}/{resource_name}")
        if namespace:
            sections.append(f"# Namespace: {namespace}")
        sections.append(f"#")
        if message:
            sections.append(f"# Issue: {message}")
        if resolution:
            sections.append(f"# Remediation: {resolution}")
        sections.append(f"#")
        sections.append(f"# Command to edit:")
        ns_flag = f" -n {namespace}" if namespace else ""
        sections.append(f"# kubectl edit {resource_kind.lower()} {resource_name}{ns_flag}")
        sections.append(f"#")

        if cause_lines:
            sections.append(f"# ── Affected Configuration (lines {start_line or '?'}-{end_line or '?'}) ──")
            for line in cause_lines:
                content = line.get("Content", "")
                num = line.get("Number", "")
                marker = " >>>" if line.get("IsCause") else "    "
                sections.append(f"#{marker} {num}: {content}")
            sections.append(f"#")

        sections.append(f"# ── Fix Instructions ──")
        # Append the template content
        for tpl_line in patch_yaml.strip().split("\n"):
            sections.append(tpl_line)

        patch_yaml = "\n".join(sections)
        kubectl_cmd = f"kubectl edit {resource_kind.lower()} {resource_name}{ns_flag}"

    # Build combined notes
    combined_notes = fix.notes or ""
    if message and message not in combined_notes:
        combined_notes = f"{message}\n\n{combined_notes}" if combined_notes else message

    return GeneratedPatchResponse(
        control_id=control_id,
        title=fix.title,
        patch_type=fix.patch_type,
        resource_kind=resource_kind,
        resource_name=resource_name,
        namespace=namespace,
        patch_yaml=patch_yaml,
        kubectl_command=kubectl_cmd,
        notes=combined_notes,
        risk_level=fix.risk_level,
    )


@router.patch("/bulk", response_model=list[FindingResponse])
async def bulk_update_findings(
    body: FindingBulkUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("security_engineer")),
):
    """Bulk update findings by IDs. Requires security_engineer role."""
    result = await db.execute(
        select(Finding).where(Finding.id.in_(body.ids))
    )
    findings = result.scalars().all()

    if not findings:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No findings found for the given IDs")

    update_data = body.model_dump(exclude={"ids"}, exclude_unset=True)

    for finding in findings:
        if "status" in update_data and update_data["status"] == "resolved":
            finding.resolved_at = datetime.now(timezone.utc)

        for field, value in update_data.items():
            setattr(finding, field, value)

    await db.commit()

    for finding in findings:
        await db.refresh(finding)

    return findings
