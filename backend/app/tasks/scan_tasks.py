import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.config import settings
from app.integrations.base import NormalizedFinding
from app.integrations.trivy import TrivyIntegration
from app.integrations.gitleaks import GitleaksIntegration
from app.integrations.semgrep import SemgrepIntegration
from app.integrations.kubescape import KubescapeIntegration
from app.integrations.zap import ZapIntegration
from app.integrations.parsers.burp_parser import parse_burp_report
from app.integrations.parsers.nessus_parser import parse_nessus_report
from app.integrations.parsers.generic_parser import parse_generic_json, parse_generic_csv
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.report import Report
from app.tasks.celery_app import celery

logger = logging.getLogger(__name__)

sync_engine = create_engine(settings.sync_database_url)

TOOL_INTEGRATIONS = {
    "trivy": TrivyIntegration,
    "gitleaks": GitleaksIntegration,
    "semgrep": SemgrepIntegration,
    "kubescape": KubescapeIntegration,
    "zap": ZapIntegration,
}


def _save_findings(session: Session, scan_id: uuid.UUID, project_id: uuid.UUID, tool_name: str, findings: list[NormalizedFinding]):
    if not findings:
        return 0

    # Separate findings with and without fingerprints, dedup by fingerprint
    seen_fp: set[str] = set()
    with_fp: list[NormalizedFinding] = []
    without_fp: list[NormalizedFinding] = []
    for f in findings:
        if f.fingerprint:
            if f.fingerprint not in seen_fp:
                seen_fp.add(f.fingerprint)
                with_fp.append(f)
        else:
            without_fp.append(f)

    count = 0

    # Upsert fingerprinted findings — on conflict update scan_id so "View Results" stays linked
    if with_fp:
        stmt = pg_insert(Finding).values([
            dict(
                id=uuid.uuid4(),
                scan_id=scan_id,
                project_id=project_id,
                tool_name=tool_name,
                severity=f.severity,
                title=f.title[:500],
                description=f.description,
                file_path=f.file_path,
                line_number=f.line_number,
                cwe_id=(f.cwe_id or "")[:255],
                cve_id=(f.cve_id or "")[:50] if f.cve_id else None,
                cvss_score=f.cvss_score,
                remediation=f.remediation,
                fingerprint=f.fingerprint,
                raw_data=f.raw_data,
            )
            for f in with_fp
        ])
        stmt = stmt.on_conflict_do_update(
            index_elements=["project_id", "fingerprint"],
            index_where=Finding.__table__.c.fingerprint.isnot(None),
            set_={"scan_id": stmt.excluded.scan_id},
        )
        session.execute(stmt)
        count += len(with_fp)

    # Findings without fingerprints are always inserted as new rows
    for f in without_fp:
        session.add(Finding(
            scan_id=scan_id,
            project_id=project_id,
            tool_name=tool_name,
            severity=f.severity,
            title=f.title[:500],
            description=f.description,
            file_path=f.file_path,
            line_number=f.line_number,
            cwe_id=(f.cwe_id or "")[:255],
            cve_id=(f.cve_id or "")[:50] if f.cve_id else None,
            cvss_score=f.cvss_score,
            remediation=f.remediation,
            fingerprint=f.fingerprint,
            raw_data=f.raw_data,
        ))
        count += 1

    return count


@celery.task(bind=True, max_retries=2)
def run_scan_task(self, scan_id: str):
    logger.info(f"Starting scan task: {scan_id}")
    with Session(sync_engine) as session:
        scan = session.get(Scan, uuid.UUID(scan_id))
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        session.commit()

        integration_cls = TOOL_INTEGRATIONS.get(scan.tool_name)
        if not integration_cls:
            scan.status = "failed"
            scan.error_message = f"Unknown tool: {scan.tool_name}"
            scan.completed_at = datetime.now(timezone.utc)
            session.commit()
            return

        kubeconfig_tmpfile = None
        try:
            integration = integration_cls()
            config = scan.config_json or {}
            target = config.get("target", "")
            clone_dir = None
            is_sbom = (scan.tool_name == "trivy" and config.get("scan_subtype") == "sbom")
            is_k8s = scan.scan_type == "k8s"

            # For K8s scans: write project kubeconfig to temp file if stored in DB
            if is_k8s and "kubeconfig_path" not in config:
                from app.models.project import Project as ProjectModel
                proj = session.execute(
                    select(ProjectModel).where(ProjectModel.id == scan.project_id)
                ).scalar_one_or_none()
                if proj and proj.kubeconfig_data:
                    import yaml as _yaml
                    kubeconfig_tmpfile = f"/tmp/kubeconfig_{scan.id}.yaml"
                    with open(kubeconfig_tmpfile, "w") as kf:
                        _yaml.dump(proj.kubeconfig_data, kf)
                    config["kubeconfig_path"] = kubeconfig_tmpfile

            # If no explicit target, try to use project's repo URL
            if not target and scan.project_id:
                from app.models.project import Project
                project_row = session.execute(
                    select(Project).where(Project.id == scan.project_id)
                ).scalar_one_or_none()
                if project_row and project_row.repo_url:
                    try:
                        from app.services.remote_scan import clone_repo
                        branch = config.get("branch", "main")
                        clone_dir = clone_repo(project_row.repo_url, branch)
                        target = clone_dir
                        logger.info(f"Cloned {project_row.repo_url} to {clone_dir}")
                    except Exception as e:
                        logger.warning(f"Failed to clone repo: {e}. Continuing with empty target.")

            if is_sbom:
                sbom_data = integration.run_sbom_scan(target, config)
                scan.output_data = sbom_data or {}
                scan.findings_count = len((sbom_data or {}).get("components", []))
                scan.status = "completed"
                scan.completed_at = datetime.now(timezone.utc)
                session.commit()
                logger.info(f"SBOM scan {scan_id} completed: {scan.findings_count} components")
            else:
                normalized = integration.run_scan(target, config)
                count = _save_findings(session, scan.id, scan.project_id, scan.tool_name, normalized)
                scan.findings_count = count
                unique_pkg_count = len(set(
                    f"{(f.raw_data or {}).get('PkgName','')}||{(f.raw_data or {}).get('InstalledVersion','')}"
                    for f in normalized
                    if (f.raw_data or {}).get('PkgName')
                ))
                fixable_count = len(set(
                    f"{(f.raw_data or {}).get('PkgName','')}||{(f.raw_data or {}).get('InstalledVersion','')}"
                    for f in normalized
                    if (f.raw_data or {}).get('PkgName') and (f.raw_data or {}).get('FixedVersion','')
                ))
                no_fix_count = len(set(
                    f"{(f.raw_data or {}).get('PkgName','')}||{(f.raw_data or {}).get('InstalledVersion','')}"
                    for f in normalized
                    if (f.raw_data or {}).get('PkgName') and not (f.raw_data or {}).get('FixedVersion','')
                ))
                scan.config_json = {
                    **(scan.config_json or {}),
                    'unique_packages_count': unique_pkg_count,
                    'fixable_count': fixable_count,
                    'no_fix_count': no_fix_count,
                }
                scan.status = "completed"
                scan.completed_at = datetime.now(timezone.utc)
                session.commit()
                logger.info(f"Scan {scan_id} completed: {count} findings")

            # Cleanup cloned repo
            if clone_dir:
                from app.services.remote_scan import cleanup_repo
                cleanup_repo(clone_dir)
            if kubeconfig_tmpfile:
                import os
                try: os.remove(kubeconfig_tmpfile)
                except OSError: pass

        except Exception as e:
            logger.exception(f"Scan {scan_id} failed")
            scan.status = "failed"
            scan.error_message = str(e)[:1000]
            scan.completed_at = datetime.now(timezone.utc)
            session.commit()

            # Cleanup cloned repo
            if clone_dir:
                from app.services.remote_scan import cleanup_repo
                cleanup_repo(clone_dir)
            if kubeconfig_tmpfile:
                import os
                try: os.remove(kubeconfig_tmpfile)
                except OSError: pass


REPORT_PARSERS = {
    "burpsuite": parse_burp_report,
    "burp": parse_burp_report,
    "nessus": parse_nessus_report,
}


@celery.task(bind=True, max_retries=2)
def parse_report_task(self, report_id: str):
    logger.info(f"Parsing report: {report_id}")
    with Session(sync_engine) as session:
        report = session.get(Report, uuid.UUID(report_id))
        if not report:
            logger.error(f"Report {report_id} not found")
            return

        try:
            tool = (report.tool_name or "").lower()
            file_path = report.file_path

            parser = REPORT_PARSERS.get(tool)
            if parser:
                findings = parser(file_path)
            elif file_path.endswith(".json"):
                findings = parse_generic_json(file_path)
            elif file_path.endswith(".csv"):
                findings = parse_generic_csv(file_path)
            elif file_path.endswith(".xml"):
                # Try Burp first, then Nessus
                try:
                    findings = parse_burp_report(file_path)
                except Exception:
                    findings = parse_nessus_report(file_path)
            else:
                findings = parse_generic_json(file_path)

            tool_name = report.tool_name or "imported"
            count = _save_findings(session, None, report.project_id, tool_name, findings)

            report.parsed = True
            report.findings_count = count
            session.commit()
            logger.info(f"Report {report_id} parsed: {count} findings")

        except Exception as e:
            logger.exception(f"Report {report_id} parsing failed")
            report.parsed = False
            session.commit()
