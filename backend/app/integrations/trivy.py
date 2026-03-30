import json
import logging
import subprocess
import tarfile
import tempfile
from typing import Optional

from app.config import settings
from app.integrations.base import BaseIntegration, NormalizedFinding
from app.utils.dedup import compute_fingerprint
from app.utils.severity_mapper import normalize_severity

logger = logging.getLogger(__name__)


class TrivyIntegration(BaseIntegration):
    tool_name = "trivy"
    scan_type = "dependency"

    def __init__(self):
        self.server_url = getattr(settings, "TRIVY_SERVER_URL", None)
        # Each worker process gets its own cache dir to avoid concurrent lock contention
        import os
        self.cache_dir = f"/tmp/trivy-cache-{os.getpid()}"

    def _base_cmd(self, scan_type: str, target: str, username: str = "", password: str = "") -> list[str]:
        cmd = ["trivy", scan_type, target, "--format", "json", "--cache-dir", self.cache_dir]
        if self.server_url:
            cmd.extend(["--server", self.server_url])
        if username:
            cmd.extend(["--username", username])
        if password:
            cmd.extend(["--password", password])
        return cmd

    def _run_cmd(self, cmd: list[str], fallback_cmd: list[str] | None = None) -> dict:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode != 0 and fallback_cmd:
                logger.warning("Trivy server unavailable, falling back to local scan: %s", result.stderr[:300])
                result = subprocess.run(fallback_cmd, capture_output=True, text=True, timeout=600)
            if result.returncode != 0:
                # Extract the last meaningful line from stderr for the error message
                lines = [l.strip() for l in result.stderr.splitlines() if l.strip()]
                msg = lines[-1] if lines else result.stderr[:300]
                raise RuntimeError(f"Trivy exited with code {result.returncode}: {msg}")
            return json.loads(result.stdout)
        except RuntimeError:
            raise
        except FileNotFoundError:
            raise RuntimeError("Trivy binary not found in PATH")
        except subprocess.TimeoutExpired:
            raise RuntimeError("Trivy scan timed out after 600s")
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Failed to parse Trivy JSON output: {exc}")

    def run_scan(self, target: str, config: dict) -> list[NormalizedFinding]:
        """Entry point — routes to the correct sub-scanner."""
        subtype = config.get("scan_subtype", "dependency")
        if subtype == "secrets":
            return self._run_secrets_scan(target, config)
        if subtype == "k8s":
            return self._run_k8s_scan(target, config)
        return self._run_dependency_scan(target, config)

    def run_sbom_scan(self, target: str, config: dict) -> dict | None:
        """Run a Trivy SBOM scan and return raw CycloneDX JSON."""
        scan_type = config.get("scan_type", "image")
        if scan_type not in ("image", "repo", "fs"):
            scan_type = "image"
        username = config.get("registry_username", "")
        password = config.get("registry_password", "")

        is_tar = target.endswith((".tar", ".tar.gz", ".tgz"))
        if is_tar:
            return self._sbom_scan_tar(target)

        cmd = ["trivy", scan_type, target, "--format", "cyclonedx", "--quiet", "--cache-dir", self.cache_dir]
        if self.server_url:
            cmd.extend(["--server", self.server_url])
        if username:
            cmd.extend(["--username", username])
        if password:
            cmd.extend(["--password", password])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            lines = [l.strip() for l in result.stderr.splitlines() if l.strip()]
            msg = lines[-1] if lines else result.stderr[:300]
            raise RuntimeError(f"Trivy SBOM scan failed: {msg}")
        return json.loads(result.stdout)

    def _sbom_scan_tar(self, target: str) -> dict:
        """SBOM scan a tar: try Docker image, handle nested tar, fall back to fs."""
        import os

        def _sbom_cmd(cmd):
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode != 0:
                raise RuntimeError(result.stderr[-300:])
            return json.loads(result.stdout)

        try:
            return _sbom_cmd(["trivy", "image", "--input", target, "--format", "cyclonedx", "--quiet"])
        except RuntimeError:
            pass

        logger.info("Not a direct Docker image tar for SBOM, extracting: %s", target)
        with tempfile.TemporaryDirectory() as tmpdir:
            with tarfile.open(target, "r:*") as tf:
                tf.extractall(tmpdir)
            extracted = os.listdir(tmpdir)
            if len(extracted) == 1 and extracted[0].endswith(".tar"):
                inner_tar = os.path.join(tmpdir, extracted[0])
                try:
                    return _sbom_cmd(["trivy", "image", "--input", inner_tar, "--format", "cyclonedx", "--quiet"])
                except RuntimeError:
                    pass
            return _sbom_cmd(["trivy", "fs", tmpdir, "--format", "cyclonedx", "--quiet"])

    def _run_dependency_scan(self, target: str, config: dict) -> list[NormalizedFinding]:
        scan_type = config.get("scan_type", "repo")
        if scan_type not in ("repo", "image", "fs"):
            scan_type = "repo"
        username = config.get("registry_username", "")
        password = config.get("registry_password", "")

        # Tar/tar.gz files: try Docker image first, fall back to filesystem scan
        is_tar = target.endswith((".tar", ".tar.gz", ".tgz"))
        if is_tar:
            report = self._scan_tar(target)
        else:
            cmd = self._base_cmd(scan_type, target, username, password)
            fallback = None
            if self.server_url:
                # Fallback (local, no server) must also carry credentials
                fallback = ["trivy", scan_type, target, "--format", "json"]
                if username:
                    fallback.extend(["--username", username])
                if password:
                    fallback.extend(["--password", password])
            report = self._run_cmd(cmd, fallback)

        if report is None:
            return []
        return self._parse_vulnerabilities(report)

    def _scan_tar(self, target: str) -> dict:
        """Scan a tar/tar.gz: try Docker image first, handle nested tars, fall back to fs."""
        import os
        # First try as Docker/OCI image directly
        try:
            return self._run_cmd(["trivy", "image", "--input", target, "--format", "json"])
        except RuntimeError:
            pass

        logger.info("Not a direct Docker image tar, extracting: %s", target)
        with tempfile.TemporaryDirectory() as tmpdir:
            with tarfile.open(target, "r:*") as tf:
                tf.extractall(tmpdir)

            extracted = os.listdir(tmpdir)
            # If extraction yielded a single .tar, try it as a Docker image
            if len(extracted) == 1 and extracted[0].endswith(".tar"):
                inner_tar = os.path.join(tmpdir, extracted[0])
                logger.info("Found inner tar, trying trivy image --input: %s", inner_tar)
                try:
                    return self._run_cmd(["trivy", "image", "--input", inner_tar, "--format", "json"])
                except RuntimeError:
                    pass

            # Fall back to scanning extracted directory as filesystem
            logger.info("Falling back to trivy fs on extracted contents")
            return self._run_cmd(["trivy", "fs", tmpdir, "--format", "json"])

    def _run_secrets_scan(self, target: str, config: dict) -> list[NormalizedFinding]:
        scan_type = config.get("scan_type", "fs")
        if scan_type not in ("fs", "image", "repo"):
            scan_type = "fs"
        # trivy maps "repo" to "fs" for secrets
        trivy_cmd_type = "fs" if scan_type == "repo" else scan_type
        username = config.get("registry_username", "")
        password = config.get("registry_password", "")

        cmd = ["trivy", trivy_cmd_type, target, "--scanners", "secret", "--format", "json", "--cache-dir", self.cache_dir]
        if username:
            cmd.extend(["--username", username])
        if password:
            cmd.extend(["--password", password])

        report = self._run_cmd(cmd)
        if report is None:
            return []
        return self._parse_secrets(report)

    def parse_report(self, report_path: str) -> list[NormalizedFinding]:
        try:
            with open(report_path, "r", encoding="utf-8") as fh:
                report = json.load(fh)
            return self._parse_vulnerabilities(report)
        except Exception as exc:
            logger.error("Error parsing Trivy report: %s", exc)
            return []

    @staticmethod
    def _clean_target(target: str) -> str:
        """Strip internal upload paths from Trivy Target strings.

        e.g. '/app/uploads/images/uuid_file.tar.gz (alpine 3.22.2)' → 'alpine 3.22.2'
             '/app/uploads/images/uuid_file.tar.gz'                  → 'file.tar.gz'
             'usr/local/bin/traefik'                                  → 'usr/local/bin/traefik'
        """
        import re
        # If the target contains ' (...)' after a tar filename, extract the parenthesised part
        m = re.search(r'\(([^)]+)\)\s*$', target)
        if m:
            return m.group(1).strip()
        # Strip known upload directory prefix and UUID prefix (uuid_ or uuid-)
        if "/uploads/" in target:
            filename = target.rsplit("/", 1)[-1]
            # Remove leading UUID (8-4-4-4-12 hex chars followed by _ or -)
            filename = re.sub(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[_-]', '', filename, flags=re.IGNORECASE)
            return filename
        return target

    def _parse_vulnerabilities(self, report: dict) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for result_block in report.get("Results", []):
            target_file = self._clean_target(result_block.get("Target", ""))
            for vuln in result_block.get("Vulnerabilities") or []:
                vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
                pkg_name = vuln.get("PkgName", "unknown")
                raw_severity = vuln.get("Severity", "UNKNOWN")

                cvss_score: Optional[float] = None
                for source_data in vuln.get("CVSS", {}).values():
                    if isinstance(source_data, dict) and "V3Score" in source_data:
                        cvss_score = float(source_data["V3Score"])
                        break

                fixed_version = vuln.get("FixedVersion", "")
                remediation = f"Upgrade {pkg_name} to {fixed_version}" if fixed_version else None

                finding = NormalizedFinding(
                    title=f"{vuln_id}: {pkg_name}",
                    description=vuln.get("Description", ""),
                    severity=normalize_severity(raw_severity),
                    file_path=target_file,
                    line_number=None,
                    cwe_id=None,
                    cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
                    cvss_score=cvss_score,
                    remediation=remediation,
                    raw_data=vuln,
                )
                finding.fingerprint = compute_fingerprint(finding)
                findings.append(finding)
        return findings

    def _run_k8s_scan(self, target: str, config: dict) -> list[NormalizedFinding]:
        """Scan a live Kubernetes cluster using trivy k8s."""
        kubeconfig_path = config.get("kubeconfig_path", "/root/.kube/config")
        namespace = config.get("namespace")

        cmd = ["trivy", "k8s", "--format", "json", "--cache-dir", self.cache_dir,
               "--kubeconfig", kubeconfig_path, "--timeout", "10m0s",
               "--report", "all", "--scanners", "misconfig",
               "--disable-node-collector"]
        if namespace:
            cmd.extend(["--include-namespaces", namespace])

        report = self._run_cmd(cmd)
        if report is None:
            return []
        return self._parse_k8s_findings(report)

    def _parse_k8s_findings(self, report: dict) -> list[NormalizedFinding]:
        """Parse Trivy K8s JSON into normalized findings."""
        findings: list[NormalizedFinding] = []

        # Trivy k8s wraps resources; handle both formats
        resources = report.get("Resources", [])
        if not resources and "Results" in report:
            resources = [report]

        for resource in resources:
            namespace = resource.get("Namespace", "")
            kind = resource.get("Kind", "")
            name = resource.get("Name", "")
            resource_label = f"{kind}/{name}" + (f" ({namespace})" if namespace else "")

            for result_block in resource.get("Results", []):
                # Misconfigurations
                for mc in result_block.get("Misconfigurations") or []:
                    raw_sev = mc.get("Severity", "UNKNOWN")
                    finding = NormalizedFinding(
                        title=f"{mc.get('ID', 'UNKNOWN')}: {mc.get('Title', '')}",
                        description=mc.get("Description", ""),
                        severity=normalize_severity(raw_sev),
                        file_path=resource_label,
                        line_number=None,
                        cwe_id=None,
                        cve_id=None,
                        cvss_score=None,
                        remediation=mc.get("Resolution") or mc.get("Message"),
                        raw_data={
                            **mc,
                            "k8s_resource_kind": kind,
                            "k8s_resource_name": name,
                            "k8s_namespace": namespace,
                            "finding_type": "misconfiguration",
                            "category": mc.get("Type", "Unknown"),
                        },
                    )
                    finding.fingerprint = compute_fingerprint(finding)
                    findings.append(finding)

                # Vulnerabilities in running images
                for vuln in result_block.get("Vulnerabilities") or []:
                    vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
                    pkg = vuln.get("PkgName", "unknown")
                    cvss: Optional[float] = None
                    for src in vuln.get("CVSS", {}).values():
                        if isinstance(src, dict) and "V3Score" in src:
                            cvss = float(src["V3Score"])
                            break
                    fixed = vuln.get("FixedVersion", "")
                    finding = NormalizedFinding(
                        title=f"{vuln_id}: {pkg} in {resource_label}",
                        description=vuln.get("Description", ""),
                        severity=normalize_severity(vuln.get("Severity", "UNKNOWN")),
                        file_path=resource_label,
                        line_number=None,
                        cwe_id=None,
                        cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
                        cvss_score=cvss,
                        remediation=f"Upgrade {pkg} to {fixed}" if fixed else None,
                        raw_data={
                            **vuln,
                            "k8s_resource_kind": kind,
                            "k8s_resource_name": name,
                            "k8s_namespace": namespace,
                            "finding_type": "vulnerability",
                        },
                    )
                    finding.fingerprint = compute_fingerprint(finding)
                    findings.append(finding)

        return findings

    def _parse_secrets(self, report: dict) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for result_block in report.get("Results", []):
            target_file = self._clean_target(result_block.get("Target", ""))
            for secret in result_block.get("Secrets") or []:
                raw_severity = secret.get("Severity", "HIGH")
                finding = NormalizedFinding(
                    title=f"Secret: {secret.get('Title', secret.get('RuleID', 'Unknown'))}",
                    description=f"Rule: {secret.get('RuleID', '')} | Match: {secret.get('Match', '')[:200]}",
                    severity=normalize_severity(raw_severity),
                    file_path=target_file,
                    line_number=secret.get("StartLine"),
                    cwe_id=None,
                    cve_id=None,
                    cvss_score=None,
                    remediation="Remove the secret from source code and rotate the credential immediately.",
                    raw_data=secret,
                )
                finding.fingerprint = compute_fingerprint(finding)
                findings.append(finding)
        return findings
