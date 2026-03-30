import json
import logging
import os
import subprocess
import uuid

from app.integrations.base import BaseIntegration, NormalizedFinding
from app.utils.dedup import compute_fingerprint
from app.utils.severity_mapper import normalize_severity

logger = logging.getLogger(__name__)

# Mapping from Kubescape scoreFactor ranges to severity strings
_SCORE_FACTOR_SEVERITY = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (1.0, "low"),
    (0.0, "info"),
]


def _severity_from_score_factor(score_factor: float) -> str:
    """Map a Kubescape scoreFactor (0-10) to a severity string."""
    for threshold, sev in _SCORE_FACTOR_SEVERITY:
        if score_factor >= threshold:
            return sev
    return "info"


class KubescapeIntegration(BaseIntegration):
    tool_name = "kubescape"
    scan_type = "k8s"

    def run_scan(self, target: str, config: dict) -> list[NormalizedFinding]:
        """Execute a Kubescape scan using the NSA framework."""
        report_path = f"/tmp/kubescape_{uuid.uuid4().hex}.json"
        framework = config.get("framework", "nsa")

        cmd = [
            "kubescape",
            "scan",
            "framework",
            framework,
            "--format",
            "json",
            "--output",
            report_path,
        ]

        # Kubeconfig for live cluster scanning
        kubeconfig_path = config.get("kubeconfig_path")
        if kubeconfig_path:
            cmd.extend(["--kubeconfig", kubeconfig_path])

        # If a specific target path is provided, add it
        if target:
            cmd.append(target)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600
            )
            if result.returncode != 0:
                logger.warning(
                    "Kubescape scan returned non-zero exit code %d: %s",
                    result.returncode,
                    result.stderr,
                )

            if not os.path.exists(report_path):
                logger.error(
                    "Kubescape did not produce output file at %s", report_path
                )
                return []

            return self._parse_kubescape_file(report_path)

        except FileNotFoundError:
            logger.error("Kubescape binary not found in PATH")
            return []
        except subprocess.TimeoutExpired:
            logger.error("Kubescape scan timed out")
            return []
        except Exception as exc:
            logger.error("Unexpected error during Kubescape scan: %s", exc)
            return []
        finally:
            if os.path.exists(report_path):
                os.remove(report_path)

    def parse_report(self, report_path: str) -> list[NormalizedFinding]:
        """Parse a Kubescape JSON report file."""
        try:
            return self._parse_kubescape_file(report_path)
        except FileNotFoundError:
            logger.error("Report file not found: %s", report_path)
            return []
        except Exception as exc:
            logger.error("Error parsing Kubescape report: %s", exc)
            return []

    def _parse_kubescape_file(self, path: str) -> list[NormalizedFinding]:
        """Read and parse a Kubescape JSON file."""
        with open(path, "r", encoding="utf-8") as fh:
            report = json.load(fh)
        return self._parse_kubescape_json(report)

    @staticmethod
    def _load_framework_controls() -> dict[str, dict]:
        """Load control metadata (description, remediation) from cached framework files."""
        cache_dir = os.environ.get("KS_CACHE_DIR", os.path.expanduser("~/.kubescape"))
        ctrl_meta: dict[str, dict] = {}
        for fname in os.listdir(cache_dir) if os.path.isdir(cache_dir) else []:
            if not fname.endswith(".json"):
                continue
            try:
                with open(os.path.join(cache_dir, fname), "r", encoding="utf-8") as fh:
                    fw = json.load(fh)
                for ctrl in fw.get("controls", []):
                    cid = ctrl.get("controlID", "")
                    if not cid or cid in ctrl_meta:
                        continue
                    ctrl_meta[cid] = {
                        "description": ctrl.get("description", ""),
                        "remediation": ctrl.get("remediation", ""),
                        "baseScore": ctrl.get("baseScore", 0),
                    }
            except Exception:
                continue
        return ctrl_meta

    def _parse_kubescape_json(self, report: dict) -> list[NormalizedFinding]:
        """Parse Kubescape JSON structure into normalized findings.

        Supports Kubescape v4 format where:
        - ``results`` is a list of *resources*, each containing ``controls``
        - ``resources`` holds object metadata (kind, name, namespace)
        - ``summaryDetails.controls`` has control-level metadata (category, scoreFactor)
        Also falls back to older v2/v3 format where results is a list of controls.
        """
        findings: list[NormalizedFinding] = []

        # ── Load control descriptions/remediation from cached framework files ──
        fw_controls = self._load_framework_controls()

        # ── Build resource metadata lookup from resources section ──
        res_meta: dict[str, dict] = {}
        for res in report.get("resources", []):
            rid = res.get("resourceID", "")
            obj = res.get("object", {})
            meta = obj.get("metadata", {})
            res_meta[rid] = {
                "kind": obj.get("kind", ""),
                "name": meta.get("name", ""),
                "namespace": meta.get("namespace", ""),
            }

        # ── Build control summary lookup (category, scoreFactor, remediation) ──
        ctrl_summary: dict[str, dict] = {}
        sd_controls = report.get("summaryDetails", {}).get("controls", {})
        if isinstance(sd_controls, dict):
            for cid, cv in sd_controls.items():
                cat = cv.get("category", {})
                fw_ctrl = fw_controls.get(cid, {})
                ctrl_summary[cid] = {
                    "scoreFactor": float(cv.get("scoreFactor", 0)),
                    "severity": cv.get("severity", ""),
                    "category": cat.get("name", "General") if isinstance(cat, dict) else "General",
                    "remediation": fw_ctrl.get("remediation") or cv.get("remediation", ""),
                    "description": fw_ctrl.get("description") or cv.get("description", ""),
                }

        results = report.get("results", [])

        # ── Detect format: v4 (resources with nested controls) vs v2/v3 (flat controls) ──
        if results and "controls" in results[0] and "resourceID" in results[0]:
            return self._parse_v4(results, res_meta, ctrl_summary)

        # Fallback: older format — results is a list of controls
        if not results and "controlReports" in report:
            results = report["controlReports"]
        return self._parse_legacy(results)

    def _parse_v4(self, results: list, res_meta: dict, ctrl_summary: dict) -> list[NormalizedFinding]:
        """Parse Kubescape v4 format: per-resource results with nested controls."""
        findings: list[NormalizedFinding] = []
        seen: set[str] = set()

        for res in results:
            rid = res.get("resourceID", "")
            meta = res_meta.get(rid, {})
            kind = meta.get("kind", "")
            name = meta.get("name", "")
            namespace = meta.get("namespace", "")

            for ctrl in res.get("controls", []):
                status = ctrl.get("status", {})
                if isinstance(status, dict):
                    status_str = status.get("status", "")
                else:
                    status_str = str(status)
                if status_str.lower() not in ("failed", "fail"):
                    continue

                control_id = ctrl.get("controlID", "UNKNOWN")
                control_name = ctrl.get("name", "Unnamed Control")
                severity_raw = ctrl.get("severity", "")

                # Enrich from summary
                summary = ctrl_summary.get(control_id, {})
                score_factor = float(summary.get("scoreFactor", 0))
                category = summary.get("category", "General")
                remediation = summary.get("remediation") or ""
                ctrl_description = summary.get("description") or ""

                # Determine severity from severity field or score factor
                if severity_raw:
                    severity_str = normalize_severity(severity_raw.lower())
                else:
                    severity_str = normalize_severity(_severity_from_score_factor(score_factor))

                # Deduplicate: one finding per control+resource
                dedup_key = f"{control_id}|{rid}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # Extract failed/fix paths from rules
                failed_paths: list[str] = []
                fix_paths: list[dict] = []
                for rule in ctrl.get("rules", []):
                    if rule.get("status", "").lower() not in ("failed", "fail"):
                        continue
                    for p in rule.get("paths", []):
                        fp = p.get("failedPath", "")
                        if fp:
                            failed_paths.append(fp)
                        fix = p.get("fixPath", {})
                        if fix and fix.get("path"):
                            fix_paths.append(fix)

                file_path = f"{kind}/{name}" if kind or name else None

                # Build reference URL
                ref_url = f"https://hub.armosec.io/docs/{control_id.lower()}"

                finding = NormalizedFinding(
                    title=f"{control_id}: {control_name}",
                    description=ctrl_description,
                    severity=severity_str,
                    file_path=file_path,
                    line_number=None,
                    cwe_id=None,
                    cve_id=None,
                    cvss_score=score_factor,
                    remediation=remediation,
                    raw_data={
                        "controlID": control_id,
                        "name": control_name,
                        "k8s_affected_resources": [{"kind": kind, "name": name, "namespace": namespace}],
                        "k8s_resource_kind": kind,
                        "k8s_resource_name": name,
                        "k8s_namespace": namespace,
                        "finding_type": "compliance",
                        "category": category,
                        "PrimaryURL": ref_url,
                        "References": [ref_url],
                        "Message": f"{control_name} failed on {kind}/{name}"
                            + (f" in namespace {namespace}" if namespace else ""),
                        "Resolution": remediation,
                        "failedPaths": failed_paths[:10],
                        "fixPaths": fix_paths[:10],
                    },
                )
                finding.fingerprint = compute_fingerprint(finding)
                findings.append(finding)

        return findings

    def _parse_legacy(self, controls: list) -> list[NormalizedFinding]:
        """Parse older Kubescape format (v2/v3): flat list of controls."""
        findings: list[NormalizedFinding] = []

        for control in controls:
            control_id = control.get("controlID", control.get("id", "UNKNOWN"))
            control_name = control.get("name", "Unnamed Control")
            score_factor = float(control.get("scoreFactor", 0))
            status = control.get("status", {})

            if isinstance(status, dict):
                if status.get("status", "").lower() not in ("failed", "fail"):
                    continue
            elif isinstance(status, str):
                if status.lower() not in ("failed", "fail"):
                    continue

            severity_str = _severity_from_score_factor(score_factor)
            remediation = control.get("remediation", None)

            rules = control.get("rules", [])
            affected_details: list[dict] = []
            for rule in rules:
                for resource in rule.get("failedResources", []):
                    res_name = resource.get("name", "")
                    res_kind = resource.get("kind", "")
                    res_ns = resource.get("namespace", "")
                    if res_name or res_kind:
                        affected_details.append({"kind": res_kind, "name": res_name, "namespace": res_ns})

            file_path = f"{affected_details[0]['kind']}/{affected_details[0]['name']}" if affected_details else None
            first_ns = affected_details[0]["namespace"] if affected_details else ""

            category_obj = control.get("category", control.get("categories", {}))
            category_name = category_obj.get("name", "General") if isinstance(category_obj, dict) else "General"

            finding = NormalizedFinding(
                title=f"{control_id}: {control_name}",
                description=f"{control.get('description', '')}; Score factor: {score_factor}",
                severity=normalize_severity(severity_str),
                file_path=file_path,
                line_number=None,
                cwe_id=None,
                cve_id=None,
                cvss_score=score_factor,
                remediation=remediation,
                raw_data={
                    "controlID": control_id,
                    "name": control_name,
                    "k8s_affected_resources": affected_details,
                    "k8s_resource_kind": affected_details[0]["kind"] if affected_details else "",
                    "k8s_resource_name": affected_details[0]["name"] if affected_details else "",
                    "k8s_namespace": first_ns,
                    "finding_type": "compliance",
                    "category": category_name,
                },
            )
            finding.fingerprint = compute_fingerprint(finding)
            findings.append(finding)

        return findings
