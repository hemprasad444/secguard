import json
import logging
import os
import subprocess
import uuid

from app.integrations.base import BaseIntegration, NormalizedFinding
from app.utils.dedup import compute_fingerprint
from app.utils.severity_mapper import normalize_severity

logger = logging.getLogger(__name__)


class GitleaksIntegration(BaseIntegration):
    tool_name = "gitleaks"
    scan_type = "secrets"

    def run_scan(self, target: str, config: dict) -> list[NormalizedFinding]:
        """Execute a Gitleaks scan on the given source directory."""
        report_path = f"/tmp/gitleaks_{uuid.uuid4().hex}.json"

        cmd = [
            "gitleaks",
            "detect",
            "--source",
            target,
            "--report-format",
            "json",
            "--report-path",
            report_path,
            "--exit-code",
            "0",
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600
            )
            if result.returncode != 0:
                logger.error("Gitleaks scan failed: %s", result.stderr)
                return []

            return self._parse_gitleaks_json(report_path)

        except FileNotFoundError:
            logger.error("Gitleaks binary not found in PATH")
            return []
        except subprocess.TimeoutExpired:
            logger.error("Gitleaks scan timed out")
            return []
        except Exception as exc:
            logger.error("Unexpected error during Gitleaks scan: %s", exc)
            return []
        finally:
            if os.path.exists(report_path):
                os.remove(report_path)

    def parse_report(self, report_path: str) -> list[NormalizedFinding]:
        """Parse a Gitleaks JSON report file."""
        try:
            return self._parse_gitleaks_json(report_path)
        except FileNotFoundError:
            logger.error("Report file not found: %s", report_path)
            return []
        except Exception as exc:
            logger.error("Error parsing Gitleaks report: %s", exc)
            return []

    def _parse_gitleaks_json(self, path: str) -> list[NormalizedFinding]:
        """Parse Gitleaks JSON output into normalized findings."""
        findings: list[NormalizedFinding] = []

        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        if not isinstance(data, list):
            logger.warning("Unexpected Gitleaks JSON format")
            return []

        for item in data:
            rule_id = item.get("RuleID", "unknown-rule")
            file_path = item.get("File", "")
            start_line = item.get("StartLine")
            match_text = item.get("Match", "")
            secret = item.get("Secret", "")
            commit = item.get("Commit", "")

            description_parts = [
                f"Rule: {rule_id}",
                f"Match: {match_text[:80]}{'...' if len(match_text) > 80 else ''}",
            ]
            if commit:
                description_parts.append(f"Commit: {commit}")
            if secret:
                masked = secret[:4] + "****" if len(secret) > 4 else "****"
                description_parts.append(f"Secret (masked): {masked}")

            finding = NormalizedFinding(
                title=f"Secret detected: {rule_id}",
                description="; ".join(description_parts),
                severity=normalize_severity("high"),
                file_path=file_path,
                line_number=int(start_line) if start_line is not None else None,
                cwe_id=None,
                cve_id=None,
                cvss_score=None,
                remediation="Rotate the exposed secret and remove it from source code.",
                raw_data=item,
            )
            finding.fingerprint = compute_fingerprint(finding)
            findings.append(finding)

        return findings
