import logging

import httpx

from app.config import settings
from app.integrations.base import BaseIntegration, NormalizedFinding
from app.utils.dedup import compute_fingerprint
from app.utils.severity_mapper import normalize_severity

logger = logging.getLogger(__name__)

# SonarQube severity mapping
_SONAR_SEVERITY_MAP = {
    "BLOCKER": "critical",
    "CRITICAL": "high",
    "MAJOR": "medium",
    "MINOR": "low",
    "INFO": "info",
}


class SonarQubeIntegration(BaseIntegration):
    tool_name = "sonarqube"
    scan_type = "sast"

    def __init__(self):
        self.sonar_url = getattr(settings, "SONARQUBE_URL", "http://localhost:9000")
        self.sonar_token = getattr(settings, "SONARQUBE_TOKEN", "")

    def run_scan(self, target: str, config: dict) -> list[NormalizedFinding]:
        """Fetch issues from SonarQube API for the given project key.

        The `target` parameter should be the SonarQube component/project key.
        """
        page_size = config.get("page_size", 500)
        issue_types = config.get("types", "VULNERABILITY,BUG")
        findings: list[NormalizedFinding] = []

        try:
            client = httpx.Client(
                base_url=self.sonar_url,
                timeout=30.0,
                auth=(self.sonar_token, "") if self.sonar_token else None,
            )

            page = 1
            total_fetched = 0

            while True:
                resp = client.get(
                    "/api/issues/search",
                    params={
                        "componentKeys": target,
                        "types": issue_types,
                        "ps": page_size,
                        "p": page,
                        "statuses": "OPEN,CONFIRMED,REOPENED",
                    },
                )
                resp.raise_for_status()
                data = resp.json()

                issues = data.get("issues", [])
                if not issues:
                    break

                for issue in issues:
                    findings.append(self._issue_to_finding(issue))

                total_fetched += len(issues)
                total_available = data.get("total", 0)
                if total_fetched >= total_available:
                    break
                page += 1

            client.close()
            logger.info(
                "Fetched %d findings from SonarQube for %s", len(findings), target
            )
            return findings

        except httpx.HTTPError as exc:
            logger.error("HTTP error communicating with SonarQube: %s", exc)
            return []
        except Exception as exc:
            logger.error("Unexpected error during SonarQube scan: %s", exc)
            return []

    def parse_report(self, report_path: str) -> list[NormalizedFinding]:
        """Not applicable for SonarQube -- issues are fetched via API."""
        logger.info(
            "SonarQube integration does not support file-based report parsing"
        )
        return []

    def _issue_to_finding(self, issue: dict) -> NormalizedFinding:
        """Convert a SonarQube issue dict to a NormalizedFinding."""
        raw_severity = issue.get("severity", "INFO")
        severity = _SONAR_SEVERITY_MAP.get(raw_severity, raw_severity.lower())

        component = issue.get("component", "")
        # Component format: project_key:path/to/file
        file_path = component.split(":", 1)[1] if ":" in component else component
        line_number = issue.get("line")

        # Extract CWE if present in tags
        cwe_id = None
        tags = issue.get("tags", [])
        for tag in tags:
            if tag.startswith("cwe-"):
                cwe_id = tag.upper().replace("-", "-")
                break

        finding = NormalizedFinding(
            title=issue.get("message", issue.get("rule", "Unknown Issue")),
            description=issue.get("message", ""),
            severity=normalize_severity(severity),
            file_path=file_path,
            line_number=int(line_number) if line_number is not None else None,
            cwe_id=cwe_id,
            cve_id=None,
            cvss_score=None,
            remediation=None,
            raw_data=issue,
        )
        finding.fingerprint = compute_fingerprint(finding)
        return finding
