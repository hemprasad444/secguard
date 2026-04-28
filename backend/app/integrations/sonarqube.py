import logging

import httpx

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


def _client(url: str, token: str | None) -> httpx.Client:
    auth = (token, "") if token else None
    return httpx.Client(base_url=url.rstrip("/"), timeout=30.0, auth=auth)


def ping(url: str, token: str | None) -> tuple[bool, str]:
    """Test connection. Returns (ok, detail)."""
    try:
        with _client(url, token) as c:
            r = c.get("/api/system/ping")
            if r.status_code == 200 and r.text.strip().lower() == "pong":
                return True, "pong"
            r2 = c.get("/api/authentication/validate")
            if r2.status_code == 200:
                valid = r2.json().get("valid", False)
                return (valid, "authenticated" if valid else "invalid token")
            return False, f"HTTP {r.status_code} {r.text[:120]}"
    except httpx.HTTPError as exc:
        return False, f"connection error: {exc}"


class SonarQubeIntegration(BaseIntegration):
    tool_name = "sonarqube"
    scan_type = "sast"

    def __init__(self, url: str | None = None, token: str | None = None):
        self.sonar_url = (url or "").rstrip("/")
        self.sonar_token = token or ""

    def run_scan(self, target: str, config: dict) -> list[NormalizedFinding]:
        """Fetch issues from SonarQube API for the given project key.

        The `target` parameter should be the SonarQube component/project key.
        URL/token come from `__init__` so each project can hit a different SonarQube install.
        """
        if not self.sonar_url:
            logger.error("SonarQube scan requested without a URL configured")
            return []

        page_size = config.get("page_size", 500)
        issue_types = config.get("types", "VULNERABILITY,BUG")
        findings: list[NormalizedFinding] = []

        try:
            with _client(self.sonar_url, self.sonar_token) as client:
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
            logger.info("Fetched %d findings from SonarQube for %s", len(findings), target)
            return findings
        except httpx.HTTPError as exc:
            logger.error("HTTP error communicating with SonarQube: %s", exc)
            return []
        except Exception as exc:
            logger.error("Unexpected error during SonarQube scan: %s", exc)
            return []

    def parse_report(self, report_path: str) -> list[NormalizedFinding]:
        """Not applicable for SonarQube -- issues are fetched via API."""
        return []

    def _issue_to_finding(self, issue: dict) -> NormalizedFinding:
        raw_severity = issue.get("severity", "INFO")
        severity = _SONAR_SEVERITY_MAP.get(raw_severity, raw_severity.lower())

        component = issue.get("component", "")
        file_path = component.split(":", 1)[1] if ":" in component else component
        line_number = issue.get("line")

        cwe_id = None
        for tag in issue.get("tags", []) or []:
            if isinstance(tag, str) and tag.startswith("cwe-"):
                cwe_id = tag.upper()
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
