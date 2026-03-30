import json
import logging
import time

import httpx

from app.config import settings
from app.integrations.base import BaseIntegration, NormalizedFinding
from app.utils.dedup import compute_fingerprint
from app.utils.severity_mapper import normalize_severity

logger = logging.getLogger(__name__)

# ZAP risk codes to severity strings
_ZAP_RISK_MAP = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
}


class ZapIntegration(BaseIntegration):
    tool_name = "zap"
    scan_type = "dast"

    def __init__(self):
        self.zap_url = getattr(settings, "ZAP_API_URL", "http://localhost:8080")
        self.api_key = getattr(settings, "ZAP_API_KEY", "")
        self.poll_interval = 5  # seconds between status polls
        self.scan_timeout = 1800  # 30 minute max wait

    def _api_params(self, **kwargs) -> dict:
        """Build query parameters including the API key."""
        params = {}
        if self.api_key:
            params["apikey"] = self.api_key
        params.update(kwargs)
        return params

    def run_scan(self, target: str, config: dict) -> list[NormalizedFinding]:
        """Execute a ZAP spider + active scan against the target URL."""
        try:
            client = httpx.Client(base_url=self.zap_url, timeout=30.0)

            # --- Spider ---
            logger.info("Starting ZAP spider against %s", target)
            resp = client.post(
                "/JSON/spider/action/scan/",
                params=self._api_params(url=target, maxChildren=config.get("maxChildren", "10")),
            )
            resp.raise_for_status()
            spider_scan_id = resp.json().get("scan", "0")

            # Wait for spider to complete
            self._wait_for_completion(
                client,
                "/JSON/spider/view/status/",
                {"scanId": spider_scan_id},
                "Spider",
            )

            # --- Active Scan ---
            logger.info("Starting ZAP active scan against %s", target)
            resp = client.post(
                "/JSON/ascan/action/scan/",
                params=self._api_params(url=target, recurse="true"),
            )
            resp.raise_for_status()
            ascan_id = resp.json().get("scan", "0")

            # Wait for active scan to complete
            self._wait_for_completion(
                client,
                "/JSON/ascan/view/status/",
                {"scanId": ascan_id},
                "Active scan",
            )

            # --- Retrieve Alerts ---
            logger.info("Retrieving ZAP alerts for %s", target)
            resp = client.get(
                "/JSON/core/view/alerts/",
                params=self._api_params(baseurl=target, start="0", count="500"),
            )
            resp.raise_for_status()
            alerts = resp.json().get("alerts", [])

            client.close()
            return self._parse_alerts(alerts)

        except httpx.HTTPError as exc:
            logger.error("HTTP error communicating with ZAP: %s", exc)
            return []
        except Exception as exc:
            logger.error("Unexpected error during ZAP scan: %s", exc)
            return []

    def _wait_for_completion(
        self,
        client: httpx.Client,
        status_endpoint: str,
        params: dict,
        label: str,
    ) -> None:
        """Poll a ZAP status endpoint until progress reaches 100."""
        elapsed = 0
        while elapsed < self.scan_timeout:
            resp = client.get(
                status_endpoint, params=self._api_params(**params)
            )
            resp.raise_for_status()
            status = int(resp.json().get("status", "100"))
            if status >= 100:
                logger.info("%s completed", label)
                return
            logger.debug("%s progress: %d%%", label, status)
            time.sleep(self.poll_interval)
            elapsed += self.poll_interval

        logger.warning("%s timed out after %d seconds", label, self.scan_timeout)

    def parse_report(self, report_path: str) -> list[NormalizedFinding]:
        """Parse a ZAP JSON export report file."""
        try:
            with open(report_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            # ZAP JSON report may have alerts at top level or nested
            alerts = []
            if isinstance(data, list):
                alerts = data
            elif isinstance(data, dict):
                # Standard ZAP JSON report structure
                for site in data.get("site", []):
                    for alert_block in site.get("alerts", []):
                        alerts.append(alert_block)
                # Also check flat alerts key
                if not alerts and "alerts" in data:
                    alerts = data["alerts"]

            return self._parse_alerts(alerts)

        except FileNotFoundError:
            logger.error("Report file not found: %s", report_path)
            return []
        except json.JSONDecodeError as exc:
            logger.error("Invalid JSON in ZAP report: %s", exc)
            return []
        except Exception as exc:
            logger.error("Error parsing ZAP report: %s", exc)
            return []

    def _parse_alerts(self, alerts: list[dict]) -> list[NormalizedFinding]:
        """Convert ZAP alerts into normalized findings."""
        findings: list[NormalizedFinding] = []

        for alert in alerts:
            alert_name = alert.get("alert", alert.get("name", "Unknown Alert"))
            risk_code = str(alert.get("riskcode", alert.get("risk", "0")))
            raw_severity = _ZAP_RISK_MAP.get(risk_code, alert.get("risk", "info"))
            description = alert.get("description", alert.get("desc", ""))
            url = alert.get("url", alert.get("uri", ""))
            cwe_raw = alert.get("cweid", alert.get("cwe", ""))
            cwe_id = str(cwe_raw) if cwe_raw and str(cwe_raw) != "-1" else None
            solution = alert.get("solution", None)

            finding = NormalizedFinding(
                title=alert_name,
                description=description,
                severity=normalize_severity(raw_severity),
                file_path=url,
                line_number=None,
                cwe_id=cwe_id,
                cve_id=None,
                cvss_score=None,
                remediation=solution,
                raw_data=alert,
            )
            finding.fingerprint = compute_fingerprint(finding)
            findings.append(finding)

        return findings
