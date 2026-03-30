import json
import logging
import subprocess

from app.integrations.base import BaseIntegration, NormalizedFinding
from app.utils.dedup import compute_fingerprint
from app.utils.severity_mapper import normalize_severity

logger = logging.getLogger(__name__)


class SemgrepIntegration(BaseIntegration):
    tool_name = "semgrep"
    scan_type = "sast"

    def run_scan(self, target: str, config: dict) -> list[NormalizedFinding]:
        """Execute a Semgrep scan on the given target directory."""
        semgrep_config = config.get("config", "auto")

        cmd = ["semgrep", "--config", semgrep_config, "--json", target]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600
            )
            # Semgrep returns exit code 1 when findings are present,
            # so we only treat other failures as errors.
            if result.returncode not in (0, 1):
                logger.error("Semgrep scan failed: %s", result.stderr)
                return []

            report = json.loads(result.stdout)
            return self._parse_semgrep_json(report)

        except FileNotFoundError:
            logger.error("Semgrep binary not found in PATH")
            return []
        except subprocess.TimeoutExpired:
            logger.error("Semgrep scan timed out")
            return []
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse Semgrep JSON output: %s", exc)
            return []
        except Exception as exc:
            logger.error("Unexpected error during Semgrep scan: %s", exc)
            return []

    def parse_report(self, report_path: str) -> list[NormalizedFinding]:
        """Parse a Semgrep JSON report file."""
        try:
            with open(report_path, "r", encoding="utf-8") as fh:
                report = json.load(fh)
            return self._parse_semgrep_json(report)
        except FileNotFoundError:
            logger.error("Report file not found: %s", report_path)
            return []
        except json.JSONDecodeError as exc:
            logger.error("Invalid JSON in report file: %s", exc)
            return []
        except Exception as exc:
            logger.error("Error parsing Semgrep report: %s", exc)
            return []

    def _parse_semgrep_json(self, report: dict) -> list[NormalizedFinding]:
        """Parse Semgrep JSON structure into normalized findings."""
        findings: list[NormalizedFinding] = []
        results = report.get("results", [])

        for item in results:
            check_id = item.get("check_id", "unknown")
            path = item.get("path", "")

            start_info = item.get("start", {})
            line_number = start_info.get("line")

            extra = item.get("extra", {})
            raw_severity = extra.get("severity", "UNKNOWN")
            message = extra.get("message", "")

            metadata = extra.get("metadata", {})
            cwe_raw = metadata.get("cwe")
            cwe_id = None
            if isinstance(cwe_raw, list) and cwe_raw:
                cwe_id = str(cwe_raw[0])
            elif isinstance(cwe_raw, str):
                cwe_id = cwe_raw

            finding = NormalizedFinding(
                title=check_id,
                description=message,
                severity=normalize_severity(raw_severity),
                file_path=path,
                line_number=int(line_number) if line_number is not None else None,
                cwe_id=cwe_id,
                cve_id=None,
                cvss_score=None,
                remediation=metadata.get("fix", None),
                raw_data=item,
            )
            finding.fingerprint = compute_fingerprint(finding)
            findings.append(finding)

        return findings
