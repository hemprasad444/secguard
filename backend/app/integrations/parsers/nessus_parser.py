import logging
import xml.etree.ElementTree as ET
from typing import Optional

from app.integrations.base import NormalizedFinding
from app.utils.dedup import compute_fingerprint
from app.utils.severity_mapper import normalize_severity

logger = logging.getLogger(__name__)

# Nessus severity scale: 0=info, 1=low, 2=medium, 3=high, 4=critical
_NESSUS_SEVERITY_MAP = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "critical",
}


def parse_nessus_report(file_path: str) -> list[NormalizedFinding]:
    """Parse a Nessus .nessus XML report and return normalized findings.

    Nessus XML structure:
    <NessusClientData_v2>
      <Report>
        <ReportHost name="hostname">
          <ReportItem pluginName="..." severity="0-4" port="..." ...>
            <description>...</description>
            <cve>CVE-XXXX-XXXX</cve>
            <cvss3_base_score>7.5</cvss3_base_score>
            <solution>...</solution>
            <plugin_output>...</plugin_output>
          </ReportItem>
        </ReportHost>
      </Report>
    </NessusClientData_v2>
    """
    findings: list[NormalizedFinding] = []

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except FileNotFoundError:
        logger.error("Nessus report file not found: %s", file_path)
        return []
    except ET.ParseError as exc:
        logger.error("Failed to parse Nessus XML report: %s", exc)
        return []
    except Exception as exc:
        logger.error("Unexpected error reading Nessus report: %s", exc)
        return []

    for report_host in root.findall(".//ReportHost"):
        hostname = report_host.get("name", "unknown-host")

        for item in report_host.findall("ReportItem"):
            plugin_name = item.get("pluginName", "Unknown Plugin")
            raw_severity = item.get("severity", "0")
            port = item.get("port", "0")
            protocol = item.get("protocol", "")
            plugin_id = item.get("pluginID", "")

            severity_str = _NESSUS_SEVERITY_MAP.get(raw_severity, "info")
            description = _get_text(item, "description", "")
            solution = _get_text(item, "solution", "")
            cve_text = _get_text(item, "cve", "")
            cvss3_text = _get_text(item, "cvss3_base_score", "")
            synopsis = _get_text(item, "synopsis", "")
            plugin_output = _get_text(item, "plugin_output", "")

            # Parse CVSS score
            cvss_score: Optional[float] = None
            if cvss3_text:
                try:
                    cvss_score = float(cvss3_text)
                except ValueError:
                    pass

            # Build file_path as host:port for network findings
            file_path_str = f"{hostname}:{port}" if port != "0" else hostname

            # Build detailed description
            desc_parts = []
            if synopsis:
                desc_parts.append(synopsis)
            if description:
                desc_parts.append(description)
            if plugin_output:
                desc_parts.append(f"Output: {plugin_output[:500]}")
            full_description = " | ".join(desc_parts) if desc_parts else plugin_name

            raw_data = {
                "pluginID": plugin_id,
                "pluginName": plugin_name,
                "severity": raw_severity,
                "host": hostname,
                "port": port,
                "protocol": protocol,
            }

            finding = NormalizedFinding(
                title=plugin_name,
                description=full_description,
                severity=normalize_severity(severity_str),
                file_path=file_path_str,
                line_number=None,
                cwe_id=None,
                cve_id=cve_text if cve_text else None,
                cvss_score=cvss_score,
                remediation=solution if solution and solution.lower() != "n/a" else None,
                raw_data=raw_data,
            )
            finding.fingerprint = compute_fingerprint(finding)
            findings.append(finding)

    logger.info(
        "Parsed %d findings from Nessus report %s", len(findings), file_path
    )
    return findings


def _get_text(element: ET.Element, tag: str, default: str = "") -> str:
    """Safely extract text from a child element."""
    child = element.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return default
