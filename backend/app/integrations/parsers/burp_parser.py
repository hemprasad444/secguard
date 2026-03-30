import logging
import xml.etree.ElementTree as ET

from app.integrations.base import NormalizedFinding
from app.utils.dedup import compute_fingerprint
from app.utils.severity_mapper import normalize_severity

logger = logging.getLogger(__name__)


def parse_burp_report(file_path: str) -> list[NormalizedFinding]:
    """Parse a Burp Suite XML report and return normalized findings.

    Burp Suite XML reports contain <issue> elements with child elements:
    <name>, <severity>, <host>, <path>, <issueDetail>, <confidence>,
    <issueBackground>, <remediationBackground>, <remediationDetail>.
    """
    findings: list[NormalizedFinding] = []

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except FileNotFoundError:
        logger.error("Burp report file not found: %s", file_path)
        return []
    except ET.ParseError as exc:
        logger.error("Failed to parse Burp XML report: %s", exc)
        return []
    except Exception as exc:
        logger.error("Unexpected error reading Burp report: %s", exc)
        return []

    # Burp XML structure: <issues><issue>...</issue></issues>
    issues = root.findall(".//issue")
    if not issues:
        issues = root.findall("issue")

    for issue in issues:
        name = _get_text(issue, "name", "Unknown Issue")
        raw_severity = _get_text(issue, "severity", "Information")
        host = _get_text(issue, "host", "")
        path = _get_text(issue, "path", "")
        issue_detail = _get_text(issue, "issueDetail", "")
        issue_background = _get_text(issue, "issueBackground", "")
        remediation_detail = _get_text(issue, "remediationDetail", "")
        remediation_background = _get_text(issue, "remediationBackground", "")

        # Build URL from host + path
        url = f"{host}{path}" if host else path

        # Build description from available fields
        description_parts = []
        if issue_detail:
            description_parts.append(issue_detail)
        if issue_background:
            description_parts.append(issue_background)
        description = " ".join(description_parts) if description_parts else name

        # Build remediation
        remediation_parts = []
        if remediation_detail:
            remediation_parts.append(remediation_detail)
        if remediation_background:
            remediation_parts.append(remediation_background)
        remediation = (
            " ".join(remediation_parts) if remediation_parts else None
        )

        # Strip HTML tags from description and remediation (basic cleanup)
        description = _strip_html_tags(description)
        if remediation:
            remediation = _strip_html_tags(remediation)

        raw_data = {
            "name": name,
            "severity": raw_severity,
            "host": host,
            "path": path,
        }

        finding = NormalizedFinding(
            title=name,
            description=description,
            severity=normalize_severity(raw_severity),
            file_path=url,
            line_number=None,
            cwe_id=None,
            cve_id=None,
            cvss_score=None,
            remediation=remediation,
            raw_data=raw_data,
        )
        finding.fingerprint = compute_fingerprint(finding)
        findings.append(finding)

    logger.info("Parsed %d findings from Burp report %s", len(findings), file_path)
    return findings


def _get_text(element: ET.Element, tag: str, default: str = "") -> str:
    """Safely extract text from a child element."""
    child = element.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return default


def _strip_html_tags(text: str) -> str:
    """Remove HTML tags from a string (basic implementation)."""
    import re

    clean = re.sub(r"<[^>]+>", "", text)
    # Collapse multiple whitespace
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean
