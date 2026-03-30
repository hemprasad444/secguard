import csv
import json
import logging
from typing import Any, Optional

from app.integrations.base import NormalizedFinding
from app.utils.dedup import compute_fingerprint
from app.utils.severity_mapper import normalize_severity

logger = logging.getLogger(__name__)

# Common field name mappings for title
_TITLE_KEYS = ["title", "name", "summary", "rule", "check_id", "vulnerability", "issue"]

# Common field name mappings for description
_DESCRIPTION_KEYS = ["description", "desc", "message", "detail", "details", "info"]

# Common field name mappings for severity
_SEVERITY_KEYS = ["severity", "risk", "risk_level", "priority", "level", "criticality"]

# Common field name mappings for file_path
_FILE_PATH_KEYS = ["file_path", "file", "path", "filename", "location", "url", "uri", "target"]

# Common field name mappings for line_number
_LINE_KEYS = ["line_number", "line", "start_line", "lineno", "line_no"]

# Common field name mappings for CWE
_CWE_KEYS = ["cwe_id", "cwe", "cweid", "cwe_number"]

# Common field name mappings for CVE
_CVE_KEYS = ["cve_id", "cve", "cveid", "cve_number", "vulnerability_id"]

# Common field name mappings for CVSS
_CVSS_KEYS = ["cvss_score", "cvss", "cvss3", "cvss_v3", "score", "cvss3_base_score"]

# Common field name mappings for remediation
_REMEDIATION_KEYS = ["remediation", "fix", "solution", "recommendation", "mitigation"]


def _find_value(data: dict, key_candidates: list[str]) -> Optional[str]:
    """Search for a value in a dict using a list of possible key names (case-insensitive)."""
    lower_map = {k.lower(): v for k, v in data.items()}
    for key in key_candidates:
        if key.lower() in lower_map:
            val = lower_map[key.lower()]
            if val is not None and str(val).strip():
                return str(val).strip()
    return None


def _extract_findings_list(data: Any) -> list[dict]:
    """Extract a list of finding dicts from various JSON structures."""
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        # Check common container keys
        for key in ("findings", "results", "vulnerabilities", "issues", "alerts", "items"):
            if key in data and isinstance(data[key], list):
                return data[key]

        # If the dict itself looks like a single finding, wrap it
        if any(_find_value(data, keys) for keys in [_TITLE_KEYS, _DESCRIPTION_KEYS]):
            return [data]

    return []


def _dict_to_finding(item: dict) -> NormalizedFinding:
    """Convert a generic dict to a NormalizedFinding using field mapping."""
    title = _find_value(item, _TITLE_KEYS) or "Unknown Finding"
    description = _find_value(item, _DESCRIPTION_KEYS) or title
    raw_severity = _find_value(item, _SEVERITY_KEYS) or "info"
    file_path = _find_value(item, _FILE_PATH_KEYS)
    cwe_id = _find_value(item, _CWE_KEYS)
    cve_id = _find_value(item, _CVE_KEYS)
    remediation = _find_value(item, _REMEDIATION_KEYS)

    # Parse line number
    line_str = _find_value(item, _LINE_KEYS)
    line_number: Optional[int] = None
    if line_str:
        try:
            line_number = int(float(line_str))
        except (ValueError, TypeError):
            pass

    # Parse CVSS score
    cvss_str = _find_value(item, _CVSS_KEYS)
    cvss_score: Optional[float] = None
    if cvss_str:
        try:
            cvss_score = float(cvss_str)
        except (ValueError, TypeError):
            pass

    finding = NormalizedFinding(
        title=title,
        description=description,
        severity=normalize_severity(raw_severity),
        file_path=file_path,
        line_number=line_number,
        cwe_id=cwe_id,
        cve_id=cve_id,
        cvss_score=cvss_score,
        remediation=remediation,
        raw_data=item,
    )
    finding.fingerprint = compute_fingerprint(finding)
    return finding


def parse_generic_json(file_path: str) -> list[NormalizedFinding]:
    """Parse a generic JSON file containing security findings.

    Supports:
    - A JSON array of finding objects.
    - A JSON object with a "findings", "results", or "vulnerabilities" key
      containing an array of finding objects.

    Field names are matched case-insensitively to common naming conventions.
    """
    findings: list[NormalizedFinding] = []

    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        logger.error("Generic JSON file not found: %s", file_path)
        return []
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON in file %s: %s", file_path, exc)
        return []
    except Exception as exc:
        logger.error("Error reading generic JSON file %s: %s", file_path, exc)
        return []

    items = _extract_findings_list(data)

    for item in items:
        if not isinstance(item, dict):
            logger.warning("Skipping non-dict item in JSON findings list")
            continue
        findings.append(_dict_to_finding(item))

    logger.info(
        "Parsed %d findings from generic JSON file %s", len(findings), file_path
    )
    return findings


def parse_generic_csv(file_path: str) -> list[NormalizedFinding]:
    """Parse a generic CSV file containing security findings.

    Uses csv.DictReader to read headers automatically. Field names are
    matched case-insensitively to common naming conventions.
    """
    findings: list[NormalizedFinding] = []

    try:
        with open(file_path, "r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                findings.append(_dict_to_finding(dict(row)))
    except FileNotFoundError:
        logger.error("Generic CSV file not found: %s", file_path)
        return []
    except csv.Error as exc:
        logger.error("CSV parsing error in file %s: %s", file_path, exc)
        return []
    except Exception as exc:
        logger.error("Error reading generic CSV file %s: %s", file_path, exc)
        return []

    logger.info(
        "Parsed %d findings from generic CSV file %s", len(findings), file_path
    )
    return findings
