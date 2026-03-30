SEVERITY_MAP = {
    # Trivy
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
    # ZAP
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
    # Semgrep
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
    # SonarQube
    "BLOCKER": "critical",
    "MAJOR": "high",
    "MINOR": "medium",
    # Nessus
    "Critical": "critical",
    # Burp
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "information": "info",
}

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def normalize_severity(raw: str) -> str:
    mapped = SEVERITY_MAP.get(raw, None)
    if mapped:
        return mapped
    lower = raw.lower().strip()
    if lower in VALID_SEVERITIES:
        return lower
    return "info"
