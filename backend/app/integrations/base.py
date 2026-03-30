from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NormalizedFinding:
    title: str
    description: str
    severity: str  # already normalized
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None
    raw_data: dict = field(default_factory=dict)
    fingerprint: str = ""


class BaseIntegration(ABC):
    tool_name: str
    scan_type: str

    @abstractmethod
    def run_scan(self, target: str, config: dict) -> list[NormalizedFinding]:
        """Execute scan and return normalized findings."""
        ...

    @abstractmethod
    def parse_report(self, report_path: str) -> list[NormalizedFinding]:
        """Parse an uploaded report file and return normalized findings."""
        ...
