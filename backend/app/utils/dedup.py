from __future__ import annotations
import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.integrations.base import NormalizedFinding


def compute_fingerprint(tool_name_or_finding, title: str | None = None, file_path: str | None = None, line_number: int | None = None, cve_id: str | None = None) -> str:
    """Compute a SHA-256 fingerprint for deduplication.

    Can be called two ways:
      compute_fingerprint(finding_obj)           -- pass a NormalizedFinding
      compute_fingerprint(tool, title, ...)      -- pass individual fields
    """
    if hasattr(tool_name_or_finding, "title"):
        f = tool_name_or_finding
        tool_name = getattr(f, "tool_name", "") or ""
        title = f.title or ""
        file_path = f.file_path
        line_number = f.line_number
        cve_id = f.cve_id
    else:
        tool_name = tool_name_or_finding or ""
        title = title or ""

    parts = [tool_name, title]
    if cve_id:
        parts.append(cve_id)
    if file_path:
        parts.append(file_path)
    if line_number is not None:
        parts.append(str(line_number))
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:64]
