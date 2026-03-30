from fastapi import APIRouter, Depends

from app.middleware.auth import require_role
from app.models.user import User

router = APIRouter(prefix="/api/settings", tags=["settings"])

CONFIGURED_TOOLS = [
    {"name": "trivy", "type": "dependency", "local": True, "configured": True},
    {"name": "gitleaks", "type": "secrets", "local": True, "configured": True},
    {"name": "semgrep", "type": "sast", "local": True, "configured": True},
    {"name": "kubescape", "type": "k8s", "local": True, "configured": True},
    {"name": "zap", "type": "dast", "local": True, "configured": True},
    {"name": "sonarqube", "type": "sast", "local": False, "configured": False},
    {"name": "burpsuite", "type": "dast", "local": False, "configured": False},
    {"name": "nessus", "type": "vulnerability", "local": False, "configured": False},
]


@router.get("/tools")
async def list_tools(
    current_user: User = Depends(require_role("admin")),
):
    """Return the list of configured security tools and their status. Requires admin role."""
    return CONFIGURED_TOOLS
