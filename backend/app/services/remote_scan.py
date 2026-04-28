import os
import shutil
import tempfile
import logging
import subprocess
from uuid import uuid4

logger = logging.getLogger(__name__)

def clone_repo(repo_url: str, branch: str = "main") -> str:
    """Clone a git repo to a temp directory and return the path."""
    clone_dir = os.path.join(tempfile.gettempdir(), f"opensentinel_scan_{uuid4().hex[:12]}")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", branch, repo_url, clone_dir],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode != 0:
            # Try without branch (some repos use 'master')
            result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, clone_dir],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode != 0:
                raise RuntimeError(f"Git clone failed: {result.stderr}")
        return clone_dir
    except subprocess.TimeoutExpired:
        raise RuntimeError("Git clone timed out")

def cleanup_repo(clone_dir: str):
    """Remove cloned repo directory."""
    try:
        if clone_dir and os.path.exists(clone_dir) and clone_dir.startswith(tempfile.gettempdir()):
            shutil.rmtree(clone_dir)
    except Exception as e:
        logger.warning(f"Failed to cleanup {clone_dir}: {e}")
