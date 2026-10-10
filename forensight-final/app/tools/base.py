from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from app.constants import (
    STATUS_SUCCESS,
    STATUS_TOOL_FAILED,
    STATUS_TOOL_TIMEOUT,
    STATUS_TOOL_NOT_INSTALLED,
    STATUS_SKIPPED,
)


@dataclass
class ToolResult:
    tool: str
    available: bool
    executed: bool = False
    returncode: int | None = None
    command: list[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    output_dir: str | None = None
    error: str | None = None
    status: str = "NOT_RUN"


def resolve_executable(candidates: Sequence[str], env_var: str | None = None) -> str | None:
    # 1. Check environment variable override
    if env_var:
        configured = os.getenv(env_var)
        if configured:
            if Path(configured).exists():
                return str(Path(configured).resolve())
            found = shutil.which(configured)
            if found:
                return found

    # 2. Check active virtual environment Scripts directory
    venv_dir = Path(__file__).resolve().parents[2] / ".venv" / "Scripts"
    if venv_dir.exists():
        for candidate in candidates:
            candidate_path = venv_dir / candidate
            if candidate_path.exists():
                return str(candidate_path.resolve())

    # 3. Check system PATH
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found

    return None


def run_command(command: list[str], timeout: int = 7200) -> subprocess.CompletedProcess[str]:
    """Runs a subprocess with arguments array, without shell=True for security."""
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        shell=False,
    )
