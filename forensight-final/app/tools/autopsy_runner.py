from __future__ import annotations

import glob
import subprocess
from pathlib import Path

from app.config import config
from app.constants import (
    STATUS_SUCCESS,
    STATUS_TOOL_FAILED,
    STATUS_TOOL_NOT_INSTALLED,
    STATUS_TOOL_TIMEOUT,
)
from app.tools.base import ToolResult
from app.tools.detector import find_autopsy


def run_autopsy(source: str, output_dir: str, case_name: str = "ForensightIngest") -> ToolResult:
    out = Path(output_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    exe = find_autopsy()
    if not exe:
        return ToolResult(
            tool="Autopsy",
            available=False,
            executed=False,
            returncode=None,
            command=[],
            stdout="",
            stderr="",
            output_dir=str(out),
            error="Autopsy is not installed or configured. Set AUTOPSY_BIN or install Autopsy.",
            status=STATUS_TOOL_NOT_INSTALLED,
        )

    case_base = out / "cases"
    case_base.mkdir(parents=True, exist_ok=True)
    timeout = config.get_tool_timeout("autopsy", default=7200)

    command = [
        exe,
        "--createCase",
        f"--caseName={case_name}",
        f"--caseBaseDir={case_base}",
        "--addDataSource",
        f"--dataSourcePath={source}",
        "--runIngest",
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )

        # Check if database was produced
        db_matches = glob.glob(str(case_base / "*" / "autopsy.db"))
        has_db = len(db_matches) > 0

        status = STATUS_SUCCESS if completed.returncode == 0 and has_db else STATUS_TOOL_FAILED
        error = None if status == STATUS_SUCCESS else f"Autopsy failed with returncode {completed.returncode}"
        if completed.returncode == 0 and not has_db:
            error = "Autopsy finished with code 0 but no autopsy.db was created in the case directory."

        return ToolResult(
            tool="Autopsy",
            available=True,
            executed=True,
            returncode=completed.returncode,
            command=command,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
            output_dir=str(out),
            error=error,
            status=status,
        )
    except subprocess.TimeoutExpired as exc:
        return ToolResult(
            tool="Autopsy",
            available=True,
            executed=True,
            returncode=None,
            command=command,
            stdout="",
            stderr=str(exc),
            output_dir=str(out),
            error=f"Autopsy timed out after {timeout} seconds",
            status=STATUS_TOOL_TIMEOUT,
        )
