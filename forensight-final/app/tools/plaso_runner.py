from __future__ import annotations

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
from app.tools.detector import find_plaso


def _command_base(exe: str) -> list[str]:
    if exe.lower().endswith("python.exe") or exe.lower().endswith("python"):
        return [exe, "-m", "plaso.scripts.psteal"]
    return [exe]


def run_plaso(source: str, output_dir: str, timezone: str = "UTC") -> ToolResult:
    out = Path(output_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    exe = find_plaso()
    if not exe:
        return ToolResult(
            tool="Plaso",
            available=False,
            executed=False,
            returncode=None,
            command=[],
            stdout="",
            stderr="",
            output_dir=str(out),
            error="psteal executable not found. Ensure Plaso is installed or set PLASO_PSTEAL.",
            status=STATUS_TOOL_NOT_INSTALLED,
        )

    csv_path = out / "plaso_timeline.csv"
    csv_path.unlink(missing_ok=True)
    timeout = config.get_tool_timeout("plaso", default=7200)
    command = _command_base(exe) + [
        "--source",
        source,
        "-o",
        "l2tcsv",
        "-w",
        str(csv_path),
        "--timezone",
        timezone,
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

        has_output = csv_path.exists() and csv_path.stat().st_size > 0
        status = STATUS_SUCCESS if completed.returncode == 0 and has_output else STATUS_TOOL_FAILED
        error = None
        if status != STATUS_SUCCESS:
            if completed.returncode != 0:
                error = f"Plaso failed with exit code {completed.returncode}"
            else:
                error = "Plaso completed with code 0 but generated no timeline CSV output"

        return ToolResult(
            tool="Plaso",
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
            tool="Plaso",
            available=True,
            executed=True,
            returncode=None,
            command=command,
            stdout="",
            stderr=str(exc),
            output_dir=str(out),
            error=f"Plaso timed out after {timeout} seconds",
            status=STATUS_TOOL_TIMEOUT,
        )
