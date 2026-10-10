from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from app.config import config
from app.constants import (
    STATUS_SUCCESS,
    STATUS_TOOL_FAILED,
    STATUS_TOOL_NOT_INSTALLED,
    STATUS_TOOL_TIMEOUT,
)
from app.tools.base import ToolResult
from app.tools.detector import find_volatility


def _command_base(exe: str) -> list[str]:
    if exe.lower().endswith("python.exe") or exe.lower().endswith("python"):
        return [exe, "-m", "volatility3.cli"]
    return [exe]


def run_volatility(
    source: str,
    output_dir: str,
    plugins: list[str] | None = None
) -> ToolResult:
    out = Path(output_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    exe = find_volatility()
    if not exe:
        return ToolResult(
            tool="Volatility 3",
            available=False,
            executed=False,
            returncode=None,
            command=[],
            stdout="",
            stderr="",
            output_dir=str(out),
            error="Volatility 3 is not installed or configured. Install volatility3 or set VOLATILITY_BIN.",
            status=STATUS_TOOL_NOT_INSTALLED,
        )

    plugins = plugins or config.get_volatility_plugins()
    timeout = config.get_tool_timeout("volatility3", default=7200)

    stdout_all: list[str] = []
    stderr_all: list[str] = []
    executed_commands: list[list[str]] = []
    last_code = 0
    any_success = False

    for plugin in plugins:
        command = _command_base(exe) + ["-q", "-r", "jsonl", "-f", source, plugin]
        executed_commands.append(command)

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            return ToolResult(
                tool="Volatility 3",
                available=True,
                executed=True,
                returncode=None,
                command=command,
                stdout="\n".join(stdout_all),
                stderr="\n".join(stderr_all + [str(exc)]),
                output_dir=str(out),
                error=f"Timeout executing Volatility 3 plugin {plugin}",
                status=STATUS_TOOL_TIMEOUT,
            )

        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        stdout_all.append(f"PLUGIN={plugin}\n{stdout}")
        stderr_all.append(f"PLUGIN={plugin}\n{stderr}")
        last_code = completed.returncode

        plugin_file = out / f"{plugin.replace('.', '_')}.jsonl"
        plugin_file.write_text(stdout, encoding="utf-8", errors="replace")
        (out / f"{plugin.replace('.', '_')}.stderr.txt").write_text(stderr, encoding="utf-8", errors="replace")

        if completed.returncode == 0:
            any_success = True

    status = STATUS_SUCCESS if any_success else STATUS_TOOL_FAILED
    error = None if status == STATUS_SUCCESS else f"Volatility plugins failed with code {last_code}"

    return ToolResult(
        tool="Volatility 3",
        available=True,
        executed=True,
        returncode=last_code,
        command=executed_commands[0] if len(executed_commands) == 1 else ["..."],
        stdout="\n".join(stdout_all),
        stderr="\n".join(stderr_all),
        output_dir=str(out),
        error=error,
        status=status,
    )
