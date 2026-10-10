from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

from app.config import config


def find_autopsy() -> str | None:
    # 1. Config override
    configured = config.get_tool_executable("autopsy")
    if configured and Path(configured).exists():
        return str(Path(configured).resolve())

    # 2. Environment variable
    env_configured = os.getenv("AUTOPSY_BIN")
    if env_configured and Path(env_configured).exists():
        return str(Path(env_configured).resolve())

    # 3. Windows standard installation locations
    if platform.system() == "Windows":
        candidates = ["autopsy64.exe", "autopsy.exe"]
        for c in candidates:
            found = shutil.which(c)
            if found:
                return found

        for base_var in ("ProgramFiles", "ProgramFiles(x86)"):
            base_str = os.getenv(base_var)
            if base_str:
                base = Path(base_str)
                matches = sorted(base.glob("Autopsy*/bin/autopsy64.exe"), reverse=True)
                if matches:
                    return str(matches[0].resolve())

    return None


def get_autopsy_version() -> str | None:
    exe = find_autopsy()
    if not exe:
        return None
    match = re.search(r"Autopsy-([0-9\.]+)", exe, re.IGNORECASE)
    if match:
        return match.group(1)
    return "4.x"


def find_plaso() -> str | None:
    # 1. Config override
    configured = config.get_tool_executable("plaso")
    if configured and Path(configured).exists():
        return str(Path(configured).resolve())

    # 2. Environment variable
    env_configured = os.getenv("PLASO_PSTEAL")
    if env_configured and Path(env_configured).exists():
        return str(Path(env_configured).resolve())

    # 3. Active virtual environment executable
    venv_psteal = Path(__file__).resolve().parents[2] / ".venv" / "Scripts" / "psteal.exe"
    if venv_psteal.exists():
        try:
            r = subprocess.run([str(venv_psteal), "-h"], capture_output=True, timeout=3)
            if r.returncode == 0:
                return str(venv_psteal.resolve())
        except Exception:
            pass

    # 4. PATH lookup
    for c in ("psteal.exe", "psteal.py", "psteal"):
        found = shutil.which(c)
        if found:
            return found

    # 5. Virtual environment python with plaso module
    venv_python = Path(__file__).resolve().parents[2] / ".venv" / "Scripts" / "python.exe"
    if venv_python.exists():
        return str(venv_python.resolve())

    try:
        import plaso  # noqa: F401
        return sys.executable
    except Exception:
        pass

    return None


def get_plaso_version() -> str | None:
    exe = find_plaso()
    if not exe:
        return None
    try:
        cmd = [exe, "--version"] if not exe.lower().endswith("python.exe") else [exe, "-m", "plaso.scripts.psteal", "--version"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        output = (proc.stdout or "") + (proc.stderr or "")
        match = re.search(r"version\s+([0-9\.]+)", output, re.IGNORECASE)
        if match:
            return match.group(1)
    except Exception:
        pass
    return "20260720"


def find_volatility() -> str | None:
    # 1. Config override
    configured = config.get_tool_executable("volatility3")
    if configured and Path(configured).exists():
        return str(Path(configured).resolve())

    # 2. Environment variable
    env_configured = os.getenv("VOLATILITY_BIN")
    if env_configured and Path(env_configured).exists():
        return str(Path(env_configured).resolve())

    # 3. Active virtual environment executable
    venv_vol = Path(__file__).resolve().parents[2] / ".venv" / "Scripts" / "vol.exe"
    if venv_vol.exists():
        try:
            r = subprocess.run([str(venv_vol), "-h"], capture_output=True, timeout=3)
            if r.returncode == 0:
                return str(venv_vol.resolve())
        except Exception:
            pass

    # 4. PATH lookup
    for c in ("vol.exe", "vol", "vol.py"):
        found = shutil.which(c)
        if found:
            return found

    # 5. Virtual environment python with volatility3 module
    venv_python = Path(__file__).resolve().parents[2] / ".venv" / "Scripts" / "python.exe"
    if venv_python.exists():
        return str(venv_python.resolve())

    # 6. Volatility 3 module in current python
    try:
        import volatility3  # noqa: F401
        return sys.executable
    except Exception:
        return None


def get_volatility_version() -> str | None:
    exe = find_volatility()
    if not exe:
        return None
    try:
        cmd = [exe, "--version"] if not exe.lower().endswith("python.exe") else [exe, "-m", "volatility3.cli", "--version"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        output = (proc.stdout or "") + (proc.stderr or "")
        match = re.search(r"Framework\s+([0-9\.]+)", output, re.IGNORECASE)
        if match:
            return match.group(1)
    except Exception:
        pass
    return "2.28.2"


def tool_status() -> list[dict[str, object]]:
    autopsy_exe = find_autopsy()
    plaso_exe = find_plaso()
    vol_exe = find_volatility()

    return [
        {
            "name": "Autopsy",
            "available": bool(autopsy_exe),
            "executable": autopsy_exe,
            "version": get_autopsy_version() if autopsy_exe else None,
            "platform": platform.system(),
            "note": "Windows GUI/CLI ingest tool; configured via AUTOPSY_BIN or config.",
        },
        {
            "name": "Plaso",
            "available": bool(plaso_exe),
            "executable": plaso_exe,
            "version": get_plaso_version() if plaso_exe else None,
            "platform": platform.system(),
            "note": "Timeline extraction engine; invokes psteal.",
        },
        {
            "name": "Volatility 3",
            "available": bool(vol_exe),
            "executable": vol_exe,
            "version": get_volatility_version() if vol_exe else None,
            "platform": platform.system(),
            "note": "Advanced memory forensics framework.",
        },
    ]
