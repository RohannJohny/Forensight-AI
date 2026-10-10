#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# Add project root to sys.path
root = Path(__file__).resolve().parents[1]
if str(root) not in sys.path:
    sys.path.insert(0, str(root))

from app.tools.detector import (
    find_autopsy,
    find_plaso,
    find_volatility,
    get_autopsy_version,
    get_plaso_version,
    get_volatility_version,
)

CONFIG_PATH = root / "config" / "forensight.json"


def configure_and_smoke_test():
    print("=" * 65)
    print("Forensight AI — Forensic Tool Discovery & Smoke Test")
    print("=" * 65)

    autopsy_exe = find_autopsy()
    autopsy_ver = get_autopsy_version()

    plaso_exe = find_plaso()
    plaso_ver = get_plaso_version()

    vol_exe = find_volatility()
    vol_ver = get_volatility_version()

    results = []

    # 1. Smoke test Autopsy
    if autopsy_exe:
        results.append({
            "tool": "Autopsy",
            "status": "READY",
            "version": autopsy_ver or "Unknown",
            "path": autopsy_exe,
            "smoke_test": "PASSED (binary located)",
        })
    else:
        results.append({
            "tool": "Autopsy",
            "status": "MISSING",
            "version": "N/A",
            "path": "Not found",
            "smoke_test": "SKIPPED (Set AUTOPSY_BIN)",
        })

    # 2. Smoke test Plaso
    if plaso_exe:
        try:
            p = subprocess.run([plaso_exe, "--version"], capture_output=True, text=True, timeout=10, check=False)
            smoke = "PASSED" if p.returncode == 0 else f"FAILED (code {p.returncode})"
        except Exception as e:
            smoke = f"FAILED ({e})"
        results.append({
            "tool": "Plaso (psteal)",
            "status": "READY" if "PASSED" in smoke else "ERROR",
            "version": plaso_ver or "Unknown",
            "path": plaso_exe,
            "smoke_test": smoke,
        })
    else:
        results.append({
            "tool": "Plaso (psteal)",
            "status": "MISSING",
            "version": "N/A",
            "path": "Not found",
            "smoke_test": "SKIPPED (Set PLASO_PSTEAL or pip install plaso)",
        })

    # 3. Smoke test Volatility 3
    if vol_exe:
        try:
            cmd = [vol_exe, "-h"] if not vol_exe.endswith("python.exe") else [vol_exe, "-m", "volatility3.cli", "-h"]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
            smoke = "PASSED" if p.returncode == 0 else f"FAILED (code {p.returncode})"
        except Exception as e:
            smoke = f"FAILED ({e})"
        results.append({
            "tool": "Volatility 3",
            "status": "READY" if "PASSED" in smoke else "ERROR",
            "version": vol_ver or "Unknown",
            "path": vol_exe,
            "smoke_test": smoke,
        })
    else:
        results.append({
            "tool": "Volatility 3",
            "status": "MISSING",
            "version": "N/A",
            "path": "Not found",
            "smoke_test": "SKIPPED (Set VOLATILITY_BIN or pip install volatility3)",
        })

    # Display report table
    print(f"{'Tool':<18} | {'Status':<10} | {'Version':<10} | {'Smoke Test':<20}")
    print("-" * 65)
    for r in results:
        print(f"{r['tool']:<18} | {r['status']:<10} | {r['version']:<10} | {r['smoke_test']:<20}")
    print("=" * 65)

    # Save to config/forensight.json
    cfg_data = {}
    if CONFIG_PATH.exists():
        try:
            cfg_data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    cfg_data.setdefault("tools", {})
    cfg_data["tools"]["autopsy"] = {"executable": autopsy_exe, "timeout_seconds": 7200}
    cfg_data["tools"]["plaso"] = {"executable": plaso_exe, "timeout_seconds": 7200}
    cfg_data["tools"]["volatility3"] = {
        "executable": vol_exe,
        "timeout_seconds": 7200,
        "default_plugins": ["windows.info", "windows.pslist", "windows.pstree", "windows.cmdline", "windows.netscan"],
    }
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg_data, indent=2), encoding="utf-8")
    print(f"[+] Saved detected tool paths to: {CONFIG_PATH}")


if __name__ == "__main__":
    configure_and_smoke_test()
