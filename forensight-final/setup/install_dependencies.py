#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path


def install_dependencies():
    print("=" * 60)
    print("Forensight AI — Installing Python Dependencies")
    print("=" * 60)
    req = Path(__file__).resolve().parents[1] / "requirements.txt"
    if not req.exists():
        print(f"[-] Error: {req} not found.")
        sys.exit(1)

    cmd = [sys.executable, "-m", "pip", "install", "-r", str(req)]
    print(f"Running: {' '.join(cmd)}")
    res = subprocess.run(cmd, check=False)
    if res.returncode == 0:
        print("[+] OK: Dependencies installed successfully.")
    else:
        print(f"[-] Error: pip exited with code {res.returncode}")
        sys.exit(res.returncode)


if __name__ == "__main__":
    install_dependencies()
