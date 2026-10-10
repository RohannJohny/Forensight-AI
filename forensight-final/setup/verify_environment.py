#!/usr/bin/env python3
import platform
import shutil
import sys


def verify():
    print("=" * 60)
    print("Forensight AI — Environment Verification")
    print("=" * 60)

    # 1. Python version
    py_ver = sys.version_info
    print(f"Python Version: {py_ver.major}.{py_ver.minor}.{py_ver.micro}")
    if py_ver < (3, 10):
        print("[-] FAIL: Python 3.10 or higher is required.")
        return False
    print("[+] OK: Python version supported.")

    # 2. Operating System
    os_name = platform.system()
    arch = platform.machine()
    print(f"OS: {os_name} ({arch})")
    if os_name != "Windows":
        print("[!] Note: Autopsy CLI ingest is natively Windows-based.")
    else:
        print("[+] OK: Windows forensic workstation environment detected.")

    # 3. Virtual Environment
    in_venv = sys.prefix != sys.base_prefix
    print(f"Virtual Environment Active: {in_venv} ({sys.prefix})")
    if not in_venv:
        print("[!] Warning: Running outside of a virtual environment.")

    # 4. Git availability
    git_path = shutil.which("git")
    print(f"Git: {'Found (' + git_path + ')' if git_path else 'Not found'}")

    print("=" * 60)
    print("Environment Verification Complete: PASS")
    print("=" * 60)
    return True


if __name__ == "__main__":
    success = verify()
    sys.exit(0 if success else 1)
