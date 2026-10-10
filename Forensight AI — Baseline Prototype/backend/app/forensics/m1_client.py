"""
Forensight AI - M1 Forensic Integration Client (Module 1/3 Bridge)
Connects M3 (Backend/API) to M1 (Evidence Identification, Extraction & Normalization).
Supports both REST API communication (when M1 service is running) and direct isolated execution.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

def find_m1_dir() -> Path:
    env_dir = os.getenv("M1_DIR")
    if env_dir and Path(env_dir).exists():
        return Path(env_dir).resolve()
    curr = Path(__file__).resolve().parent
    for _ in range(6):
        candidate = curr / "forensight-final"
        if candidate.exists():
            return candidate.resolve()
        curr = curr.parent
    return Path(r"c:\Users\rohan\Downloads\Project\forensight-final").resolve()

M1_DIR = find_m1_dir()
M1_SERVICE_URL = os.getenv("M1_SERVICE_URL", "http://localhost:8001").rstrip("/")


class M1Client:
    """Client for invoking M1 forensic classification, extraction, and normalization."""

    @classmethod
    def is_service_online(cls) -> bool:
        """Checks if the standalone M1 FastAPI service is reachable."""
        try:
            with httpx.Client(timeout=1.5) as client:
                res = client.get(f"{M1_SERVICE_URL}/health")
                return res.status_code == 200
        except Exception:
            return False

    @classmethod
    def get_tool_status(cls) -> List[Dict[str, Any]]:
        """Retrieves installed forensic tool states from M1."""
        if cls.is_service_online():
            try:
                with httpx.Client(timeout=5.0) as client:
                    res = client.get(f"{M1_SERVICE_URL}/tools")
                    if res.status_code == 200:
                        return res.json().get("tools", [])
            except Exception:
                pass

        # Subprocess fallback
        if not M1_DIR.exists():
            raise FileNotFoundError(f"M1 directory not found at {M1_DIR}")

        proc = subprocess.run(
            [sys.executable, "-m", "app.cli", "tools"],
            cwd=str(M1_DIR),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"M1 tools check failed: {proc.stderr or proc.stdout}")

        try:
            return json.loads(proc.stdout)
        except Exception as exc:
            raise RuntimeError(f"Failed to parse M1 tools output: {exc}") from exc

    @classmethod
    def identify_evidence(
        cls,
        file_path: str | Path,
        kind: str = "auto"
    ) -> Dict[str, Any]:
        """
        Classifies evidence using M1's magic-byte, container signature, and structural validation.
        Returns classification dictionary.
        """
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Evidence file not found: {path}")

        if cls.is_service_online():
            try:
                with open(path, "rb") as f:
                    files = {"file": (path.name, f, "application/octet-stream")}
                    with httpx.Client(timeout=60.0) as client:
                        res = client.post(f"{M1_SERVICE_URL}/identify?kind={kind}", files=files)
                        if res.status_code == 200:
                            return res.json()
            except Exception:
                pass

        # Subprocess fallback
        if not M1_DIR.exists():
            raise FileNotFoundError(f"M1 directory not found at {M1_DIR}")

        cmd = [sys.executable, "-m", "app.cli", "identify", "--kind", kind, str(path)]
        proc = subprocess.run(
            cmd,
            cwd=str(M1_DIR),
            capture_output=True,
            text=True,
            timeout=60,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"M1 evidence identification failed: {proc.stderr or proc.stdout}")

        try:
            return json.loads(proc.stdout)
        except Exception as exc:
            raise RuntimeError(f"Failed to parse M1 identify output: {exc}. Raw: {proc.stdout[:300]}") from exc

    @classmethod
    def process_evidence(
        cls,
        file_path: str | Path,
        case_id: str,
        kind: str = "auto",
        timeline: bool = True,
        output_dir: Optional[str | Path] = None,
    ) -> Dict[str, Any]:
        """
        Routes evidence to genuine forensic tools (Autopsy / Plaso / Volatility),
        extracts artifacts, normalizes events into the 17-field common schema,
        and returns the M1->M3 ingestion payload.
        """
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Evidence file not found: {path}")

        out_path = Path(output_dir) if output_dir else (M1_DIR / "cases" / case_id)
        out_path = out_path.resolve()
        out_path.mkdir(parents=True, exist_ok=True)

        # 1. Try M1 REST service
        if cls.is_service_online():
            try:
                with httpx.Client(timeout=300.0) as client:
                    payload = {
                        "file_path": str(path),
                        "case_id": case_id,
                        "kind": kind,
                        "timeline": timeline,
                        "output_dir": str(out_path),
                    }
                    res = client.post(f"{M1_SERVICE_URL}/process-path", json=payload)
                    if res.status_code == 200:
                        return res.json()
            except Exception:
                pass

        # 2. Subprocess execution
        if not M1_DIR.exists():
            raise FileNotFoundError(f"M1 directory not found at {M1_DIR}")

        cmd = [
            sys.executable,
            "-m",
            "app.cli",
            "process",
            str(path),
            "--output",
            str(out_path),
            "--kind",
            kind,
        ]
        if not timeline:
            cmd.append("--no-timeline")

        proc = subprocess.run(
            cmd,
            cwd=str(M1_DIR),
            capture_output=True,
            text=True,
            timeout=600,
        )

        if proc.returncode != 0:
            err_msg = proc.stderr.strip() or proc.stdout.strip()
            raise RuntimeError(f"M1 forensic extraction failed: {err_msg}")

        # Load normalized events and manifest from output directory
        norm_json = out_path / "normalized" / "normalized_events.json"
        manifest_json = out_path / "processing_manifest.json"

        if not norm_json.exists():
            # Check case root
            norm_json = out_path / "normalized_events.json"

        if not norm_json.exists():
            raise FileNotFoundError(f"M1 output normalized_events.json not found in {out_path}")

        events_data = json.loads(norm_json.read_text(encoding="utf-8"))
        events_list = events_data.get("events", []) if isinstance(events_data, dict) else events_data

        manifest = {}
        if manifest_json.exists():
            manifest = json.loads(manifest_json.read_text(encoding="utf-8"))

        return {
            **manifest,
            "case_id": case_id,
            "input_file": path.name,
            "input_path": str(path),
            "events": events_list,
            "event_count": len(events_list),
            "output_json": str(norm_json),
            "manifest_path": str(manifest_json) if manifest_json.exists() else None,
        }
