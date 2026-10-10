import json
from pathlib import Path

from app.extractors.volatility_extractor import parse_volatility_jsonl


def test_volatility_pslist_normalizes_process(tmp_path: Path):
    path = tmp_path / "windows_pslist.jsonl"
    path.write_text(json.dumps({"PID": 1234, "PPID": 1000, "ImageFileName": "powershell.exe", "CreateTime": "2026-10-05 10:00:00", "Args": "powershell.exe -File test.ps1"}) + "\n", encoding="utf-8")
    events = parse_volatility_jsonl(path, plugin="windows.pslist")
    assert events[0]["event_type"] == "PROCESS_EXECUTION"
    assert events[0]["process"] == "powershell.exe"
    assert events[0]["metadata"]["pid"] == 1234
