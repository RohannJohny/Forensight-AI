from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _records_from_json(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [x for x in value if isinstance(x, dict)]
    if isinstance(value, dict):
        for key in ("rows", "data", "result", "results"):
            candidate = value.get(key)
            if isinstance(candidate, list):
                return [x for x in candidate if isinstance(x, dict)]
        return [value]
    return []


def _value(row: dict[str, Any], *keys: str) -> Any:
    lowered = {str(k).strip().lower(): v for k, v in row.items()}
    for key in keys:
        if key.lower() in lowered:
            return lowered[key.lower()]
    return None


def parse_volatility_jsonl(path: str | Path, plugin: str | None = None) -> list[dict[str, Any]]:
    path = Path(path)
    events: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return events

    for line_no, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        for row in _records_from_json(payload):
            row_plugin = plugin or str(_value(row, "Plugin", "plugin") or path.stem)
            process = _value(row, "ImageFileName", "Name", "Process", "ProcessName")
            pid = _value(row, "PID", "Pid", "ProcessId")
            ppid = _value(row, "PPID", "Ppid", "ParentPid")
            create_time = _value(row, "CreateTime", "Create Time", "Timestamp", "TimeCreated")
            source_ip = _value(row, "LocalAddr", "LocalAddress", "SourceAddress")
            destination_ip = _value(row, "ForeignAddr", "RemoteAddress", "DestinationAddress", "DestinationIP")
            source_port = _value(row, "LocalPort", "SourcePort")
            destination_port = _value(row, "ForeignPort", "DestinationPort")
            command_line = _value(row, "Args", "CommandLine", "Command Line")

            if "pslist" in row_plugin.lower() or "pstree" in row_plugin.lower() or process:
                event_type = "PROCESS_EXECUTION"
                action = "observed_in_memory"
                artifact = "Volatility 3: " + row_plugin
            elif "netscan" in row_plugin.lower() or destination_ip or source_ip:
                event_type = "NETWORK_CONNECTION"
                action = "network_object_observed"
                artifact = "Volatility 3: " + row_plugin
            else:
                event_type = "MEMORY_ARTIFACT"
                action = "extracted"
                artifact = "Volatility 3: " + row_plugin

            events.append({
                "timestamp": create_time,
                "event_type": event_type,
                "source": "Volatility 3",
                "host": _value(row, "Computer", "Host", "Hostname"),
                "user": _value(row, "Username", "User", "Owner"),
                "process": process,
                "command_line": command_line,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "source_port": source_port,
                "destination_port": destination_port,
                "file_path": _value(row, "Path", "FilePath", "CommandLine", "Args"),
                "file_hash": _value(row, "SHA256", "SHA-256", "Hash"),
                "artifact": artifact,
                "action": action,
                "metadata": {
                    "plugin": row_plugin,
                    "pid": pid,
                    "ppid": ppid,
                    "source_line": line_no,
                    "raw_record": row,
                },
            })
    return events


def parse_volatility_output(directory: str | Path) -> list[dict[str, Any]]:
    directory = Path(directory)
    events: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.jsonl")):
        plugin = path.stem.replace("_", ".")
        events.extend(parse_volatility_jsonl(path, plugin=plugin))
    return events
