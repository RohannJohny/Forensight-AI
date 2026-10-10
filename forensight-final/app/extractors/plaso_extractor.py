from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Any

from app.utils.normalize import clean, normalize_timestamp

ALIASES = {
    "event_type": ["event_type", "type", "data_type", "event type"],
    "description": ["description", "desc", "message", "short"],
    "source": ["source", "parser", "source_short"],
    "sourcetype": ["sourcetype", "source_type", "source type"],
    "host": ["hostname", "host"],
    "user": ["username", "user"],
    "process": ["process", "process_name"],
    "command_line": ["command_line", "command line", "cmdline"],
    "source_ip": ["source_ip", "src_ip", "source ip", "local_addr", "local address"],
    "destination_ip": ["destination_ip", "dest_ip", "destination ip", "foreign_addr", "remote address"],
    "source_port": ["source_port", "src_port", "source port", "local_port"],
    "destination_port": ["destination_port", "dest_port", "destination port", "foreign_port", "remote_port"],
    "file_path": ["filename", "file_path", "path", "full_path"],
    "file_hash": ["hash", "file_hash", "sha256", "md5"],
    "artifact": ["artifact", "source_short", "parser", "sourcetype", "source type"],
    "action": ["action", "activity"],
    "macb": ["macb", "MACB"],
}

SHA256_RE = re.compile(r"sha256(?:_hash)?\s*[:=]\s*([a-fA-F0-9]{64})", re.IGNORECASE)
MD5_RE = re.compile(r"md5(?:_hash)?\s*[:=]\s*([a-fA-F0-9]{32})", re.IGNORECASE)
SHA1_RE = re.compile(r"sha1(?:_hash)?\s*[:=]\s*([a-fA-F0-9]{40})", re.IGNORECASE)


def _pick(row: dict[str, Any], names: list[str]) -> Any:
    lowered = {str(k).strip().lower(): v for k, v in row.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return None


def _combine_plaso_timestamp(row: dict[str, Any]) -> str | None:
    raw_timestamp = _pick(row, ["timestamp", "datetime", "date time"])
    if raw_timestamp:
        normalized = normalize_timestamp(raw_timestamp, _pick(row, ["timezone", "tz"]))
        if normalized:
            return normalized

    date = clean(_pick(row, ["date"]))
    time = clean(_pick(row, ["time"]))
    tz = clean(_pick(row, ["timezone", "tz"]))
    if not date or not time:
        return None
    # Plaso uses --:--:-- or 00/00/0000 for records with no valid timestamp
    if date in ("00/00/0000", "0000-00-00") or time in ("--:--:--", "00:00:00", "-"):
        return None
    candidate = f"{date} {time}"
    return normalize_timestamp(candidate, tz)


def _artifact_name(row: dict[str, Any]) -> str | None:
    explicit = clean(_pick(row, ["artifact"]))
    source = clean(_pick(row, ALIASES["source"]))
    source_type = clean(_pick(row, ALIASES["sourcetype"]))
    if explicit:
        return explicit
    if source and source_type:
        return f"{source} ({source_type})"
    return source_type or source


def _extract_hash_from_row(row: dict[str, Any]) -> str | None:
    # 1. Direct column
    direct = clean(_pick(row, ALIASES["file_hash"]))
    if direct:
        return str(direct)

    # 2. Check 'extra' column (standard in Plaso l2tcsv)
    extra = str(_pick(row, ["extra"]) or "")
    if extra:
        m256 = SHA256_RE.search(extra)
        if m256:
            return m256.group(1)
        m1 = SHA1_RE.search(extra)
        if m1:
            return m1.group(1)
        m5 = MD5_RE.search(extra)
        if m5:
            return m5.group(1)

    # 3. Check 'desc' column
    desc = str(_pick(row, ["desc", "description"]) or "")
    if desc:
        m256 = SHA256_RE.search(desc)
        if m256:
            return m256.group(1)
        m5 = MD5_RE.search(desc)
        if m5:
            return m5.group(1)

    return None


def extract_plaso_csv(path: str | Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            event_type = _pick(row, ALIASES["event_type"])
            file_hash = _extract_hash_from_row(row)
            raw = {
                "timestamp": _combine_plaso_timestamp(row),
                "event_type": event_type or "UNKNOWN",
                "source": _pick(row, ALIASES["source"]),
                "host": _pick(row, ALIASES["host"]),
                "user": _pick(row, ALIASES["user"]),
                "process": _pick(row, ALIASES["process"]),
                "command_line": _pick(row, ALIASES["command_line"]),
                "source_ip": _pick(row, ALIASES["source_ip"]),
                "destination_ip": _pick(row, ALIASES["destination_ip"]),
                "source_port": _pick(row, ALIASES["source_port"]),
                "destination_port": _pick(row, ALIASES["destination_port"]),
                "file_path": _pick(row, ALIASES["file_path"]),
                "file_hash": file_hash,
                "artifact": _artifact_name(row),
                "action": _pick(row, ALIASES["action"]),
                "MACB": _pick(row, ALIASES["macb"]),
                "metadata": {
                    "plaso_row": row,
                    "timezone": _pick(row, ["timezone", "tz"]),
                    "source_type": _pick(row, ALIASES["sourcetype"]),
                    "desc": _pick(row, ["desc", "description"]),
                },
            }
            # Preserve original date/time for forensic traceability
            raw["metadata"]["original_date"] = _pick(row, ["date"])
            raw["metadata"]["original_time"] = _pick(row, ["time"])
            events.append(raw)
    return events
